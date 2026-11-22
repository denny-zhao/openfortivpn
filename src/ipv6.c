/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ipv6.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#if HAVE_IPV6_TUNNEL && defined(__APPLE__)
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#endif

#if HAVE_IPV6_TUNNEL
#include <libxml/parser.h>
#include <libxml/tree.h>
#endif

enum { MAX_IPV6_ROUTES = 4096 };

struct prefixes {
	struct ipv6_prefix *items;
	size_t count;
	size_t capacity;
};

bool ipv6_prefix_contains(const struct ipv6_prefix *prefix,
                          const struct in6_addr *address)
{
	unsigned int bytes = prefix->length / 8;
	unsigned int bits = prefix->length % 8;

	if (bytes > sizeof(*address) || (bytes == sizeof(*address) && bits))
		return false;
	if (memcmp(&prefix->address, address, bytes))
		return false;
	if (!bits)
		return true;

	uint8_t mask = (uint8_t)(0xff << (8 - bits));
	return !(mask & (prefix->address.s6_addr[bytes] ^ address->s6_addr[bytes]));
}

#if HAVE_IPV6_TUNNEL
static void normalize_prefix(struct ipv6_prefix *prefix)
{
	for (unsigned int bit = prefix->length; bit < 128; ++bit)
		prefix->address.s6_addr[bit / 8] &= (uint8_t)~(0x80 >> (bit % 8));
}

static int append_prefix(struct prefixes *list, struct ipv6_prefix prefix)
{
	if (list->count == MAX_IPV6_ROUTES)
		return -1;
	if (list->count == list->capacity) {
		size_t capacity = list->capacity ? list->capacity * 2 : 8;
		struct ipv6_prefix *items = realloc(list->items,
		                                    capacity * sizeof(*items));

		if (!items)
			return -1;
		list->items = items;
		list->capacity = capacity;
	}
	list->items[list->count++] = prefix;
	return 0;
}

static int append_include(struct prefixes *list, struct ipv6_prefix prefix)
{
	for (size_t i = 0; i < list->count; ) {
		const struct ipv6_prefix *current = &list->items[i];

		if (current->length <= prefix.length &&
		    ipv6_prefix_contains(current, &prefix.address))
			return 0;
		if (current->length > prefix.length &&
		    ipv6_prefix_contains(&prefix, &current->address))
			list->items[i] = list->items[--list->count];
		else
			++i;
	}

	// Two more-specific routes leave the system's default route in place.
	if (prefix.length == 0) {
		prefix.length = 1;
		if (append_include(list, prefix))
			return -1;
		prefix.address.s6_addr[0] = 0x80;
		return append_include(list, prefix);
	}
	return append_prefix(list, prefix);
}

static int exclude_prefix(struct prefixes *list, const struct ipv6_prefix *exclude)
{
	struct prefixes remainder = {0};

	for (size_t i = 0; i < list->count; ++i) {
		const struct ipv6_prefix *route = &list->items[i];

		if (exclude->length <= route->length &&
		    ipv6_prefix_contains(exclude, &route->address))
			continue;
		if (!ipv6_prefix_contains(route, &exclude->address)) {
			if (append_prefix(&remainder, *route))
				goto fail;
			continue;
		}

		// Keep the sibling prefixes along the path to the excluded subnet.
		for (unsigned int bit = route->length; bit < exclude->length; ++bit) {
			struct ipv6_prefix sibling = *exclude;

			sibling.length = bit + 1;
			sibling.address.s6_addr[bit / 8] ^= (uint8_t)(0x80 >> (bit % 8));
			normalize_prefix(&sibling);
			if (append_prefix(&remainder, sibling))
				goto fail;
		}
	}
	free(list->items);
	*list = remainder;
	return 0;

fail:
	free(remainder.items);
	return -1;
}

static bool named(const xmlNode *node, const char *name)
{
	return node->type == XML_ELEMENT_NODE && xmlStrEqual(node->name, BAD_CAST name);
}

static const xmlNode *child(const xmlNode *parent, const char *name)
{
	if (parent)
		for (const xmlNode *node = parent->children; node; node = node->next)
			if (named(node, name))
				return node;
	return NULL;
}

static int read_address(const xmlNode *node, const char *name, int family, void *address)
{
	xmlChar *value = xmlGetProp(node, BAD_CAST name);
	int result = value ? inet_pton(family, (const char *)value, address) : 0;

	xmlFree(value);
	return result == 1 ? 0 : -1;
}

static int read_prefix(const xmlNode *node, struct ipv6_prefix *prefix, bool host)
{
	if (read_address(node, "ipv6", AF_INET6, &prefix->address))
		return -1;

	xmlChar *value = xmlGetProp(node, BAD_CAST "prefix-len");
	if (!value) {
		prefix->length = 128;
		return host ? 0 : -1;
	}
	char *end;
	long length = strtol((const char *)value, &end, 10);
	bool valid = value[0] >= '0' && value[0] <= '9' && !*end && length <= 128;

	xmlFree(value);
	if (!valid)
		return -1;
	prefix->length = (unsigned int)length;
	return 0;
}

static int read_routes(struct prefixes *routes, const xmlNode *ipv6)
{
	struct prefixes exclusions = {0};
	bool has_includes = false;
	int result = -1;

	for (const xmlNode *node = ipv6->children; node; node = node->next) {
		if (!named(node, "split-tunnel-info"))
			continue;
		xmlChar *negate = xmlGetProp(node, BAD_CAST "negate");
		bool exclude = xmlStrEqual(negate, BAD_CAST "1");

		xmlFree(negate);
		has_includes |= !exclude;
		for (const xmlNode *entry = node->children; entry; entry = entry->next) {
			struct ipv6_prefix prefix;

			if (!named(entry, "addr"))
				continue;
			if (read_prefix(entry, &prefix, false))
				goto done;
			normalize_prefix(&prefix);
			int error = exclude ? append_prefix(&exclusions, prefix) :
			            append_include(routes, prefix);
			if (error)
				goto done;
		}
	}

	if (!has_includes && append_include(routes, (struct ipv6_prefix) {
		0
	}))
		goto done;
	for (size_t i = 0; i < exclusions.count; ++i)
		if (exclude_prefix(routes, &exclusions.items[i]))
			goto done;
	result = 0;

done:
	free(exclusions.items);
	return result;
}

static int copy_ipv4(xmlDoc *document, const xmlNode *node, char **out)
{
	xmlBuffer *buffer = xmlBufferCreate();

	if (!buffer)
		return -1;
	if (xmlNodeDump(buffer, document, (xmlNode *)node, 0, 0) >= 0)
		*out = strdup((const char *)xmlBufferContent(buffer));
	xmlBufferFree(buffer);
	return *out ? 0 : -1;
}
#endif

int ipv6_parse_config(struct ipv6_config *config, const char *xml, char **ipv4)
{
	*ipv4 = NULL;
#if HAVE_IPV6_TUNNEL
	int options = XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
	xmlDoc *document = xmlReadDoc(BAD_CAST xml, NULL, NULL, options);
	struct prefixes routes = {0};
	struct ipv6_prefix address;
	struct in_addr ipv4_address;
	int result = -1;

	if (!document)
		return -1;
	if (document->intSubset || document->extSubset)
		goto done;
	const xmlNode *root = xmlDocGetRootElement(document);
	const xmlNode *v4 = child(root, "ipv4");
	const xmlNode *v6 = child(root, "ipv6");
	const xmlNode *assigned = child(v6, "assigned-addr");

	if (!v6) {
		result = 0;
		goto done;
	}
	if (v4 && copy_ipv4(document, v4, ipv4))
		goto done;
	if (!assigned) {
		result = 0;
		goto done;
	}
	if (read_prefix(assigned, &address, true) ||
	    IN6_IS_ADDR_UNSPECIFIED(&address.address) ||
	    IN6_IS_ADDR_MULTICAST(&address.address) ||
	    IN6_IS_ADDR_LINKLOCAL(&address.address) ||
	    read_routes(&routes, v6))
		goto done;

	config->address = address.address;
	config->prefix_len = address.length;
	const xmlNode *ipv4_assigned = child(v4 ? v4 : root, "assigned-addr");
	config->only = !ipv4_assigned ||
	               read_address(ipv4_assigned, "ipv4", AF_INET, &ipv4_address)
	               || ipv4_address.s_addr == INADDR_ANY;
	config->routes = routes.items;
	config->route_count = routes.count;
	config->full_tunnel = routes.count == 2 &&
	                      routes.items[0].length == 1 &&
	                      routes.items[1].length == 1 &&
	                      routes.items[0].address.s6_addr[0] !=
	                      routes.items[1].address.s6_addr[0];
	routes.items = NULL;

	for (const xmlNode *node = v6->children;
	     node && config->dns_count < 2; node = node->next) {
		struct in6_addr dns;

		if (named(node, "dns") && !read_address(node, "ipv6", AF_INET6, &dns) &&
		    !IN6_IS_ADDR_UNSPECIFIED(&dns) && !IN6_IS_ADDR_MULTICAST(&dns))
			config->dns[config->dns_count++] = dns;
	}
	result = 1;

done:
	free(routes.items);
	xmlFreeDoc(document);
	return result;
#else
	(void)config;
	(void)xml;
	return 0;
#endif
}

bool ipv6cp_ack_address(const uint8_t *packet, size_t length, struct in6_addr *address)
{
	if (length < 6 || packet[0] != 0x80 || packet[1] != 0x57 || packet[2] != 2)
		return false;
	size_t end = 2 + ((size_t)packet[4] << 8) + packet[5];

	if (end < 6 || end > length)
		return false;
	for (size_t i = 6; i + 2 <= end; ) {
		size_t option_length = packet[i + 1];

		if (option_length < 2 || option_length > end - i)
			return false;
		if (packet[i] == 1 && option_length == 10) {
			*address = (struct in6_addr) {
				0
			};
			address->s6_addr[0] = 0xfe;
			address->s6_addr[1] = 0x80;
			memcpy(address->s6_addr + 8, packet + i + 2, 8);
			return true;
		}
		i += option_length;
	}
	return false;
}

#if HAVE_IPV6_TUNNEL
static int run_command(const char *program, const char *const *arguments)
{
	pid_t pid;
	int status;
	char *const environment[] = {
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", NULL
	};

	if (posix_spawn(&pid, program, NULL, NULL, (char *const *)arguments,
	                environment) != 0)
		return -1;
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR)
			return -1;
	}
	return WIFEXITED(status) && !WEXITSTATUS(status) ? 0 : -1;
}

static bool address_on_interface(const char *iface, const struct in6_addr *address)
{
	struct ifaddrs *interfaces;
	bool found = false;

	if (getifaddrs(&interfaces))
		return false;
	for (struct ifaddrs *item = interfaces; item; item = item->ifa_next)
		if (item->ifa_addr && item->ifa_addr->sa_family == AF_INET6 &&
		    !strcmp(item->ifa_name, iface) &&
		    !memcmp(&((struct sockaddr_in6 *)item->ifa_addr)->sin6_addr,
		            address, sizeof(*address))) {
			found = true;
			break;
		}
	freeifaddrs(interfaces);
	return found;
}

static int format_prefix(char *out, size_t size, const struct in6_addr *address,
                         unsigned int prefix)
{
	char ip[INET6_ADDRSTRLEN];

	if (!inet_ntop(AF_INET6, address, ip, sizeof(ip)))
		return -1;
	return snprintf(out, size, "%s/%u", ip, prefix) >= (int)size ? -1 : 0;
}

static int change_address(const struct ipv6_config *config, const char *iface, bool add)
{
	char address[INET6_ADDRSTRLEN + 4];

	/* Assign the PPP endpoint without creating an implicit on-link prefix.
	 * The explicit route plan owns all routed prefixes and exclusions.
	 */
	if (format_prefix(address, sizeof(address), &config->address, 128))
		return -1;

#ifdef __APPLE__
	const char *argv[] = {"/sbin/ifconfig", iface, "inet6", address,
	                      add ? "alias" : "-alias", NULL
	                     };
#elif defined(__linux__)
	const char *argv[] = {IP_PATH, "-6", "address", add ? "add" : "del",
	                      address, "dev", iface,
	                      NULL
	                     };
#endif
	return run_command(argv[0], argv);
}

#ifdef __APPLE__
static int change_route(const struct ipv6_prefix *route, const char *iface, bool add)
{
	struct sockaddr_in6 destination = {
		.sin6_len = sizeof(destination),
		.sin6_family = AF_INET6,
		.sin6_addr = route->address,
	};
	struct sockaddr_in6 mask = {
		.sin6_len = sizeof(mask),
		.sin6_family = AF_INET6,
	};
	struct {
		struct rt_msghdr header;
		unsigned char addresses[3 * sizeof(struct sockaddr_storage)];
	} message = {0};
	struct ifaddrs *interfaces;

	if (getifaddrs(&interfaces))
		return -1;
	const struct sockaddr_dl *link = NULL;
	for (const struct ifaddrs *item = interfaces; item; item = item->ifa_next)
		if (item->ifa_addr && item->ifa_addr->sa_family == AF_LINK &&
		    !strcmp(item->ifa_name, iface)) {
			link = (const struct sockaddr_dl *)item->ifa_addr;
			break;
		}
	if (!link) {
		freeifaddrs(interfaces);
		return -1;
	}

	for (unsigned int bit = 0; bit < route->length; ++bit)
		mask.sin6_addr.s6_addr[bit / 8] |= (uint8_t)(0x80 >> (bit % 8));
	/* Darwin routing socket addresses are aligned to a 32-bit boundary. */
	size_t link_size = (link->sdl_len + 3u) & ~3u;
	unsigned char *address = message.addresses;

	memcpy(address, &destination, sizeof(destination));
	address += sizeof(destination);
	memcpy(address, link, link->sdl_len);
	address += link_size;
	memcpy(address, &mask, sizeof(mask));
	address += sizeof(mask);
	message.header.rtm_msglen = address - (unsigned char *)&message;
	message.header.rtm_version = RTM_VERSION;
	message.header.rtm_type = add ? RTM_ADD : RTM_DELETE;
	message.header.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
	message.header.rtm_flags = RTF_UP | RTF_STATIC;
	message.header.rtm_index = link->sdl_index;
	freeifaddrs(interfaces);

	/* The kernel returns EEXIST here. The route CLI can exit 0 for that error. */
	int fd = socket(PF_ROUTE, SOCK_RAW, 0);
	if (fd < 0)
		return -1;
	ssize_t written = write(fd, &message, message.header.rtm_msglen);

	close(fd);
	return written == message.header.rtm_msglen ? 0 : -1;
}
#elif defined(__linux__)
static int change_route(const struct ipv6_prefix *route, const char *iface, bool add)
{
	char prefix[INET6_ADDRSTRLEN + 4];

	if (format_prefix(prefix, sizeof(prefix), &route->address, route->length))
		return -1;
	const char *argv[] = {IP_PATH, "-6", "route", add ? "add" : "del",
	                      prefix, "dev", iface, NULL
	                     };
	return run_command(argv[0], argv);
}
#endif
#endif

int ipv6_configure(struct ipv6_config *config, const char *iface, bool set_routes)
{
#if HAVE_IPV6_TUNNEL
	if (!address_on_interface(iface, &config->address)) {
		if (change_address(config, iface, true))
			return -1;
		config->address_installed = true;
	}
	if (set_routes) {
		for (size_t i = 0; i < config->route_count; ++i) {
			if (change_route(&config->routes[i], iface, true)) {
				ipv6_restore(config, iface);
				return -1;
			}
			++config->installed_routes;
		}
	}
	config->ready = true;
	return 0;
#else
	(void)config;
	(void)iface;
	(void)set_routes;
	return -1;
#endif
}

void ipv6_restore(struct ipv6_config *config, const char *iface)
{
#if HAVE_IPV6_TUNNEL
	while (config->installed_routes)
		change_route(&config->routes[--config->installed_routes], iface, false);
	if (config->address_installed) {
		change_address(config, iface, false);
		config->address_installed = false;
	}
	config->ready = false;
#else
	(void)config;
	(void)iface;
#endif
}

void ipv6_cleanup(struct ipv6_config *config)
{
	free(config->routes);
	*config = (struct ipv6_config) {
		0
	};
}
