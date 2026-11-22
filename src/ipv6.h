/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef OPENFORTIVPN_IPV6_H
#define OPENFORTIVPN_IPV6_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

struct ipv6_prefix {
	struct in6_addr address;
	unsigned int length;
};

struct ipv6_config {
	struct in6_addr address;
	unsigned int prefix_len;
	struct in6_addr dns[2];
	size_t dns_count;
	struct ipv6_prefix *routes;
	size_t route_count;
	size_t installed_routes;
	bool only;
	bool full_tunnel;
	bool address_installed;
	bool ready;
};

bool ipv6_prefix_contains(const struct ipv6_prefix *prefix,
                          const struct in6_addr *address);
int ipv6_parse_config(struct ipv6_config *config, const char *xml, char **ipv4);
bool ipv6cp_ack_address(const uint8_t *packet, size_t length, struct in6_addr *address);
int ipv6_configure(struct ipv6_config *config, const char *iface, bool set_routes);
void ipv6_restore(struct ipv6_config *config, const char *iface);
void ipv6_cleanup(struct ipv6_config *config);

#endif
