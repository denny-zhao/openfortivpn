#include "ipv6.h"
#include "http_chunks.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool includes(const struct ipv6_config *config, const char *address)
{
	struct in6_addr candidate;
	assert(inet_pton(AF_INET6, address, &candidate) == 1);
	for (size_t i = 0; i < config->route_count; ++i)
		if (ipv6_prefix_contains(&config->routes[i], &candidate))
			return true;
	return false;
}

int main(void)
{
	struct ipv6_config config = {0};
	char *ipv4 = NULL;
	const char *dual_stack =
	        "<?xml version='1.0'?><sslvpn-tunnel>"
	        "<ipv6><assigned-addr ipv6='2001:db8:1::1' prefix-len='64'/>"
	        "<dns ipv6='2001:db8::53'/>"
	        "<split-tunnel-info><addr ipv6='::' prefix-len='0'/></split-tunnel-info>"
	        "<split-tunnel-info negate='1'>"
	        "<addr ipv6='2001:db8:2::' prefix-len='48'/></split-tunnel-info>"
	        "</ipv6><ipv4><assigned-addr ipv4='192.0.2.4'/></ipv4></sslvpn-tunnel>";
	assert(ipv6_parse_config(&config, dual_stack, &ipv4) == 1);
	assert(ipv4 != NULL && strstr(ipv4, "192.0.2.4") != NULL);
	assert(config.prefix_len == 64 && !config.only);
	assert(config.dns_count == 1);
	assert(includes(&config, "2001:db8:3::1"));
	assert(!includes(&config, "2001:db8:2::1"));
	assert(!config.full_tunnel);
	free(ipv4);
	ipv6_cleanup(&config);

	char wire[1024];
	char *xml = NULL;
	size_t split = 50;

	snprintf(wire, sizeof(wire), "%zx\r\n%.*s\r\n%zx\r\n%s\r\n0\r\n\r\n",
	         split, (int)split, dual_stack, strlen(dual_stack) - split,
	         dual_stack + split);
	assert(http_decode_chunks(wire, strlen(wire), &xml) == 0);
	assert(ipv6_parse_config(&config, xml, &ipv4) == 1);
	assert(config.prefix_len == 64);
	free(xml);
	free(ipv4);
	ipv6_cleanup(&config);

	const char *ipv4_only =
	        "<?xml version='1.0'?><sslvpn-tunnel>"
	        "<ipv4><assigned-addr ipv4='192.0.2.4'/></ipv4></sslvpn-tunnel>";

	snprintf(wire, sizeof(wire), "%zx   \r\n%s\r\n0\r\n\r\n",
	         strlen(ipv4_only), ipv4_only);
	assert(http_decode_chunks(wire, strlen(wire), &xml) == 0);
	assert(ipv6_parse_config(&config, xml, &ipv4) == 0);
	assert(config.route_count == 0 && ipv4 == NULL);
	free(xml);

	const char *native =
	        "<sslvpn-tunnel><ipv6><assigned-addr ipv6='fd00::5'/>"
	        "</ipv6></sslvpn-tunnel>";
	assert(ipv6_parse_config(&config, native, &ipv4) == 1);
	assert(ipv4 == NULL && config.only && config.prefix_len == 128);
	assert(includes(&config, "2001:db8::1") && includes(&config, "a000::1"));
	assert(config.full_tunnel && config.route_count == 2);
	ipv6_cleanup(&config);

	const char *legacy =
	        "<sslvpn-tunnel><ipv4><assigned-addr ipv4='192.0.2.4'/></ipv4>"
	        "<ipv6><split-tunnel-info><addr ipv6='::' prefix-len='0'/></split-tunnel-info>"
	        "</ipv6></sslvpn-tunnel>";
	assert(ipv6_parse_config(&config, legacy, &ipv4) == 0);
	assert(config.route_count == 0 && ipv4 != NULL);
	free(ipv4);
	assert(ipv6_parse_config(&config,
	                         "<sslvpn-tunnel><ipv6><assigned-addr ipv6='2001:db8::3' prefix-len='129'/>"
	                         "</ipv6></sslvpn-tunnel>", &ipv4) == -1);
	assert(!config.only && config.route_count == 0 && ipv4 == NULL);
	const uint8_t ack[] = {0x80, 0x57, 2, 1, 0, 14, 1, 10,
	                       0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
	                      };
	struct in6_addr address, expected;
	assert(inet_pton(AF_INET6, "fe80::211:2233:4455:6677", &expected) == 1);
	assert(ipv6cp_ack_address(ack, sizeof(ack), &address));
	assert(!memcmp(&address, &expected, sizeof(address)));
	assert(!ipv6cp_ack_address(ack, sizeof(ack) - 1, &address));
	assert(!ipv6cp_ack_address(ack, 2, &address));
	return 0;
}
