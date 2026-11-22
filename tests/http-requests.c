#include "http.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct response_fixture {
	const char *request;
	const char *reads[2];
};

static const struct response_fixture *fixtures;
static size_t fixture_count;
static size_t sent;
static size_t read_index;

int test_SSL_write(SSL *ssl, const void *data, int length)
{
	(void)ssl;
	assert(sent < fixture_count);
	size_t size = strlen(fixtures[sent].request);

	assert(length >= 0 && (size_t)length >= size);
	assert(!memcmp(data, fixtures[sent].request, size));
	++sent;
	read_index = 0;
	return length;
}

int test_SSL_read(SSL *ssl, void *data, int capacity)
{
	(void)ssl;
	assert(sent > 0 && read_index < 2);
	const char *bytes = fixtures[sent - 1].reads[read_index++];

	assert(bytes != NULL);
	size_t size = strlen(bytes);

	assert(capacity >= 0 && size <= (size_t)capacity);
	memcpy(data, bytes, size);
	return (int)size;
}

static void use_fixtures(const struct response_fixture *responses, size_t count)
{
	fixtures = responses;
	fixture_count = count;
	sent = read_index = 0;
}

static void test_dual_stack_rejection(struct vpn_config *config, const char *denial)
{
	struct tunnel tunnel = {.config = config};
	const char xml[] = "<sslvpn-tunnel><assigned-addr ipv4='192.0.2.4'/>"
	                   "<dns ip='192.0.2.54'/></sslvpn-tunnel>";
	char response[160];

	snprintf(response, sizeof(response), "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n%s",
	         strlen(xml), xml);
	const struct response_fixture rejection[] = {
		{"GET /remote/fortisslvpn_xml?dual_stack=1 HTTP/1.1\r\n", {denial}},
		{"GET /remote/fortisslvpn_xml HTTP/1.1\r\n", {response}},
	};
	use_fixtures(rejection, ARRAY_SIZE(rejection));
	assert(auth_get_config(&tunnel) == 1);
	assert(sent == ARRAY_SIZE(rejection));
	assert(tunnel.ipv4.ns1_addr.s_addr == inet_addr("192.0.2.54"));
	assert(IN6_IS_ADDR_UNSPECIFIED(&tunnel.ipv6.address));
}

int main(void)
{
	struct vpn_config config = {
		.ipv6 = 1,
		.gateway_host = "vpn.example.test",
		.gateway_port = 443,
		.user_agent = "test",
	};
	struct tunnel tunnel = {.config = &config};

	const struct response_fixture allocation[] = {
		{
			"GET /remote/index HTTP/1.1\r\n",
			{
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
				"<html>legacy response</html>\r\n0\r\n\r\n"
			}
		},
		{
			"GET /remote/fortisslvpn HTTP/1.1\r\n",
			{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"}
		},
	};
	use_fixtures(allocation, ARRAY_SIZE(allocation));
	assert(auth_request_vpn_allocation(&tunnel) == 1);
	assert(sent == ARRAY_SIZE(allocation));

	test_dual_stack_rejection(&config,
	                          "HTTP/1.1 403 Permission denied\r\nContent-Length: 0\r\n\r\n");
	test_dual_stack_rejection(&config,
	                          "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
	test_dual_stack_rejection(&config,
	                          "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n");

	const struct response_fixture expired_session[] = {
		{
			"GET /remote/fortisslvpn_xml?dual_stack=1 HTTP/1.1\r\n",
			{"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"}
		},
	};
	use_fixtures(expired_session, ARRAY_SIZE(expired_session));
	assert(auth_get_config(&tunnel) == 401);
	assert(sent == ARRAY_SIZE(expired_session));

	/* A terminator-shaped sequence inside XML data must not end a TLS read. */
	const char xml_start[] = "<sslvpn-tunnel><!--\r\n0\r\n\r\n";
	const char xml_end[] =
	        "--><ipv4><assigned-addr ipv4='192.0.2.4'/>"
	        "<dns ip='192.0.2.53'/></ipv4></sslvpn-tunnel>";
	char first_read[160];
	char last_read[160];

	snprintf(first_read, sizeof(first_read),
	         "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked,\r\n\r\n%zx   \r\n%s",
	         strlen(xml_start) + strlen(xml_end), xml_start);
	snprintf(last_read, sizeof(last_read), "%s\r\n0\r\nX-Test: trailer\r\n\r\n",
	         xml_end);
	const struct response_fixture xml[] = {
		{
			"GET /remote/fortisslvpn_xml?dual_stack=1 HTTP/1.1\r\n",
			{first_read, last_read}
		},
	};
	use_fixtures(xml, ARRAY_SIZE(xml));
	assert(auth_get_config(&tunnel) == 1);
	assert(read_index == 2);
	assert(tunnel.ipv4.ns1_addr.s_addr == inet_addr("192.0.2.53"));
	assert(IN6_IS_ADDR_UNSPECIFIED(&tunnel.ipv6.address));
	free(tunnel.ipv4.dns_suffix);
	ipv6_cleanup(&tunnel.ipv6);
	return 0;
}
