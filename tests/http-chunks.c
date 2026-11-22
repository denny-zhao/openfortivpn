#include "http_chunks.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static void expect_body(const char *wire, const char *expected)
{
	char *body = NULL;

	assert(http_scan_chunks(wire, strlen(wire)) == HTTP_CHUNKS_COMPLETE);
	assert(http_decode_chunks(wire, strlen(wire), &body) == 0);
	assert(body != NULL);
	assert(!strcmp(body, expected));
	free(body);
}

static void expect_invalid(const char *wire)
{
	char *body = NULL;

	assert(http_scan_chunks(wire, strlen(wire)) != HTTP_CHUNKS_COMPLETE);
	assert(http_decode_chunks(wire, strlen(wire), &body) != 0);
	assert(body == NULL);
}

int main(void)
{
	expect_body("3\r\n<iP\r\n4\r\nv6/>\r\n0\r\n\r\n", "<iPv6/>");
	expect_body("5 ;test=okay\r\nhello\r\n0\r\nX-Trailer: value\r\n\r\n", "hello");
	expect_body("0\r\n\r\n", "");

	expect_invalid("100000000000000000000000000000000000\r\n");
	expect_invalid("4\r\nabc\r\n0\r\n\r\n");
	expect_invalid("3\r\nabc\r\n");
	expect_invalid("3\r\nabc\r\n0\r\nX-Trailer: value\r\n");
	expect_invalid("0\r\n\r\nextra");

	const char *partial = "b\r\nabc\r\n0\r\n\r\n";

	assert(http_scan_chunks(partial, strlen(partial)) == HTTP_CHUNKS_INCOMPLETE);
	expect_body("b\r\nabc\r\n0\r\n\r\nZ\r\n0\r\n\r\n", "abc\r\n0\r\n\r\nZ");

	const char *header = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked,\r\n\r\n";

	assert(http_transfer_is_chunked(header, strlen(header)));
	header = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip; x=\",\"\r\n"
	         "Transfer-Encoding:\t, Chunked\r\n\r\n";
	assert(http_transfer_is_chunked(header, strlen(header)));
	header = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n";
	assert(!http_transfer_is_chunked(header, strlen(header)));
	return 0;
}
