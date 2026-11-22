/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef OPENFORTIVPN_HTTP_CHUNKS_H
#define OPENFORTIVPN_HTTP_CHUNKS_H

#include <stdbool.h>
#include <stddef.h>

enum http_chunk_status {
	HTTP_CHUNKS_INVALID = -1,
	HTTP_CHUNKS_INCOMPLETE,
	HTTP_CHUNKS_COMPLETE,
};

bool http_transfer_is_chunked(const char *header, size_t size);
enum http_chunk_status http_scan_chunks(const char *data, size_t size);
int http_decode_chunks(const char *data, size_t size, char **body);

#endif
