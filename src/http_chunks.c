/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "http_chunks.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char *line_end(const char *line, const char *end)
{
	for (const char *p = line; end - p > 1; ++p)
		if (p[0] == '\r' && p[1] == '\n')
			return p;
	return NULL;
}

static bool field_space(char c)
{
	return c == ' ' || c == '\t';
}

static bool last_coding_is_chunked(const char *field, const char *end, bool chunked)
{
	while (field < end) {
		while (field < end && (field_space(*field) || *field == ','))
			++field;
		if (field == end)
			break;
		const char *token = field;
		while (field < end && !field_space(*field) &&
		       *field != ',' && *field != ';')
			++field;
		chunked = field - token == 7 && !strncasecmp(token, "chunked", 7);
		bool quoted = false;
		for (; field < end && (quoted || *field != ','); ++field) {
			if (quoted && *field == '\\' && end - field > 1)
				++field;
			else if (*field == '"')
				quoted = !quoted;
		}
	}
	return chunked;
}

bool http_transfer_is_chunked(const char *header, size_t size)
{
	static const char field[] = "Transfer-Encoding:";
	const char *end = header + size;
	const char *line = line_end(header, end);
	bool chunked = false;

	if (!line)
		return false;
	header = line + 2; // skip the status line
	while ((line = line_end(header, end)) && line != header) {
		if ((size_t)(line - header) >= sizeof(field) - 1 &&
		    !strncasecmp(header, field, sizeof(field) - 1))
			chunked = last_coding_is_chunked(header + sizeof(field) - 1,
			                                 line, chunked);
		header = line + 2;
	}
	return chunked;
}

static int hex_digit(unsigned char character)
{
	if (character >= '0' && character <= '9')
		return character - '0';
	if (character >= 'a' && character <= 'f')
		return character - 'a' + 10;
	if (character >= 'A' && character <= 'F')
		return character - 'A' + 10;
	return -1;
}

static bool chunk_length(const char *line, const char *end, size_t *size)
{
	*size = 0;
	int value = hex_digit(*line);

	if (value < 0)
		return false;
	do {
		if (*size > (SIZE_MAX - (unsigned int)value) / 16)
			return false;
		*size = *size * 16 + (unsigned int)value;
	} while (++line < end && (value = hex_digit(*line)) >= 0);

	while (line < end && (*line == ' ' || *line == '\t'))
		++line;
	return line == end || *line == ';';
}

static enum http_chunk_status read_chunks(const char *data, size_t size, char *body)
{
	const char *end = data + size;

	for (;;) {
		const char *line = line_end(data, end);
		size_t length;

		if (!line)
			return HTTP_CHUNKS_INCOMPLETE;
		if (line == data || !chunk_length(data, line, &length))
			return HTTP_CHUNKS_INVALID;
		data = line + 2;
		if (!length)
			break;
		size_t available = end - data;
		if (available < 2 || length > available - 2)
			return HTTP_CHUNKS_INCOMPLETE;
		if (memcmp(data + length, "\r\n", 2))
			return HTTP_CHUNKS_INVALID;
		if (body) {
			memcpy(body, data, length);
			body += length;
		}
		data += length + 2;
	}

	/* Skip trailer fields and consume their terminating empty line. */
	for (;;) {
		const char *line = line_end(data, end);

		if (!line)
			return HTTP_CHUNKS_INCOMPLETE;
		if (line == data) {
			if (body)
				*body = '\0';
			return line + 2 == end ? HTTP_CHUNKS_COMPLETE :
			       HTTP_CHUNKS_INVALID;
		}
		if (!memchr(data, ':', line - data))
			return HTTP_CHUNKS_INVALID;
		data = line + 2;
	}
}

enum http_chunk_status http_scan_chunks(const char *data, size_t size)
{
	return read_chunks(data, size, NULL);
}

int http_decode_chunks(const char *data, size_t size, char **body)
{
	*body = NULL;
	if (size == SIZE_MAX)
		return -1;
	char *out = malloc(size + 1);

	if (!out)
		return -1;
	if (read_chunks(data, size, out) != HTTP_CHUNKS_COMPLETE) {
		free(out);
		return -1;
	}
	*body = out;
	return 0;
}
