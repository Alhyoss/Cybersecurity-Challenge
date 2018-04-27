#include <string.h>
#include <ctype.h>

#include <openssl/err.h>

#include "util.h"

int timingsafe_memcmp(const uint8_t *lhs, const uint8_t *rhs, size_t len)
{
	int rval = 0;

	for (size_t i = 0; i < len; i++)
		rval |= lhs[i] ^ rhs[i];

	return rval;
}

int os_random(uint8_t *buf, size_t len)
{
	FILE *fp = fopen("/dev/urandom", "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open /dev/urandom: ");
		perror("");
		return -1;
	}

	if (fread(buf, len, 1, fp) != 1) {
		fprintf(stderr, "Failed to read %zu random bytes from /dev/urandom: ", len);
		perror("");
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

void hexdump(const void *buffer, size_t len, const char *prefix)
{
	uint8_t *bytebuf = (uint8_t*)buffer;

	if (prefix) fprintf(stderr, "%s: ", prefix);

	for (size_t i = 0; i < len; ++i)
		fprintf(stderr, "%02X ", bytebuf[i]);

	fprintf(stderr, "\n");
}

int isprintable(const void *buffer)
{
	const char *string = (const char *)buffer;

	for (int i = 0; string[i] != '\0'; ++i)
		if (string[i] != '\0' && !isprint(string[i]))
			return 0;

	return 1;
}

int isalphanumeric(const void *buffer)
{
	const char *string = (const char *)buffer;

	for (int i = 0; string[i] != '\0'; ++i)
		if (string[i] != '\0' && !isalnum(string[i]))
			return 0;

	return 1;
}

int is_all_zero(const void *buffer, size_t len)
{
	uint8_t *bytebuf = (uint8_t*)buffer;

	for (size_t i = 0; i < len; ++i)
		if (bytebuf[i] != 0)
			return 0;

	return 1;
}

