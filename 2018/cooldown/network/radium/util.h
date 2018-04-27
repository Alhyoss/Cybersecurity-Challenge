#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>

int timingsafe_memcmp(const uint8_t *lhs, const uint8_t *rhs, size_t len);
int os_random(uint8_t *buf, size_t len);
void hexdump(const void *buffer, size_t len, const char *prefix);
int isprintable(const void *buffer);
int isalphanumeric(const void *buffer);
int is_all_zero(const void *buffer, size_t len);

#endif // UTIL_H
