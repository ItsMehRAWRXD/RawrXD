#ifndef BS_SHA256_H
#define BS_SHA256_H
#include <stddef.h>
#include <stdint.h>
typedef struct BsSha256 { uint32_t h[8]; uint64_t bits; uint8_t buf[64]; size_t used; } BsSha256;
void bs_sha256_init(BsSha256 *s);
void bs_sha256_update(BsSha256 *s, const void *data, size_t n);
void bs_sha256_final(BsSha256 *s, uint8_t out[32]);
int bs_sha256_file_hex(const char *path, char out_hex[65]);
#endif
