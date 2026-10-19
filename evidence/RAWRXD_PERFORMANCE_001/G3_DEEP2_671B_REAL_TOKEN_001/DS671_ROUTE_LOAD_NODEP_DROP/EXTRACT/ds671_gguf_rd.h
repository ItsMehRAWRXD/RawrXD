#ifndef RAWRXD_DS671_GGUF_RD_H
#define RAWRXD_DS671_GGUF_RD_H
#include <stdio.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
int ds671_gguf_rd(FILE *f, void *p, size_t n);
int ds671_gguf_ru32(FILE *f, uint32_t *v);
int ds671_gguf_ru64(FILE *f, uint64_t *v);
int ds671_gguf_rstr(FILE *f, char *b, size_t cap);
int ds671_gguf_skipv(FILE *f, uint32_t vt);
int ds671_gguf_parse_exps(const char *name, uint32_t *blk, uint32_t *proj);
#ifdef __cplusplus
}
#endif
#endif
