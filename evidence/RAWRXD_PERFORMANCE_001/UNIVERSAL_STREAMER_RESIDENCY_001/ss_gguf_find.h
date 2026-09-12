/* ss_gguf_find.h — format walker (adapter uses names; core does not) */
#ifndef SS_GGUF_FIND_H
#define SS_GGUF_FIND_H
#include <stdint.h>
typedef struct {
    uint64_t file_off;
    uint64_t nbytes;
    uint64_t dims[4];
    uint32_t n_dims;
    uint32_t type;
    uint32_t found;
    uint32_t align;
    char arch[24];
} SsTensorHit;
int ss_gguf_find(const char *path, const char *name, SsTensorHit *out);
#endif
