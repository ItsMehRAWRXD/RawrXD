/* ss_gguf_find.h — locate named tensor extents in one GGUF shard */
#ifndef SS_GGUF_FIND_H
#define SS_GGUF_FIND_H
#include <stdint.h>
typedef struct {
    uint64_t abs_off, bytes, dim0, dim1, elems;
    uint32_t type, n_dims;
    int found;
} SsGgufTensor;
int ss_gguf_find(const char *path, const char *name, SsGgufTensor *out);
#endif
