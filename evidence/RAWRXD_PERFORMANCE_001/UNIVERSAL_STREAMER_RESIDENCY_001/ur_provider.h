/* ur_provider.h — provider ABI (file + memory plugins) */
#ifndef UR_PROVIDER_H
#define UR_PROVIDER_H
#include "ur_types.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct UrFileProvider {
    void *fp;
    uint64_t size;
    char path[1024];
} UrFileProvider;

typedef struct UrMemProvider {
    const uint8_t *base;
    uint64_t size;
} UrMemProvider;

typedef struct UrProviderVTable {
    void *ctx;
    int (*read_range)(void *ctx, uint64_t offset, uint64_t length,
                      void *dst, uint64_t *out_n);
    uint64_t (*size_fn)(void *ctx);
} UrProviderVTable;

int ur_file_open(UrFileProvider *p, const char *path);
void ur_file_close(UrFileProvider *p);
int ur_file_read_range(UrFileProvider *p, uint64_t offset, uint64_t length,
                       void *dst, uint64_t *out_n);
void ur_file_as_vtable(UrFileProvider *p, UrProviderVTable *vt);

int ur_mem_init(UrMemProvider *p, const void *base, uint64_t size);
int ur_mem_read_range(UrMemProvider *p, uint64_t offset, uint64_t length,
                      void *dst, uint64_t *out_n);
void ur_mem_as_vtable(UrMemProvider *p, UrProviderVTable *vt);

#ifdef __cplusplus
}
#endif
#endif
