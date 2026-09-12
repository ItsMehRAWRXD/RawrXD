/* ss_anchor_probe.c — print GGUF anchor extent; no GPU */
#include "ss_phase_abi.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
typedef struct { uint64_t handle, file_bytes; } SSFileCtx;
typedef struct {
    uint64_t found, which_name, relative_offset, absolute_offset, storage_bytes;
    uint64_t element_count, data_base, alignment;
    uint32_t tensor_type, n_dims;
} SSTensorDesc;
extern int ss_file_open(const char *path, SSFileCtx *ctx);
extern int ss_file_close(SSFileCtx *ctx);
extern int ss_find_anchor_tensor(SSFileCtx *ctx, SSTensorDesc *d);
int main(int argc, char **argv)
{
    SSFileCtx f; SSTensorDesc d; int rc;
    const char *path = (argc > 1) ? argv[1] : 0;
    if (!path) { printf("USAGE=ss_anchor_probe <gguf>\n"); return 2; }
    memset(&f, 0, sizeof f); memset(&d, 0, sizeof d);
    rc = ss_file_open(path, &f);
    printf("OPEN_RC=%d FILE_BYTES=%llu\n", rc, (unsigned long long)f.file_bytes);
    if (rc) return rc;
    rc = ss_find_anchor_tensor(&f, &d);
    printf("FIND_RC=%d FOUND=%llu WHICH=%llu OFF=%llu BYTES=%llu ELEMS=%llu TYPE=%u ALIGN=%llu\n",
           rc, (unsigned long long)d.found, (unsigned long long)d.which_name,
           (unsigned long long)d.absolute_offset, (unsigned long long)d.storage_bytes,
           (unsigned long long)d.element_count, d.tensor_type,
           (unsigned long long)d.alignment);
    ss_file_close(&f);
    return rc;
}
