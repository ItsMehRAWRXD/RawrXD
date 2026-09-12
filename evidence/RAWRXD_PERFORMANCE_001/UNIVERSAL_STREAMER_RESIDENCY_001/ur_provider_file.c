/* ur_provider_file.c — EXACT_RANGE_READER file + mem plugins */
#include "ur_provider.h"
#include <stdio.h>
#include <string.h>

int ur_file_open(UrFileProvider *p, const char *path)
{
    FILE *f;
    if (!p || !path) return UR_E_ARG;
    memset(p, 0, sizeof *p);
    f = fopen(path, "rb");
    if (!f) return UR_E_IO;
    if (_fseeki64(f, 0, SEEK_END) != 0) { fclose(f); return UR_E_IO; }
    p->size = (uint64_t)_ftelli64(f);
    if (_fseeki64(f, 0, SEEK_SET) != 0) { fclose(f); return UR_E_IO; }
    p->fp = f;
    strncpy(p->path, path, sizeof p->path - 1);
    return UR_OK;
}
void ur_file_close(UrFileProvider *p)
{
    if (!p) return;
    if (p->fp) { fclose((FILE *)p->fp); p->fp = 0; }
}
int ur_file_read_range(UrFileProvider *p, uint64_t offset, uint64_t length,
                       void *dst, uint64_t *out_n)
{
    size_t got;
    if (!p || !p->fp || !dst || !out_n) return UR_E_ARG;
    if (!length) { *out_n = 0; return UR_OK; }
    if (offset > p->size || length > p->size - offset) return UR_E_BOUND;
    if (_fseeki64((FILE *)p->fp, (long long)offset, SEEK_SET) != 0) return UR_E_IO;
    got = fread(dst, 1, (size_t)length, (FILE *)p->fp);
    *out_n = (uint64_t)got;
    return (got == (size_t)length) ? UR_OK : UR_E_SHORT;
}
static int file_rr(void *ctx, uint64_t o, uint64_t n, void *d, uint64_t *on)
{ return ur_file_read_range((UrFileProvider *)ctx, o, n, d, on); }
static uint64_t file_sz(void *ctx) { return ((UrFileProvider *)ctx)->size; }
void ur_file_as_vtable(UrFileProvider *p, UrProviderVTable *vt)
{ vt->ctx = p; vt->read_range = file_rr; vt->size_fn = file_sz; }

int ur_mem_init(UrMemProvider *p, const void *base, uint64_t size)
{
    if (!p || !base) return UR_E_ARG;
    p->base = (const uint8_t *)base; p->size = size; return UR_OK;
}
int ur_mem_read_range(UrMemProvider *p, uint64_t offset, uint64_t length,
                      void *dst, uint64_t *out_n)
{
    if (!p || !dst || !out_n) return UR_E_ARG;
    if (offset > p->size || length > p->size - offset) return UR_E_BOUND;
    memcpy(dst, p->base + offset, (size_t)length);
    *out_n = length;
    return UR_OK;
}
static int mem_rr(void *ctx, uint64_t o, uint64_t n, void *d, uint64_t *on)
{ return ur_mem_read_range((UrMemProvider *)ctx, o, n, d, on); }
static uint64_t mem_sz(void *ctx) { return ((UrMemProvider *)ctx)->size; }
void ur_mem_as_vtable(UrMemProvider *p, UrProviderVTable *vt)
{ vt->ctx = p; vt->read_range = mem_rr; vt->size_fn = mem_sz; }
