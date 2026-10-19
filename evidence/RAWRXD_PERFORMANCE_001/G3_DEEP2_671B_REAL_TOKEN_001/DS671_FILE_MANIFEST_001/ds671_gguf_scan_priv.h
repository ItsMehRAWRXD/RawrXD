/* ds671_gguf_scan_priv.h */
#ifndef DS671_GGUF_SCAN_PRIV_H
#define DS671_GGUF_SCAN_PRIV_H
#include "ds671_gguf_scan.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef struct { HANDLE h; uint64_t pos, size; } GgufR;
int gr_open(GgufR *r, const char *path);
void gr_close(GgufR *r);
int gr_read(GgufR *r, void *dst, uint64_t n);
int gr_skip(GgufR *r, uint64_t n);
int gr_u32(GgufR *r, uint32_t *v);
int gr_u64(GgufR *r, uint64_t *v);
int gr_str(GgufR *r, char *buf, size_t cap);
int gr_skip_val(GgufR *r, uint32_t t);
int gr_scan_kv(GgufR *r, GgufShardInfo *o, uint64_t n_kv);
int gr_scan_tensors(GgufR *r, GgufShardInfo *o, uint64_t n_tensor);
#endif
