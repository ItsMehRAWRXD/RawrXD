#ifndef D2_RANGE_H
#define D2_RANGE_H
#include "d2_common.h"
#ifdef __cplusplus
extern "C" {
#endif
int d2_range_valid(const D2ByteRange *r);
int d2_range_end(const D2ByteRange *r, uint64_t *out_end);
int d2_range_contains(const D2ByteRange *outer, const D2ByteRange *inner);
int d2_range_align(D2ByteRange *r, uint64_t alignment, uint64_t file_bytes);
int d2_range_sort_merge(D2ByteRange *ranges, size_t *count, size_t cap);
#ifdef __cplusplus
}
#endif
#endif
