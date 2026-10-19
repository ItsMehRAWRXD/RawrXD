#include "d2_range.h"
#include <stdlib.h>

int d2_range_valid(const D2ByteRange *r) {
    uint64_t e;
    if (!r || r->bytes == 0) return 0;
    if (UINT64_MAX - r->offset < r->bytes) return 0;
    e = r->offset + r->bytes;
    return e > r->offset;
}
int d2_range_end(const D2ByteRange *r, uint64_t *out_end) {
    if (!out_end || !d2_range_valid(r)) return D2_EINVAL;
    *out_end = r->offset + r->bytes;
    return D2_OK;
}
int d2_range_contains(const D2ByteRange *outer, const D2ByteRange *inner) {
    uint64_t oe, ie;
    if (!outer || !inner || outer->shard != inner->shard) return 0;
    if (d2_range_end(outer,&oe) || d2_range_end(inner,&ie)) return 0;
    return inner->offset >= outer->offset && ie <= oe;
}
int d2_range_align(D2ByteRange *r, uint64_t alignment, uint64_t file_bytes) {
    uint64_t end, a0, a1;
    if (!r || !d2_range_valid(r) || alignment == 0 || (alignment & (alignment-1)) != 0) return D2_EINVAL;
    end = r->offset + r->bytes;
    a0 = r->offset & ~(alignment-1);
    if (end > UINT64_MAX - (alignment-1)) return D2_EINVAL;
    a1 = (end + alignment-1) & ~(alignment-1);
    if (file_bytes && a1 > file_bytes) a1 = file_bytes;
    if (a1 <= a0) return D2_EINVAL;
    r->offset = a0; r->bytes = a1-a0;
    return D2_OK;
}
static int cmp_range(const void *a, const void *b) {
    const D2ByteRange *x=(const D2ByteRange*)a,*y=(const D2ByteRange*)b;
    if (x->shard != y->shard) return x->shard < y->shard ? -1:1;
    if (x->offset != y->offset) return x->offset < y->offset ? -1:1;
    if (x->bytes != y->bytes) return x->bytes < y->bytes ? -1:1;
    return 0;
}
int d2_range_sort_merge(D2ByteRange *r, size_t *count, size_t cap) {
    size_t i,w;
    if (!r || !count || *count > cap) return D2_EINVAL;
    for (i=0;i<*count;i++) if (!d2_range_valid(&r[i])) return D2_EINVAL;
    qsort(r,*count,sizeof(*r),cmp_range);
    w=0;
    for (i=0;i<*count;i++) {
        if (w==0) { r[w++]=r[i]; continue; }
        D2ByteRange *p=&r[w-1];
        uint64_t pe=p->offset+p->bytes, re=r[i].offset+r[i].bytes;
        /* Merge only ranges that refer to the same physical interpretation. */
        if (p->shard==r[i].shard && p->codec==r[i].codec && p->tensor_id==r[i].tensor_id && p->role==r[i].role && p->expert_id==r[i].expert_id && r[i].offset<=pe) {
            if (re>pe) p->bytes=re-p->offset;
        } else if (p->shard==r[i].shard && p->codec==r[i].codec && p->role==r[i].role && p->expert_id==r[i].expert_id && r[i].offset==pe) {
            /* contiguous pieces for same expert/role may be coalesced; tensor_id=0 denotes composite */
            p->bytes += r[i].bytes; p->tensor_id=0;
        } else {
            if (w>=cap) return D2_ENOSPC;
            r[w++]=r[i];
        }
    }
    *count=w; return D2_OK;
}
