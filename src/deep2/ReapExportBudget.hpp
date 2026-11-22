#pragma once
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace Deep2 { namespace ReapExport {
using U = uint64_t;
inline bool Add(U a,U b,U& out) noexcept {
    if (b>UINT64_MAX-a) return false;
    out=a+b;return true;
}
inline bool Align(U n,U a,U& out) noexcept {
    if (!a || (a&(a-1))) return false;
    const U r=n%a;return Add(n,r?a-r:0,out);
}
struct Router {
    U original=0, top=0, groups=1, used=1;
    bool Valid() const noexcept {
        return original && original<=UINT32_MAX && top && top<=original && groups &&
            groups<=original && used && used<=groups && original%groups==0 &&
            top<=used*(original/groups);
    }
    bool Allows(U keep) const noexcept {
        return Valid() && keep && keep<=original && keep%groups==0 && top<=used*(keep/groups);
    }
    bool Preserves(const std::vector<uint32_t>& ids) const noexcept {
        if(!Allows(ids.size()))return false;
        const U oldWidth=original/groups,newWidth=ids.size()/groups;
        for(std::size_t i=0;i<ids.size();++i){
            if(ids[i]>=original || ids[i]/oldWidth!=i/newWidth)return false;
            for(std::size_t j=0;j<i;++j)if(ids[j]==ids[i])return false;
        }
        return true;
    }
};
// Positive explicit GGUF fields, accumulated consistently over all shards.
// Missing group fields imply ungrouped routing only when no width contradicts it.
struct GroupFields {
    U groups=0,used=0,width=0;
    static bool Observe(U& field,U value) noexcept {
        if(!value || value>UINT32_MAX || (field && field!=value))return false;
        field=value;return true;
    }
    bool Resolve(U original,U top,Router& out) const noexcept {
        U g=groups;
        if(width){if(!original || original%width)return false;const U derived=original/width;if(g&&g!=derived)return false;g=derived;}
        if(!g)g=1;
        if(g>1&&!used)return false;
        Router next{original,top,g,used?used:1};
        if(!next.Valid())return false;
        out=next;return true;
    }
};
struct Tensor { U bytes=0; bool sliced=false; };
struct Shard { U header=0, alignment=32; std::vector<Tensor> tensors; };
// Exact output size for the existing writer: header including patched metadata
// and descriptors, then aligned tensor payloads. No rounding to file blocks.
inline bool Measure(const Shard& shard,const Router& router,U keep,U& bytes) noexcept {
    if(!router.Allows(keep) || !shard.header)return false;
    U cursor=0;
    if(!Align(shard.header,shard.alignment,cursor))return false;
    for(const auto& t:shard.tensors){
        if(!t.bytes || (t.sliced && t.bytes%router.original))return false;
        const U n=t.sliced?(t.bytes/router.original)*keep:t.bytes;
        if(!Align(cursor,shard.alignment,cursor)||!Add(cursor,n,cursor))return false;
    }
    bytes=cursor;return true;
}
inline bool MeasureAll(const std::vector<Shard>& shards,const Router& router,U keep,U& bytes) noexcept {
    if(shards.empty())return false;
    U total=0,n=0;
    for(const auto& s:shards)if(!Measure(s,router,keep,n)||!Add(total,n,total))return false;
    bytes=total;return true;
}
// Largest uniform group-preserving retention fitting a hard serialized byte
// budget at current tensor dtypes. Returns zero retained if none can fit.
inline bool MaxRetained(const std::vector<Shard>& shards,const Router& router,U budget,U& retained) noexcept {
    if(!router.Valid()||!budget)return false;
    U lo=(router.top+router.used-1)/router.used,hi=router.original/router.groups;
    U n=0;
    // Validate full source layout and arithmetic before searching.
    if(!MeasureAll(shards,router,router.original,n))return false;
    U best=0;
    while(lo<=hi){const U mid=lo+(hi-lo)/2;
        if(!MeasureAll(shards,router,mid*router.groups,n))return false;
        if(n<=budget){best=mid*router.groups;lo=mid+1;}else hi=mid-1;
    }
    retained=best;return true;
}
} } // namespace Deep2::ReapExport
