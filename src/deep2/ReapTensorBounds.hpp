#pragma once
#include <algorithm>
#include <cstdint>
#include <string_view>
#include <vector>

namespace Deep2 { namespace ReapBounds {
inline bool Mul(uint64_t a,uint64_t b,uint64_t& out) noexcept {
    if (a && b>UINT64_MAX/a) return false;
    out=a*b;return true;
}
// Persisted GGUF rows contain whole quantization blocks. No implicit padding
// or division of packed blocks into independently addressable scalar weights.
inline bool ByteSize(const std::vector<uint64_t>& dims,uint64_t blockElems,
                     uint64_t blockBytes,uint64_t& bytes) noexcept {
    if(dims.empty()||!blockElems||!blockBytes||!dims.front()||dims.front()%blockElems)return false;
    uint64_t n=0;
    if(!Mul(dims.front()/blockElems,blockBytes,n))return false;
    for(size_t i=1;i<dims.size();++i)if(!dims[i]||!Mul(n,dims[i],n))return false;
    bytes=n;return true;
}
inline bool SliceStride(const std::vector<uint64_t>& dims,uint64_t blockElems,
                        uint64_t blockBytes,uint64_t storedBytes,uint64_t& stride) noexcept {
    uint64_t expected=0;
    if(!ByteSize(dims,blockElems,blockBytes,expected)||expected!=storedBytes)return false;
    if(dims.size()==1){if(blockElems!=1)return false;stride=blockBytes;return true;}
    stride=expected/dims.back();return stride!=0;
}
inline bool LayerIndex(std::string_view name,uint32_t& layer) noexcept {
    if(name.substr(0,4)!="blk.")return false;
    const auto end=name.find('.',4);
    if(end==std::string_view::npos||end==4||end+1==name.size())return false;
    uint32_t n=0;
    for(size_t i=4;i<end;++i){
        const char c=name[i];if(c<'0'||c>'9')return false;
        const auto d=static_cast<uint32_t>(c-'0');
        if(n>(UINT32_MAX-d)/10)return false;
        n=n*10+d;
    }
    if(n==UINT32_MAX)return false;
    layer=n;return true;
}
struct Range {uint64_t offset,bytes;};
inline bool ValidRanges(std::vector<Range> ranges,uint64_t dataBytes,uint64_t alignment) {
    if(!alignment||(alignment&(alignment-1)))return false;
    std::sort(ranges.begin(),ranges.end(),[](const Range& a,const Range& b){return a.offset<b.offset;});
    uint64_t end=0;
    for(const auto& r:ranges){
        if(!r.bytes||r.offset%alignment||r.offset<end||r.offset>dataBytes||r.bytes>dataBytes-r.offset)return false;
        end=r.offset+r.bytes;
    }
    return true;
}
} } // namespace Deep2::ReapBounds
