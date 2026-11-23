#pragma once
// Native, dependency-free GGUF repacker. Preserves metadata bytes and tensor
// types; streams tensor payloads without materializing the whole model.
// This is lossless repackaging, not compression or expert pruning.
#include "NativeTensorInventory.hpp"
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <limits>
#include <set>
#include <string>
#include <vector>

namespace RawrXD { namespace REAP {
enum class RepackError { None, Input, Format, Unsupported, Overflow, Output };
struct RepackTensor {
    std::string name;
    std::vector<uint64_t> dims;
    uint32_t type = 0;
    uint64_t old_offset = 0, new_offset = 0, bytes = 0;
};
inline bool ReadU32(std::istream& in, uint32_t& v) {
    return static_cast<bool>(in.read(reinterpret_cast<char*>(&v),4));
}
inline bool ReadU64(std::istream& in, uint64_t& v) {
    return static_cast<bool>(in.read(reinterpret_cast<char*>(&v),8));
}
inline bool WriteU32(std::ostream& out, uint32_t v) {
    return static_cast<bool>(out.write(reinterpret_cast<const char*>(&v),4));
}
inline bool WriteU64(std::ostream& out, uint64_t v) {
    return static_cast<bool>(out.write(reinterpret_cast<const char*>(&v),8));
}
inline bool ReadName(std::istream& in, std::string& s) {
    uint64_t n=0;
    if (!ReadU64(in,n) || n > (1ULL<<20)) return false;
    s.resize(static_cast<size_t>(n));
    return n==0 || static_cast<bool>(in.read(&s[0],static_cast<std::streamsize>(n)));
}
inline bool WriteName(std::ostream& out, const std::string& s) {
    return WriteU64(out,s.size()) &&
        static_cast<bool>(out.write(s.data(),static_cast<std::streamsize>(s.size())));
}
inline bool SkipExact(std::istream& in, uint64_t bytes) {
    const auto p=in.tellg();
    if (p<0 || bytes>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max())) return false;
    in.seekg(0,std::ios::end);
    const auto end=in.tellg();
    if (end<p || static_cast<uint64_t>(end-p)<bytes) return false;
    in.seekg(p+static_cast<std::streamoff>(bytes));
    return static_cast<bool>(in);
}
inline bool SkipMetadata(std::istream& in, uint32_t type) {
    static const uint8_t sizes[]={1,1,2,2,4,4,4,1,0,0,8,8,8};
    if(type>12) return false;
    if(type==8) {uint64_t n=0; return ReadU64(in,n)&&n<=(1ULL<<26)&&SkipExact(in,n);}
    if(type==9) {
        uint32_t elem=0; uint64_t count=0;
        if(!ReadU32(in,elem)||!ReadU64(in,count)||elem>12||elem==9||
           count>(1ULL<<24)) return false;
        if(elem==8) {
            for(uint64_t i=0;i<count;++i)if(!SkipMetadata(in,8))return false;
            return true;
        }
        return count<=UINT64_MAX/sizes[elem] && SkipExact(in,count*sizes[elem]);
    }
    return SkipExact(in,sizes[type]);
}
inline bool CopyRange(std::ifstream& in, std::ofstream& out,
                      uint64_t from, uint64_t count) {
    if(from>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()))return false;
    in.clear();
    in.seekg(static_cast<std::streamoff>(from),std::ios::beg);
    if(!in)return false;
    char buffer[1<<16];
    while(count) {
        const auto n=static_cast<std::streamsize>(std::min<uint64_t>(count,sizeof(buffer)));
        if(!in.read(buffer,n)||!out.write(buffer,n))return false;
        count-=static_cast<uint64_t>(n);
    }
    return true;
}
inline bool PadTo(std::ofstream& out, uint64_t alignment) {
    const auto p=out.tellp();
    if(p<0)return false;
    const auto pos=static_cast<uint64_t>(p);
    const auto missing=(alignment-(pos%alignment))%alignment;
    for(uint64_t i=0;i<missing;++i)out.put('\0');
    return static_cast<bool>(out);
}
inline RepackError RepackGGUF(const std::string& input,
                             const std::string& output,
                             uint64_t max_output_bytes=UINT64_MAX) {
    if(input==output)return RepackError::Output;
    std::ifstream in(input,std::ios::binary);
    if(!in)return RepackError::Input;
    uint32_t magic=0,version=0;
    uint64_t tensorCount=0,kvCount=0;
    if(!ReadU32(in,magic)||!ReadU32(in,version)||
       !ReadU64(in,tensorCount)||!ReadU64(in,kvCount)||
       magic!=0x46554747 || (version!=2&&version!=3) ||
       tensorCount>(1ULL<<20)||kvCount>(1ULL<<20))return RepackError::Format;
    uint64_t alignment=32;
    bool alignmentSeen=false;
    std::set<std::string> metadataKeys;
    for(uint64_t i=0;i<kvCount;++i) {
        std::string key;uint32_t type=0;
        if(!ReadName(in,key)||key.empty()||!metadataKeys.insert(key).second||
           !ReadU32(in,type))return RepackError::Format;
        if(key=="general.alignment") {
            if(alignmentSeen)return RepackError::Format;
            alignmentSeen=true;
            uint32_t value=0;
            if(type!=4||!ReadU32(in,value)||value<8||value>4096||
               (value&(value-1)))return RepackError::Format;
            alignment=value;
        } else if(!SkipMetadata(in,type))return RepackError::Format;
    }
    const auto metadataEnd=in.tellg();
    if(metadataEnd<0)return RepackError::Format;
    std::vector<RepackTensor> tensors;
    tensors.reserve(static_cast<size_t>(tensorCount));
    std::set<std::string> tensorNames;
    for(uint64_t i=0;i<tensorCount;++i) {
        RepackTensor t;uint32_t nd=0;
        if(!ReadName(in,t.name)||t.name.empty()||
           !tensorNames.insert(t.name).second||!ReadU32(in,nd)||
           nd==0||nd>8)return RepackError::Format;
        t.dims.resize(nd);
        uint64_t count=1;
        for(auto& dim:t.dims) {
            if(!ReadU64(in,dim)||!dim||!CheckedMultiply(count,dim,count))
                return RepackError::Format;
        }
        uint64_t block=0,blockBytes=0;
        if(!ReadU32(in,t.type)||!ReadU64(in,t.old_offset)||
           !StorageLayout(t.type,block,blockBytes)||count%block||
           !CheckedMultiply(count/block,blockBytes,t.bytes))
            return RepackError::Unsupported;
        tensors.push_back(std::move(t));
    }
    const auto directoryEnd=in.tellg();
    if(directoryEnd<0)return RepackError::Format;
    const uint64_t dirEnd=static_cast<uint64_t>(directoryEnd);
    if(dirEnd>UINT64_MAX-(alignment-1))return RepackError::Overflow;
    const uint64_t dataStart=(dirEnd+alignment-1)&~(alignment-1);
    in.seekg(0,std::ios::end);
    const auto fileEnd=in.tellg();
    if(fileEnd<0||static_cast<uint64_t>(fileEnd)<dataStart)return RepackError::Format;
    const uint64_t payload=static_cast<uint64_t>(fileEnd)-dataStart;
    for(const auto& t:tensors) {
        if(t.old_offset%alignment||t.old_offset>payload||
           t.bytes>payload-t.old_offset)return RepackError::Format;
    }
    std::vector<const RepackTensor*> offsets;
    for(const auto& t:tensors)offsets.push_back(&t);
    std::sort(offsets.begin(),offsets.end(),
              [](const RepackTensor* a,const RepackTensor* b){return a->old_offset<b->old_offset;});
    uint64_t prev=0;
    for(const auto* t:offsets) {
        if(t->old_offset<prev)return RepackError::Format;
        prev=t->old_offset+t->bytes;
    }
    uint64_t cursor=0;
    for(auto& t:tensors) {
        if(cursor>UINT64_MAX-(alignment-1))return RepackError::Overflow;
        t.new_offset=(cursor+alignment-1)&~(alignment-1);
        if(t.bytes>UINT64_MAX-t.new_offset)return RepackError::Overflow;
        cursor=t.new_offset+t.bytes;
    }
    // Budget check before opening destination; never silently truncate.
    uint64_t newDir=static_cast<uint64_t>(metadataEnd);
    for(const auto& t:tensors) {
        if(t.name.size()>UINT64_MAX-newDir-8-4-4-8-8*t.dims.size())
            return RepackError::Overflow;
        newDir+=8+t.name.size()+4+8*t.dims.size()+4+8;
    }
    if(newDir>UINT64_MAX-(alignment-1))return RepackError::Overflow;
    const uint64_t newData=(newDir+alignment-1)&~(alignment-1);
    if(cursor>UINT64_MAX-newData||newData+cursor>max_output_bytes)
        return RepackError::Overflow;
    std::ofstream out(output,std::ios::binary|std::ios::trunc);
    if(!out)return RepackError::Output;
    if(!CopyRange(in,out,0,static_cast<uint64_t>(metadataEnd)))
        return RepackError::Output;
    for(const auto& t:tensors) {
        if(!WriteName(out,t.name)||!WriteU32(out,static_cast<uint32_t>(t.dims.size())))
            return RepackError::Output;
        for(uint64_t d:t.dims)if(!WriteU64(out,d))return RepackError::Output;
        if(!WriteU32(out,t.type)||!WriteU64(out,t.new_offset))
            return RepackError::Output;
    }
    if(!PadTo(out,alignment))return RepackError::Output;
    for(const auto& t:tensors) {
        if(!PadTo(out,alignment)||
           !CopyRange(in,out,dataStart+t.old_offset,t.bytes))
            return RepackError::Output;
    }
    out.flush();
    return out?RepackError::None:RepackError::Output;
}
}} // namespace RawrXD::REAP
