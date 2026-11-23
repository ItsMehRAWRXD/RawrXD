#pragma once
// Native, dependency-free GGUF repacker. Preserves metadata bytes and tensor
// types; streams tensor payloads without materializing the whole model.
// Optional F32->F16 conversion is lossy; all other tensor types are preserved.
#include "NativeTensorInventory.hpp"
#include "NativeFloat16.hpp"
#include <algorithm>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <fstream>
#include <filesystem>
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
    uint64_t old_offset = 0, new_offset = 0, bytes = 0, source_bytes = 0;
    bool convert_f16 = false;
    bool convert_q8_0 = false;
    bool q8_source_f16 = false;
    bool convert_q4_0 = false;
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
        if (elem==9 || sizes[elem]==0) return false;
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
inline bool ConvertF32RangeToF16(std::ifstream& in, std::ofstream& out,
                                  uint64_t from, uint64_t sourceBytes) {
    if(sourceBytes%4 || from>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()))
        return false;
    in.clear();
    in.seekg(static_cast<std::streamoff>(from),std::ios::beg);
    if(!in)return false;
    unsigned char source[65536];
    unsigned char dest[32768];
    while(sourceBytes) {
        const auto n=static_cast<std::streamsize>(std::min<uint64_t>(sourceBytes,sizeof(source)));
        if(!in.read(reinterpret_cast<char*>(source),n))return false;
        for(std::streamsize i=0;i<n;i+=4) {
            const uint32_t bits=uint32_t(source[i])|(uint32_t(source[i+1])<<8)|
                (uint32_t(source[i+2])<<16)|(uint32_t(source[i+3])<<24);
            const uint16_t half=Float32BitsToFloat16(bits);
            dest[i/2]=static_cast<unsigned char>(half);
            dest[i/2+1]=static_cast<unsigned char>(half>>8);
        }
        if(!out.write(reinterpret_cast<const char*>(dest),n/2))return false;
        sourceBytes-=static_cast<uint64_t>(n);
    }
    return true;
}
// GGML Q8_0: 32 signed 8-bit weights with a little-endian FP16 scale.
// A complete 32-element block is mandatory; do not quantize nonfinite weights.
inline bool ConvertFloatRangeToQ8_0(std::ifstream& in,std::ofstream& out,
                                    uint64_t from,uint64_t sourceBytes,
                                    bool sourceF16) {
    const uint64_t inputBlock=sourceF16?64:128;
    if(sourceBytes%inputBlock || from>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()))
        return false;
    in.clear();in.seekg(static_cast<std::streamoff>(from));
    if(!in)return false;
    unsigned char source[128],encoded[34];
    while(sourceBytes) {
        if(!in.read(reinterpret_cast<char*>(source),static_cast<std::streamsize>(inputBlock)))return false;
        float values[32];
        float maxAbs=0.0f;
        for(unsigned i=0;i<32;++i) {
            uint32_t bits=0;
            if(sourceF16) {
                const unsigned j=i*2;
                const uint16_t half=uint16_t(source[j])|(uint16_t(source[j+1])<<8);
                bits=Float16ToFloat32Bits(half);
            } else {
                const unsigned j=i*4;
                bits=uint32_t(source[j])|(uint32_t(source[j+1])<<8)|
                    (uint32_t(source[j+2])<<16)|(uint32_t(source[j+3])<<24);
            }
            std::memcpy(&values[i],&bits,4);
            if(!std::isfinite(values[i]))return false;
            maxAbs=std::max(maxAbs,std::abs(values[i]));
        }
        const float scale=maxAbs/127.0f;
        uint32_t scaleBits=0;std::memcpy(&scaleBits,&scale,4);
        const uint16_t half=Float32BitsToFloat16(scaleBits);
        const uint32_t decoded=Float16ToFloat32Bits(half);
        float actualScale=0.0f;std::memcpy(&actualScale,&decoded,4);
        if(maxAbs!=0.0f && (!std::isfinite(actualScale)||actualScale==0.0f))
            return false;
        encoded[0]=static_cast<unsigned char>(half);
        encoded[1]=static_cast<unsigned char>(half>>8);
        for(unsigned i=0;i<32;++i) {
            const double normalized=actualScale==0.0f?0.0:
                static_cast<double>(values[i])/actualScale;
            const double rounded=std::round(normalized);
            const int q=static_cast<int>(std::max(-127.0,std::min(127.0,rounded)));
            encoded[2+i]=static_cast<unsigned char>(static_cast<int8_t>(q));
        }
        if(!out.write(reinterpret_cast<const char*>(encoded),34))return false;
        sourceBytes-=inputBlock;
    }
    return true;
}
inline bool ConvertF32RangeToQ8_0(std::ifstream& in,std::ofstream& out,
                                   uint64_t from,uint64_t sourceBytes) {
    return ConvertFloatRangeToQ8_0(in,out,from,sourceBytes,false);
}
// GGML Q4_0 from existing Q8_0: 32 values, FP16 scale and 16 packed nibbles.
// Nibble i is the low half; nibble i+16 is the high half of byte i.
inline bool ConvertQ8_0RangeToQ4_0(std::ifstream& in,std::ofstream& out,
                                    uint64_t from,uint64_t sourceBytes) {
    if(sourceBytes%34 || from>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()))
        return false;
    in.clear();in.seekg(static_cast<std::streamoff>(from));
    if(!in)return false;
    unsigned char source[34],encoded[18];
    while(sourceBytes) {
        if(!in.read(reinterpret_cast<char*>(source),34))return false;
        const uint16_t h=uint16_t(source[0])|(uint16_t(source[1])<<8);
        const uint32_t scaleBits=Float16ToFloat32Bits(h);
        float scale=0;std::memcpy(&scale,&scaleBits,4);
        if(!std::isfinite(scale))return false;
        float values[32],extreme=0;
        for(unsigned i=0;i<32;++i) {
            values[i]=static_cast<float>(static_cast<int8_t>(source[2+i]))*scale;
            if(!std::isfinite(values[i]))return false;
            if(std::abs(values[i])>std::abs(extreme))extreme=values[i];
        }
        const float d=extreme/-8.0f;
        uint32_t bits=0;std::memcpy(&bits,&d,4);
        const uint16_t half=Float32BitsToFloat16(bits);
        const uint32_t decoded=Float16ToFloat32Bits(half);
        float actual=0;std::memcpy(&actual,&decoded,4);
        if(extreme!=0 && (!std::isfinite(actual)||actual==0))return false;
        encoded[0]=static_cast<unsigned char>(half);
        encoded[1]=static_cast<unsigned char>(half>>8);
        unsigned char codes[32];
        for(unsigned i=0;i<32;++i) {
            const double normalized=actual==0?0.0:static_cast<double>(values[i])/actual;
            const double q=std::floor(normalized+8.5);
            codes[i]=static_cast<unsigned char>(std::max(0.0,std::min(15.0,q)));
        }
        for(unsigned i=0;i<16;++i)encoded[2+i]=static_cast<unsigned char>(codes[i]|(codes[i+16]<<4));
        if(!out.write(reinterpret_cast<const char*>(encoded),18))return false;
        sourceBytes-=34;
    }
    return true;
}
inline RepackError RepackGGUF(const std::string& input,
                             const std::string& output,
                             uint64_t max_output_bytes=UINT64_MAX,
                             bool convert_f32_to_f16=false,
                             bool convert_f32_to_q8_0=false,
                             bool convert_q8_0_to_q4_0=false) {
    if(unsigned(convert_f32_to_f16)+unsigned(convert_f32_to_q8_0)+
       unsigned(convert_q8_0_to_q4_0)>1)return RepackError::Unsupported;
    if(input==output)return RepackError::Output;
    // A different spelling of the same file must not truncate the source.
    // This also catches hard links and relative/absolute path aliases.
    std::error_code pathError;
    const bool sameFile=std::filesystem::equivalent(input,output,pathError);
    if(!pathError && sameFile)return RepackError::Output;
    std::ifstream in(input,std::ios::binary);
    if(!in)return RepackError::Input;
    uint32_t magic=0,version=0;
    uint64_t tensorCount=0,kvCount=0;
    if(!ReadU32(in,magic)||!ReadU32(in,version)||
       !ReadU64(in,tensorCount)||!ReadU64(in,kvCount)||
       magic!=0x46554747 || (version!=2&&version!=3) ||
       tensorCount==0||tensorCount>(1ULL<<20)||kvCount>(1ULL<<20))return RepackError::Format;
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
        t.source_bytes=t.bytes;
        if(convert_f32_to_f16 && t.type==0) {
            t.convert_f16=true;
            t.type=1; // GGML_TYPE_F16
            t.bytes/=2;
        }
        if(convert_f32_to_q8_0 && (t.type==0 || t.type==1) && count%32==0) {
            t.convert_q8_0=true;
            t.q8_source_f16=(t.type==1);
            t.type=8; // GGML_TYPE_Q8_0 (32 values per 34-byte block)
            t.bytes=(count/32)*34;
        }
        if(convert_q8_0_to_q4_0 && t.type==8) {
            t.convert_q4_0=true;
            t.type=2; // GGML_TYPE_Q4_0
            t.bytes=(count/32)*18;
        }
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
           t.source_bytes>payload-t.old_offset)return RepackError::Format;
    }
    std::vector<const RepackTensor*> offsets;
    for(const auto& t:tensors)offsets.push_back(&t);
    std::sort(offsets.begin(),offsets.end(),
              [](const RepackTensor* a,const RepackTensor* b){return a->old_offset<b->old_offset;});
    uint64_t prev=0;
    for(const auto* t:offsets) {
        if(t->old_offset<prev)return RepackError::Format;
        prev=t->old_offset+t->source_bytes;
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
        // Checked addition at every step: subtraction of a compound
        // expression could wrap before the bounds comparison.
        const uint64_t nameBytes=static_cast<uint64_t>(t.name.size());
        const uint64_t dimsBytes=static_cast<uint64_t>(t.dims.size())*8;
        const uint64_t fixedBytes=8+4+4+8;
        if(nameBytes>UINT64_MAX-fixedBytes ||
           dimsBytes>UINT64_MAX-fixedBytes-nameBytes)
            return RepackError::Overflow;
        const uint64_t entryBytes=fixedBytes+nameBytes+dimsBytes;
        if(newDir>UINT64_MAX-entryBytes)return RepackError::Overflow;
        newDir+=entryBytes;
    }
    if(newDir>UINT64_MAX-(alignment-1))return RepackError::Overflow;
    const uint64_t newData=(newDir+alignment-1)&~(alignment-1);
    if(cursor>UINT64_MAX-newData||newData+cursor>max_output_bytes||
       newData+cursor>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()))
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
        // Directory order and physical order are independent in GGUF.
        // Honor each advertised new offset, including its alignment gap.
        const auto position=out.tellp();
        if(position<0)return RepackError::Output;
        const uint64_t absolute=static_cast<uint64_t>(position);
        if(t.new_offset>UINT64_MAX-newData)return RepackError::Overflow;
        const uint64_t target=newData+t.new_offset;
        if(absolute>target)return RepackError::Format;
        uint64_t padding=target-absolute;
        const char zeros[4096]={};
        while(padding) {
            const auto chunk=static_cast<std::streamsize>(
                std::min<uint64_t>(padding,sizeof(zeros)));
            if(!out.write(zeros,chunk))return RepackError::Output;
            padding-=static_cast<uint64_t>(chunk);
        }
        if(t.old_offset>UINT64_MAX-dataStart)return RepackError::Overflow;
        if(t.convert_q4_0) {
            if(!ConvertQ8_0RangeToQ4_0(in,out,dataStart+t.old_offset,t.source_bytes))
                return RepackError::Output;
        } else if(t.convert_q8_0) {
            if(!ConvertFloatRangeToQ8_0(in,out,dataStart+t.old_offset,
                                        t.source_bytes,t.q8_source_f16))
                return RepackError::Output;
        } else if(t.convert_f16) {
            if(!ConvertF32RangeToF16(in,out,dataStart+t.old_offset,t.source_bytes))
                return RepackError::Output;
        } else if(!CopyRange(in,out,dataStart+t.old_offset,t.source_bytes))
            return RepackError::Output;
    }
    out.flush();
    if(!out)return RepackError::Output;
    const auto finalPosition=out.tellp();
    if(finalPosition<0||static_cast<uint64_t>(finalPosition)!=newData+cursor)
        return RepackError::Output;
    out.close();
    return out?RepackError::None:RepackError::Output;
}
}} // namespace RawrXD::REAP
