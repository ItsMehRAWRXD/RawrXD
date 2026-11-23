#pragma once
// Native, dependency-free GGUF repacker. Preserves metadata bytes and tensor
// types; streams tensor payloads without materializing the whole model.
// Explicit conversion modes requantize eligible tensor types; otherwise payloads
// are preserved. Quantization is lossy and requires numerical validation.
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
    bool q8_source_k = false;
    bool q8_source_q8_1 = false;
    bool convert_q4_0 = false;
    bool convert_q5_0 = false;
    uint32_t q4_source_type = 0;
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
// GGML tensor naming conventions: normalization and embedding/output weights
// are quality-sensitive. Never silently requantize these in broad --q4-0
// mode. Explicitly preserve tensors that need a dedicated calibration policy.
inline bool IsQualitySensitiveTensor(const std::string& name) {
    std::string lower;
    lower.reserve(name.size());
    for(unsigned char c:name)
        lower.push_back(c>='A'&&c<='Z'?static_cast<char>(c+('a'-'A')):static_cast<char>(c));
    return lower.find("norm")!=std::string::npos ||
           lower.find("embed")!=std::string::npos ||
           lower.find("token_embd")!=std::string::npos ||
           lower.find("output.weight")!=std::string::npos ||
           lower.find("lm_head")!=std::string::npos ||
           lower.find("rope_freq")!=std::string::npos ||
           lower.find("freqs")!=std::string::npos ||
           lower.find("bias")!=std::string::npos;
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
            float value=0;
            std::memcpy(&value,&bits,4);
            if(!std::isfinite(value))return false;
            const uint16_t half=Float32BitsToFloat16(bits);
            const uint32_t restoredBits=Float16ToFloat32Bits(half);
            float restored=0;
            std::memcpy(&restored,&restoredBits,4);
            if(!std::isfinite(restored) || (value!=0.0f && restored==0.0f))
                return false;
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
inline bool ConvertToQ4_0(std::ifstream& in,std::ofstream& out,
                           uint64_t from,uint64_t sourceBytes,uint32_t sourceType) {
    const uint64_t inputBlock=sourceType==0?128:sourceType==1?64:
        sourceType==8?34:sourceType==9?40:
        sourceType==6?22:sourceType==3?20:sourceType==7?24:0;
    if(!inputBlock || sourceBytes%inputBlock || from>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()))
        return false;
    in.clear();in.seekg(static_cast<std::streamoff>(from));
    if(!in)return false;
    unsigned char source[128],encoded[18];
    while(sourceBytes) {
        if(!in.read(reinterpret_cast<char*>(source),static_cast<std::streamsize>(inputBlock)))return false;
        float values[32],extreme=0;
        if(sourceType==0 || sourceType==1) {
            for(unsigned i=0;i<32;++i) {
                uint32_t bits=0;
                if(sourceType==0) {
                    const unsigned j=i*4;
                    bits=uint32_t(source[j])|(uint32_t(source[j+1])<<8)|
                        (uint32_t(source[j+2])<<16)|(uint32_t(source[j+3])<<24);
                } else {
                    const unsigned j=i*2;
                    const uint16_t half=uint16_t(source[j])|(uint16_t(source[j+1])<<8);
                    bits=Float16ToFloat32Bits(half);
                }
                std::memcpy(&values[i],&bits,4);
                if(!std::isfinite(values[i]))return false;
                if(std::abs(values[i])>std::abs(extreme))extreme=values[i];
            }
        } else {
            float scale=0;
            if(sourceType==9) {
                const uint32_t bits=uint32_t(source[0])|(uint32_t(source[1])<<8)|
                    (uint32_t(source[2])<<16)|(uint32_t(source[3])<<24);
                std::memcpy(&scale,&bits,4);
            } else {
                const uint16_t half=uint16_t(source[0])|(uint16_t(source[1])<<8);
                const uint32_t bits=Float16ToFloat32Bits(half);
                std::memcpy(&scale,&bits,4);
            }
            if(!std::isfinite(scale))return false;
            float minimum=0;
            if(sourceType==3 || sourceType==7) {
                const uint16_t half=uint16_t(source[2])|(uint16_t(source[3])<<8);
                const uint32_t bits=Float16ToFloat32Bits(half);
                std::memcpy(&minimum,&bits,4);
                if(!std::isfinite(minimum))return false;
            }
            for(unsigned i=0;i<32;++i) {
                int quantized=0;
                if(sourceType==8)quantized=static_cast<int8_t>(source[2+i]);
                else if(sourceType==9)quantized=static_cast<int8_t>(source[8+i]);
                else if(sourceType==6 || sourceType==7) {
                    const unsigned qs=sourceType==6?6:8;
                    const unsigned qh=sourceType==6?2:4;
                    const unsigned j=i%16;
                    const unsigned nibble=i<16?(source[qs+j]&15):(source[qs+j]>>4);
                    const unsigned high=(source[qh+i/8]>>(i%8))&1;
                    quantized=static_cast<int>(nibble|(high<<4));
                    if(sourceType==6)quantized-=16;
                } else if(sourceType==3) {
                    const unsigned j=i%16;
                    quantized=static_cast<int>(i<16?(source[4+j]&15):(source[4+j]>>4));
                } else return false;
                values[i]=static_cast<float>(quantized)*scale+minimum;
                if(!std::isfinite(values[i]))return false;
                if(std::abs(values[i])>std::abs(extreme))extreme=values[i];
            }
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
        sourceBytes-=inputBlock;
    }
    return true;
}
// GGML Q8_K: FP32 d, 256 signed int8 values, then 16 int16 sums.
// Decode all 256 values, then independently encode eight Q4_0 blocks.
// No cross-row blocks and no whole-model buffering.
inline bool ConvertQ8KToQ4_0(std::ifstream& in,std::ofstream& out,
                              uint64_t from,uint64_t sourceBytes) {
    if(sourceBytes%292 || from>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()))
        return false;
    in.clear();in.seekg(static_cast<std::streamoff>(from));
    if(!in)return false;
    unsigned char source[292],encoded[18];
    while(sourceBytes) {
        if(!in.read(reinterpret_cast<char*>(source),292))return false;
        const uint32_t scaleBits=uint32_t(source[0])|(uint32_t(source[1])<<8)|
            (uint32_t(source[2])<<16)|(uint32_t(source[3])<<24);
        float scale=0;std::memcpy(&scale,&scaleBits,4);
        if(!std::isfinite(scale))return false;
        for(unsigned group=0;group<8;++group) {
            float values[32],extreme=0;
            for(unsigned i=0;i<32;++i) {
                values[i]=scale*static_cast<float>(static_cast<int8_t>(source[4+group*32+i]));
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
            for(unsigned i=0;i<16;++i)
                encoded[2+i]=static_cast<unsigned char>(codes[i]|(codes[i+16]<<4));
            if(!out.write(reinterpret_cast<const char*>(encoded),18))return false;
        }
        sourceBytes-=292;
    }
    return true;
}
inline bool ConvertQ6KToQ4_0(std::ifstream& in,std::ofstream& out,
                              uint64_t from,uint64_t sourceBytes) {
    if(sourceBytes%210 || from>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()))
        return false;
    in.clear();in.seekg(static_cast<std::streamoff>(from));
    if(!in)return false;
    unsigned char source[210],encoded[18];
    while(sourceBytes) {
        if(!in.read(reinterpret_cast<char*>(source),210))return false;
        // Q6_K layout: ql[128], qh[64], scales[16], FP16 d.
        const uint16_t halfScale=uint16_t(source[208])|(uint16_t(source[209])<<8);
        const uint32_t scaleBits=Float16ToFloat32Bits(halfScale);
        float scale=0;std::memcpy(&scale,&scaleBits,4);
        if(!std::isfinite(scale))return false;
        for(unsigned group=0;group<8;++group) {
            float values[32],extreme=0;
            for(unsigned i=0;i<32;++i) {
                const unsigned half=group/4;
                const unsigned quarter=group%4;
                const unsigned lane=i;
                const unsigned qlOffset=half*64+(quarter%2)*32+lane;
                const unsigned qhOffset=128+half*32+lane;
                const unsigned low=(source[qlOffset]>>(quarter>=2?4:0))&15;
                const unsigned high=(source[qhOffset]>>(quarter*2))&3;
                const int quantized=static_cast<int>(low|(high<<4))-32;
                const unsigned scaleIndex=half*8+quarter*2+lane/16;
                const int multiplier=static_cast<int8_t>(source[192+scaleIndex]);
                values[i]=scale*static_cast<float>(multiplier*quantized);
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
            for(unsigned i=0;i<16;++i)
                encoded[2+i]=static_cast<unsigned char>(codes[i]|(codes[i+16]<<4));
            if(!out.write(reinterpret_cast<const char*>(encoded),18))return false;
        }
        sourceBytes-=210;
    }
    return true;
}
inline bool ConvertQ6KToQ5_0(std::ifstream& in,std::ofstream& out,
                              uint64_t from,uint64_t sourceBytes) {
    if(sourceBytes%210 || from>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()))
        return false;
    in.clear();in.seekg(static_cast<std::streamoff>(from));
    if(!in)return false;
    unsigned char source[210],encoded[22];
    while(sourceBytes) {
        if(!in.read(reinterpret_cast<char*>(source),210))return false;
        // Q6_K layout: ql[128], qh[64], scales[16], FP16 d.
        const uint16_t halfScale=uint16_t(source[208])|(uint16_t(source[209])<<8);
        const uint32_t scaleBits=Float16ToFloat32Bits(halfScale);
        float scale=0;std::memcpy(&scale,&scaleBits,4);
        if(!std::isfinite(scale))return false;
        for(unsigned group=0;group<8;++group) {
            float values[32],extreme=0;
            for(unsigned i=0;i<32;++i) {
                const unsigned half=group/4;
                const unsigned quarter=group%4;
                const unsigned lane=i;
                const unsigned qlOffset=half*64+(quarter%2)*32+lane;
                const unsigned qhOffset=128+half*32+lane;
                const unsigned low=(source[qlOffset]>>(quarter>=2?4:0))&15;
                const unsigned high=(source[qhOffset]>>(quarter*2))&3;
                const int quantized=static_cast<int>(low|(high<<4))-32;
                const unsigned scaleIndex=half*8+quarter*2+lane/16;
                const int multiplier=static_cast<int8_t>(source[192+scaleIndex]);
                values[i]=scale*static_cast<float>(multiplier*quantized);
                if(!std::isfinite(values[i]))return false;
                if(std::abs(values[i])>std::abs(extreme))extreme=values[i];
            }
            const float d=extreme/-16.0f;
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
                const double q=std::floor(normalized+16.5);
                codes[i]=static_cast<unsigned char>(std::max(0.0,std::min(31.0,q)));
            }
            for(unsigned i=0;i<4;++i)encoded[2+i]=0;
            for(unsigned i=0;i<32;++i)
                encoded[2+i/8]|=static_cast<unsigned char>(((codes[i]>>4)&1)<<(i%8));
            for(unsigned i=0;i<16;++i)
                encoded[6+i]=static_cast<unsigned char>((codes[i]&15)|((codes[i+16]&15)<<4));
            if(!out.write(reinterpret_cast<const char*>(encoded),22))return false;
        }
        sourceBytes-=210;
    }
    return true;
}
inline bool ConvertQ5KToQ4_0(std::ifstream& in,std::ofstream& out,
                              uint64_t from,uint64_t sourceBytes) {
    if(sourceBytes%176 || from>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()))
        return false;
    in.clear();in.seekg(static_cast<std::streamoff>(from));
    if(!in)return false;
    unsigned char source[176],encoded[18];
    while(sourceBytes) {
        if(!in.read(reinterpret_cast<char*>(source),176))return false;
        // GGML Q5_K: FP16 d, FP16 dmin, scales[12], qh[32], qs[128].
        const uint16_t hd=uint16_t(source[0])|(uint16_t(source[1])<<8);
        const uint16_t hm=uint16_t(source[2])|(uint16_t(source[3])<<8);
        const uint32_t bd=Float16ToFloat32Bits(hd);
        const uint32_t bm=Float16ToFloat32Bits(hm);
        float dbase=0,mbase=0;
        std::memcpy(&dbase,&bd,4);std::memcpy(&mbase,&bm,4);
        if(!std::isfinite(dbase)||!std::isfinite(mbase))return false;
        const unsigned char* scales=source+4;
        for(unsigned group=0;group<8;++group) {
            float values[32],extreme=0;
            unsigned sc=0,m=0;
            if(group<4) {
                sc=scales[group]&63;
                m=scales[group+4]&63;
            } else {
                sc=(scales[group+4]&15)|((scales[group-4]>>6)<<4);
                m=(scales[group+4]>>4)|((scales[group]>>6)<<4);
            }
            const unsigned chunk=group/2,half=group%2;
            for(unsigned i=0;i<32;++i) {
                const unsigned packed=source[48+chunk*32+i];
                const unsigned low=half?(packed>>4):(packed&15);
                const unsigned high=(source[16+i]>>(group))&1;
                const unsigned quantized=low|(high<<4);
                values[i]=dbase*static_cast<float>(sc*quantized)-
                          mbase*static_cast<float>(m);
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
            for(unsigned i=0;i<16;++i)
                encoded[2+i]=static_cast<unsigned char>(codes[i]|(codes[i+16]<<4));
            if(!out.write(reinterpret_cast<const char*>(encoded),18))return false;
        }
        sourceBytes-=176;
    }
    return true;
}
// Requantize GGML Q8_K to eight independent GGML Q8_0 blocks.
// Each 256-weight Q8_K block is: FP32 d, 256 int8 weights, 16 int16 sums.
// Q8_0 uses a separately rounded FP16 scale per 32-weight block.
// Q8_1 has FP32 d, FP32 block sum, and 32 signed weights.
// Re-encode to the standard 34-byte Q8_0 block with an FP16 scale.
// The Q8_1 sum is derived metadata, not a second scaling factor.
inline bool ConvertQ8_1ToQ8_0(std::ifstream& in,std::ofstream& out,
                               uint64_t from,uint64_t sourceBytes) {
    if(sourceBytes%40 || from>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()))
        return false;
    in.clear();in.seekg(static_cast<std::streamoff>(from));
    if(!in)return false;
    unsigned char source[40],encoded[34];
    while(sourceBytes) {
        if(!in.read(reinterpret_cast<char*>(source),40))return false;
        const uint32_t bits=uint32_t(source[0])|(uint32_t(source[1])<<8)|
            (uint32_t(source[2])<<16)|(uint32_t(source[3])<<24);
        float scale=0;std::memcpy(&scale,&bits,4);
        if(!std::isfinite(scale))return false;
        // Exact fast path: Q8_1 and Q8_0 share the same signed 8-bit
        // quantization payload. If the FP32 scale is exactly representable
        // in FP16, preserve all 32 codes verbatim (including -128) instead
        // of introducing a second lossy quantization step. The Q8_1 sum
        // field is auxiliary and does not participate in reconstruction.
        const uint16_t directHalf=Float32BitsToFloat16(bits);
        if(Float16ToFloat32Bits(directHalf)==bits) {
            encoded[0]=static_cast<unsigned char>(directHalf);
            encoded[1]=static_cast<unsigned char>(directHalf>>8);
            std::memcpy(encoded+2,source+8,32);
            if(!out.write(reinterpret_cast<const char*>(encoded),34))return false;
            sourceBytes-=40;
            continue;
        }
        float values[32],maxAbs=0;
        for(unsigned i=0;i<32;++i) {
            values[i]=scale*static_cast<float>(static_cast<int8_t>(source[8+i]));
            if(!std::isfinite(values[i]))return false;
            maxAbs=std::max(maxAbs,std::abs(values[i]));
        }
        const float d=maxAbs/127.0f;
        uint32_t dbits=0;std::memcpy(&dbits,&d,4);
        const uint16_t half=Float32BitsToFloat16(dbits);
        const uint32_t decoded=Float16ToFloat32Bits(half);
        float actual=0;std::memcpy(&actual,&decoded,4);
        if(maxAbs!=0 && (!std::isfinite(actual)||actual==0))return false;
        encoded[0]=static_cast<unsigned char>(half);
        encoded[1]=static_cast<unsigned char>(half>>8);
        for(unsigned i=0;i<32;++i) {
            const double normalized=actual==0?0.0:static_cast<double>(values[i])/actual;
            const double q=std::round(normalized);
            const int value=static_cast<int>(std::max(-127.0,std::min(127.0,q)));
            encoded[2+i]=static_cast<unsigned char>(static_cast<int8_t>(value));
        }
        if(!out.write(reinterpret_cast<const char*>(encoded),34))return false;
        sourceBytes-=40;
    }
    return true;
}
inline bool ConvertQ8KToQ8_0(std::ifstream& in,std::ofstream& out,
                              uint64_t from,uint64_t sourceBytes) {
    if(sourceBytes%292 || from>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()))
        return false;
    in.clear();in.seekg(static_cast<std::streamoff>(from));
    if(!in)return false;
    unsigned char source[292],encoded[34];
    while(sourceBytes) {
        if(!in.read(reinterpret_cast<char*>(source),292))return false;
        const uint32_t bits=uint32_t(source[0])|(uint32_t(source[1])<<8)|
            (uint32_t(source[2])<<16)|(uint32_t(source[3])<<24);
        float scale=0;std::memcpy(&scale,&bits,4);
        if(!std::isfinite(scale))return false;
        // Q8_K uses one FP32 scale for 256 signed codes. If it fits
        // FP16 exactly, all eight Q8_0 blocks can reuse those codes
        // without any requantization or numerical reconstruction error.
        const uint16_t directHalf=Float32BitsToFloat16(bits);
        if(Float16ToFloat32Bits(directHalf)==bits) {
            encoded[0]=static_cast<unsigned char>(directHalf);
            encoded[1]=static_cast<unsigned char>(directHalf>>8);
            for(unsigned group=0;group<8;++group) {
                std::memcpy(encoded+2,source+4+group*32,32);
                if(!out.write(reinterpret_cast<const char*>(encoded),34))return false;
            }
            sourceBytes-=292;
            continue;
        }
        for(unsigned group=0;group<8;++group) {
            float values[32],maxAbs=0;
            for(unsigned i=0;i<32;++i) {
                values[i]=scale*static_cast<float>(
                    static_cast<int8_t>(source[4+group*32+i]));
                if(!std::isfinite(values[i]))return false;
                maxAbs=std::max(maxAbs,std::abs(values[i]));
            }
            const float d=maxAbs/127.0f;
            uint32_t dbits=0;std::memcpy(&dbits,&d,4);
            const uint16_t half=Float32BitsToFloat16(dbits);
            const uint32_t decoded=Float16ToFloat32Bits(half);
            float actual=0;std::memcpy(&actual,&decoded,4);
            if(maxAbs!=0 && (!std::isfinite(actual)||actual==0))return false;
            encoded[0]=static_cast<unsigned char>(half);
            encoded[1]=static_cast<unsigned char>(half>>8);
            for(unsigned i=0;i<32;++i) {
                const double normalized=actual==0?0.0:
                    static_cast<double>(values[i])/actual;
                const double q=std::round(normalized);
                const int value=static_cast<int>(std::max(-127.0,std::min(127.0,q)));
                encoded[2+i]=static_cast<unsigned char>(static_cast<int8_t>(value));
            }
            if(!out.write(reinterpret_cast<const char*>(encoded),34))return false;
        }
        sourceBytes-=292;
    }
    return true;
}
inline RepackError RepackGGUF(const std::string& input,
                             const std::string& output,
                             uint64_t max_output_bytes=UINT64_MAX,
                             bool convert_f32_to_f16=false,
                             bool convert_f32_to_q8_0=false,
                             bool convert_q8_0_to_q4_0=false,
                             bool convert_q6_k_to_q5_0=false,
                             bool auto_compress=false) {
    if(unsigned(convert_f32_to_f16)+unsigned(convert_f32_to_q8_0)+
       unsigned(convert_q8_0_to_q4_0)+unsigned(convert_q6_k_to_q5_0)+
        unsigned(auto_compress)>1)return RepackError::Unsupported;
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
           !StorageLayout(t.type,block,blockBytes)||t.dims[0]%block||
           !CheckedMultiply(count/block,blockBytes,t.bytes))
            return RepackError::Unsupported;
        t.source_bytes=t.bytes;
        // Auto mode uses FP16 for sensitive F32 tensors rather than aggressively
        // quantizing normalization, embeddings, or output projection weights.
        const bool sensitive=IsQualitySensitiveTensor(t.name);
        // All F32 vectors can shrink to F16, including singleton-row matrices.
        // Only ordinary multi-row matrices are candidates for Q4_0.
        const bool matrix = t.dims.size()>=2 && t.dims[1]>1;
        if((convert_f32_to_f16 || (auto_compress && (sensitive || !matrix || t.dims[0]%32!=0))) && t.type==0) {
            t.convert_f16=true;
            t.type=1; // GGML_TYPE_F16
            t.bytes/=2;
        }
        // Q8_K is already 292 bytes/256 weights; Q8_0 would be
        // 272 bytes/256. Never choose an expanding target format.
        // Preserve the original tensor when a requested conversion
        // does not strictly reduce its serialized payload.
        const uint64_t q8Bytes = (count/32)*34;
        // Q8_1 and Q8_K vectors have no eligible Q4_0 path, while
        // sensitive matrices must not be aggressively requantized.
        // Repack both to Q8_0 only when the serialized payload shrinks.
        // Ordinary multi-row matrices remain candidates for Q4_0.
        if(auto_compress && (sensitive || !matrix) &&
           (t.type==9 || t.type==15) && q8Bytes<t.bytes &&
           t.dims[0]%(t.type==15?256ULL:32ULL)==0) {
            t.convert_q8_0=true;
            t.q8_source_k=(t.type==15);
            t.q8_source_q8_1=(t.type==9);
            t.type=8;
            t.bytes=(count/32)*34;
        }
        if(convert_f32_to_q8_0 && !t.convert_f16 && !t.convert_q8_0 &&
           (t.type==0 || t.type==1 || t.type==9 || t.type==15) &&
           t.dims[0]%32==0 && q8Bytes<t.bytes) {
            t.convert_q8_0=true;
            t.q8_source_f16=(t.type==1);
            t.q8_source_k=(t.type==15);
            t.q8_source_q8_1=(t.type==9);
            t.type=8; // GGML_TYPE_Q8_0 (32 values per 34-byte block)
            t.bytes=(count/32)*34;
        }
        // Automatic requantization must not touch vector-like parameters,
        // nor expand a tensor that is already more compact than Q4_0.
        // A two-dimensional GGUF tensor with a singleton second axis is
        // still a vector; require at least two logical rows.
        const uint64_t q4Bytes = (count/32)*18;
        if((convert_q8_0_to_q4_0 || auto_compress) &&
           !t.convert_f16 && !t.convert_q8_0 && !sensitive &&
           (t.type==0 || t.type==1 || t.type==8 || t.type==9 ||
            t.type==6 || t.type==3 || t.type==7 || t.type==13 || t.type==14 || t.type==15) &&
            t.dims[0]%32==0 &&
            // K-quantized blocks are 256 values, not 32. Never dispatch
            // a K decoder on a row that is not a complete superblock.
            ((t.type!=13 && t.type!=14 && t.type!=15) || t.dims[0]%256==0) &&
            q4Bytes<t.bytes &&
            (!auto_compress || matrix)) {
            t.q4_source_type=t.type;
            t.convert_q4_0=true;
            t.type=2; // GGML_TYPE_Q4_0
            t.bytes=(count/32)*18;
        }
        // Never reinterpret a tensor after another conversion was planned.
        // Explicit Q6_K -> Q5_0 applies only to original Q6_K payloads.
        if(convert_q6_k_to_q5_0 && !t.convert_q4_0 && !t.convert_q8_0 &&
           !t.convert_f16 && t.type==14 && t.dims[0]%256==0) {
            t.convert_q5_0=true;
            t.type=6; // GGML_TYPE_Q5_0: 8 x 22-byte blocks per 256 weights
            t.bytes=(count/256)*176;
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
    // Auto mode promises a smaller artifact, not merely smaller selected
    // tensor payloads. Directory alignment can erase small savings.
    // Reject the plan before opening the destination if it cannot shrink.
    if(auto_compress && newData+cursor>=static_cast<uint64_t>(fileEnd))
        return RepackError::Unsupported;
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
            if(!(t.q4_source_type==15 ?
                 ConvertQ8KToQ4_0(in,out,dataStart+t.old_offset,t.source_bytes) :
                 t.q4_source_type==13 ?
                 ConvertQ5KToQ4_0(in,out,dataStart+t.old_offset,t.source_bytes) :
                 t.q4_source_type==14 ?
                 ConvertQ6KToQ4_0(in,out,dataStart+t.old_offset,t.source_bytes) :
                 ConvertToQ4_0(in,out,dataStart+t.old_offset,
                               t.source_bytes,t.q4_source_type)))
                return RepackError::Output;
        } else if(t.convert_q5_0) {
            if(!ConvertQ6KToQ5_0(in,out,dataStart+t.old_offset,t.source_bytes))
                return RepackError::Output;
        } else if(t.convert_q8_0) {
            if(!(t.q8_source_k ?
                 ConvertQ8KToQ8_0(in,out,dataStart+t.old_offset,t.source_bytes) :
                 t.q8_source_q8_1 ?
                 ConvertQ8_1ToQ8_0(in,out,dataStart+t.old_offset,t.source_bytes) :
                 ConvertFloatRangeToQ8_0(in,out,dataStart+t.old_offset,
                                          t.source_bytes,t.q8_source_f16)))
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
