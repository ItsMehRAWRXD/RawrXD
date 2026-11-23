// Native GGUF v2/v3 floating tensor rewriter: F16 and GGML Q8/Q5/Q4 formats.
// No dependencies; writes to a temporary file and only publishes on success.
// Build: c++ -std=c++17 -O2 tools/native_gguf_f16.cpp -o native_gguf_f16
#include "../src/deep2/NativeTensorCompression.hpp"
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <iostream>
#include <limits>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <filesystem>
using namespace RawrXD::TensorCompression;
namespace {
using U=uint64_t;
U read(std::istream& f,int n) {
    U x=0;
    for(int i=0;i<n;++i) {int c=f.get();if(c==EOF)throw std::runtime_error("truncated GGUF");x|=U(uint8_t(c))<<(i*8);}
    return x;
}
void write(std::ostream& f,U x,int n) {for(int i=0;i<n;++i)f.put(char(x>>(8*i)));}
U pos(std::istream& f) {auto p=f.tellg();if(p<0)throw std::runtime_error("invalid file position");return U(p);}
U add(U a,U b) {if(b>std::numeric_limits<U>::max()-a)throw std::runtime_error("size overflow");return a+b;}
U mul(U a,U b) {if(a && b>std::numeric_limits<U>::max()/a)throw std::runtime_error("size overflow");return a*b;}
U align(U x,U n) {return mul((add(x,n-1)/n),n);}
void seek(std::istream& f,U p) {if(p>U(std::numeric_limits<std::streamoff>::max()))throw std::runtime_error("offset overflow");f.seekg(std::streamoff(p));if(!f)throw std::runtime_error("seek failed");}
void copy(std::istream& in,std::ostream& out,U n) {
    char buf[65536];
    while(n) {size_t k=size_t(std::min<U>(n,sizeof(buf)));if(!in.read(buf,k))throw std::runtime_error("truncated payload");out.write(buf,k);if(!out)throw std::runtime_error("write failed");n-=k;}
}
std::string str(std::istream& f) {
    U n=read(f,8);if(n>1u<<20)throw std::runtime_error("GGUF string too long");
    std::string s(size_t(n),'\0');if(n && !f.read(&s[0],std::streamsize(n)))throw std::runtime_error("truncated string");return s;
}
void skip(std::istream& f,U n,U fileSize) {U end=add(pos(f),n);if(end>fileSize)throw std::runtime_error("metadata exceeds file");seek(f,end);}
void value(std::istream& f,uint32_t t,U fileSize,int depth=0) {
    if(depth>8)throw std::runtime_error("nested metadata too deep");
    switch(t) {
        case 0:case 1:case 7:skip(f,1,fileSize);break;
        case 2:case 3:skip(f,2,fileSize);break;
        case 4:case 5:case 6:skip(f,4,fileSize);break;
        case 8:(void)str(f);break;
        case 9: {
            uint32_t inner=uint32_t(read(f,4));U count=read(f,8);
            if(count>fileSize)throw std::runtime_error("metadata array too large");
            U unit=0;
            switch(inner) {case 0:case 1:case 7:unit=1;break;case 2:case 3:unit=2;break;case 4:case 5:case 6:unit=4;break;case 10:case 11:case 12:unit=8;break;default:break;}
            if(unit) skip(f,mul(count,unit),fileSize);
            else {if(inner!=8)throw std::runtime_error("unsupported array type");for(U i=0;i<count;++i)value(f,inner,fileSize,depth+1);}
            break;
        }
        case 10:case 11:case 12:skip(f,8,fileSize);break;
        default:throw std::runtime_error("unsupported GGUF metadata type");
    }
}
bool encodeQ8Block(const uint8_t* raw,uint32_t type,float tolerance,uint8_t out[34]) {
    float v[32],maxAbs=0;
    for(int j=0;j<32;++j) {
        if(type==0) {
            uint32_t bits=uint32_t(raw[4*j])|(uint32_t(raw[4*j+1])<<8)|
                          (uint32_t(raw[4*j+2])<<16)|(uint32_t(raw[4*j+3])<<24);
            v[j]=Float(bits);
        } else {
            uint16_t h=uint16_t(raw[2*j])|(uint16_t(raw[2*j+1])<<8);
            if(type==1)v[j]=FromHalf(h);
            else v[j]=Float(uint32_t(h)<<16);
        }
        if(!std::isfinite(v[j]))return false;
        maxAbs=std::max(maxAbs,std::fabs(v[j]));
    }
    uint16_t h=ToHalf(maxAbs/127.0f);
    float scale=FromHalf(h);
    if(!std::isfinite(scale) || (maxAbs && (scale==0 || maxAbs/scale>127.5f)))
        return false;
    out[0]=uint8_t(h);out[1]=uint8_t(h>>8);
    for(int j=0;j<32;++j) {
        float qf=scale?std::round(v[j]/scale):0;
        qf=std::max(-128.0f,std::min(127.0f,qf));
        int q=int(qf);
        if(!(std::fabs(scale*q-v[j])<=tolerance))return false;
        out[2+j]=uint8_t(int8_t(q));
    }
    return true;
}
bool encodeQ4Block(const uint8_t* raw,uint32_t type,float tolerance,uint8_t out[18]) {
    float v[32],extremum=0;
    for(int j=0;j<32;++j) {
        if(type==0) {
            uint32_t bits=uint32_t(raw[4*j])|(uint32_t(raw[4*j+1])<<8)|
                          (uint32_t(raw[4*j+2])<<16)|(uint32_t(raw[4*j+3])<<24);
            v[j]=Float(bits);
        } else {
            uint16_t h=uint16_t(raw[2*j])|(uint16_t(raw[2*j+1])<<8);
            v[j]=type==1?FromHalf(h):Float(uint32_t(h)<<16);
        }
        if(!std::isfinite(v[j]))return false;
        if(std::fabs(v[j])>std::fabs(extremum))extremum=v[j];
    }
    uint16_t h=ToHalf(extremum/-8.0f);
    float scale=FromHalf(h);
    if(!std::isfinite(scale)||(extremum && scale==0))return false;
    out[0]=uint8_t(h);out[1]=uint8_t(h>>8);
    for(int j=0;j<16;++j)out[2+j]=0;
    for(int j=0;j<32;++j) {
        float qf=scale?std::round(v[j]/scale):0;
        qf=std::max(-8.0f,std::min(7.0f,qf));
        int q=int(qf);
        if(!(std::fabs(scale*q-v[j])<=tolerance))return false;
        if(j<16)out[2+j]=uint8_t(q+8);
        else out[2+j-16]|=uint8_t((q+8)<<4);
    }
    return true;
}
bool encodeQ5Block(const uint8_t* raw,uint32_t type,float tolerance,uint8_t out[22]) {
    float v[32],extremum=0;
    for(int j=0;j<32;++j) {
        if(type==0) {
            uint32_t bits=uint32_t(raw[4*j])|(uint32_t(raw[4*j+1])<<8)|
                          (uint32_t(raw[4*j+2])<<16)|(uint32_t(raw[4*j+3])<<24);
            v[j]=Float(bits);
        } else {
            uint16_t h=uint16_t(raw[2*j])|(uint16_t(raw[2*j+1])<<8);
            v[j]=type==1?FromHalf(h):Float(uint32_t(h)<<16);
        }
        if(!std::isfinite(v[j]))return false;
        if(std::fabs(v[j])>std::fabs(extremum))extremum=v[j];
    }
    uint16_t h=ToHalf(extremum/-16.0f);
    float scale=FromHalf(h);
    if(!std::isfinite(scale)||(extremum && scale==0))return false;
    out[0]=uint8_t(h);out[1]=uint8_t(h>>8);
    for(int j=0;j<20;++j)out[2+j]=0;
    uint32_t highBits=0;
    for(int j=0;j<32;++j) {
        float qf=scale?std::round(v[j]/scale):0;
        qf=std::max(-16.0f,std::min(15.0f,qf));
        int q=int(qf);
        if(!(std::fabs(scale*q-v[j])<=tolerance))return false;
        unsigned code=unsigned(q+16);
        if(code&16u)highBits|=uint32_t(1)<<j;
        if(j<16)out[6+j]=uint8_t(code&15u);
        else out[6+j-16]|=uint8_t((code&15u)<<4);
    }
    for(int j=0;j<4;++j)out[2+j]=uint8_t(highBits>>(8*j));
    return true;
}
bool encodeQ41Block(const uint8_t* raw,uint32_t type,float tolerance,uint8_t out[20]) {
    float v[32],low=0,high=0;
    for(int j=0;j<32;++j) {
        if(type==0) {
            uint32_t bits=uint32_t(raw[4*j])|(uint32_t(raw[4*j+1])<<8)|
                          (uint32_t(raw[4*j+2])<<16)|(uint32_t(raw[4*j+3])<<24);
            v[j]=Float(bits);
        } else {
            uint16_t h=uint16_t(raw[2*j])|(uint16_t(raw[2*j+1])<<8);
            v[j]=type==1?FromHalf(h):Float(uint32_t(h)<<16);
        }
        if(!std::isfinite(v[j]))return false;
        if(!j)low=high=v[j];else {low=std::min(low,v[j]);high=std::max(high,v[j]);}
    }
    uint16_t hm=ToHalf(low),hd=ToHalf((high-low)/15.0f);
    float minimum=FromHalf(hm),scale=FromHalf(hd);
    if(!std::isfinite(minimum)||!std::isfinite(scale)||(high>low && scale<=0))return false;
    out[0]=uint8_t(hd);out[1]=uint8_t(hd>>8);
    out[2]=uint8_t(hm);out[3]=uint8_t(hm>>8);
    for(int j=0;j<16;++j)out[4+j]=0;
    for(int j=0;j<32;++j) {
        float qf=scale?std::round((v[j]-minimum)/scale):0;
        qf=std::max(0.0f,std::min(15.0f,qf));
        int q=int(qf);
        if(!(std::fabs(minimum+scale*q-v[j])<=tolerance))return false;
        if(j<16)out[4+j]=uint8_t(q);
        else out[4+j-16]|=uint8_t(q<<4);
    }
    return true;
}
bool encodeQ51Block(const uint8_t* raw,uint32_t type,float tolerance,uint8_t out[24]) {
    float v[32],low=0,high=0;
    for(int j=0;j<32;++j) {
        if(type==0) {
            uint32_t bits=uint32_t(raw[4*j])|(uint32_t(raw[4*j+1])<<8)|
                          (uint32_t(raw[4*j+2])<<16)|(uint32_t(raw[4*j+3])<<24);
            v[j]=Float(bits);
        } else {
            uint16_t h=uint16_t(raw[2*j])|(uint16_t(raw[2*j+1])<<8);
            v[j]=type==1?FromHalf(h):Float(uint32_t(h)<<16);
        }
        if(!std::isfinite(v[j]))return false;
        if(!j)low=high=v[j];else {low=std::min(low,v[j]);high=std::max(high,v[j]);}
    }
    uint16_t hm=ToHalf(low),hd=ToHalf((high-low)/31.0f);
    float minimum=FromHalf(hm),scale=FromHalf(hd);
    if(!std::isfinite(minimum)||!std::isfinite(scale)||(high>low && scale<=0))return false;
    out[0]=uint8_t(hd);out[1]=uint8_t(hd>>8);
    out[2]=uint8_t(hm);out[3]=uint8_t(hm>>8);
    for(int j=0;j<20;++j)out[4+j]=0;
    uint32_t highBits=0;
    for(int j=0;j<32;++j) {
        float qf=scale?std::round((v[j]-minimum)/scale):0;
        qf=std::max(0.0f,std::min(31.0f,qf));
        int q=int(qf);
        if(!(std::fabs(minimum+scale*q-v[j])<=tolerance))return false;
        if(q&16)highBits|=uint32_t(1)<<j;
        if(j<16)out[8+j]=uint8_t(q&15);
        else out[8+j-16]|=uint8_t((q&15)<<4);
    }
    for(int j=0;j<4;++j)out[4+j]=uint8_t(highBits>>(8*j));
    return true;
}
struct Tensor {std::string name;std::vector<U> dims;uint32_t type;U offset;U bytes;U newOffset;bool convert;};
}
int main(int argc,char** argv) {
    if(argc!=4 && argc!=5) {std::cerr<<"usage: native_gguf_f16 INPUT.gguf OUTPUT.gguf MAX_ABS_ERROR [auto|q2_k|f32|f16|bf16|q8_k|q8_0|q5_1|q5_0|q4_1|q4_0]\n";return 2;}
    if(std::string(argv[1])==argv[2]) {std::cerr<<"input and output must differ\n";return 2;}
    std::string tmp=std::string(argv[2])+".partial";
    bool ownsTemporary=false;
    try {
        // String inequality is insufficient: aliases and symlinks can name
        // the same inode. Never truncate or replace the input model.
        namespace fs=std::filesystem;
        const fs::path inputPath(argv[1]), outputPath(argv[2]), partialPath(tmp);
        if(fs::exists(inputPath) && fs::exists(outputPath) &&
           fs::equivalent(inputPath,outputPath))
            throw std::runtime_error("input and output refer to the same file");
        if(fs::exists(partialPath) && fs::equivalent(inputPath,partialPath))
            throw std::runtime_error("temporary output refers to the input file");
        const bool f32=argc==5 && std::string(argv[4])=="f32";
        const bool automatic=argc==5 && std::string(argv[4])=="auto";
        const bool bf16=argc==5 && std::string(argv[4])=="bf16";
        const bool q2k=argc==5 && std::string(argv[4])=="q2_k";
        const bool q8k=argc==5 && std::string(argv[4])=="q8_k";
        const bool q8=argc==5 && std::string(argv[4])=="q8_0";
        const bool q4=argc==5 && std::string(argv[4])=="q4_0";
        const bool q5=argc==5 && std::string(argv[4])=="q5_0";
        const bool q41=argc==5 && std::string(argv[4])=="q4_1";
        const bool q51=argc==5 && std::string(argv[4])=="q5_1";
        if(argc==5 && !q8 && !q4 && !q5 && !q41 && !q51 && !bf16 && !automatic && !f32 && std::string(argv[4])!="f16")throw std::runtime_error("unknown encoding");
        // A quantized GGUF tensor's innermost dimension must be divisible
        // by the 32-element block size. No flattened cross-row packing.
        const bool quantized=q8||q4||q5||q41||q51;
        // Require the complete argument to be a finite nonnegative number.
        // std::stof alone accepts trailing garbage (e.g. "0.1oops").
        const std::string toleranceArg(argv[3]);
        size_t toleranceEnd=0;
        float tolerance=std::stof(toleranceArg,&toleranceEnd);
        if(toleranceEnd!=toleranceArg.size() || !std::isfinite(tolerance) || tolerance<0)
            throw std::runtime_error("invalid tolerance");
        std::ifstream in(argv[1],std::ios::binary|std::ios::ate);
        if(!in)throw std::runtime_error("cannot open input");
        U fileSize=pos(in);seek(in,0);
        if(read(in,4)!=0x46554747u)throw std::runtime_error("not GGUF");
        U version=read(in,4);if(version!=2 && version!=3)throw std::runtime_error("requires GGUF v2/v3");
        U count=read(in,8), kv=read(in,8);
        if(count>1000000 || kv>1000000)throw std::runtime_error("unreasonable table counts");
        U alignment=32;
        for(U i=0;i<kv;++i) {
            std::string key=str(in);uint32_t type=uint32_t(read(in,4));
            if(key=="general.alignment") {
                if(type!=4)throw std::runtime_error("invalid alignment metadata type");
                alignment=read(in,4);
                if(alignment<1 || alignment>4096 || (alignment&(alignment-1)))throw std::runtime_error("invalid alignment");
            } else value(in,type,fileSize);
        }
        U kvEnd=pos(in);
        std::vector<Tensor> ts;ts.reserve(size_t(count));
        for(U i=0;i<count;++i) {
            Tensor t;t.name=str(in);U nd=read(in,4);if(!nd || nd>4)throw std::runtime_error("invalid tensor rank");
            U elements=1;
            for(U d=0;d<nd;++d) {U dim=read(in,8);if(!dim)throw std::runtime_error("zero dimension");t.dims.push_back(dim);elements=mul(elements,dim);}
            t.type=uint32_t(read(in,4));t.offset=read(in,8);
            t.convert=((t.type==0 || t.type==1 || t.type==30 || t.type==28) && elements<=std::numeric_limits<size_t>::max()/8);
            t.bytes=t.type==28?mul(elements,8):(t.type==0?mul(elements,4):((t.type==1 || t.type==30)?mul(elements,2):0));
            ts.push_back(std::move(t));
        }
        U dataStart=align(pos(in),alignment);
        if(dataStart>fileSize)throw std::runtime_error("missing tensor data");
        std::vector<size_t> order(ts.size());
        for(size_t i=0;i<order.size();++i)order[i]=i;
        std::sort(order.begin(),order.end(),[&](size_t a,size_t b){return ts[a].offset<ts[b].offset;});
        for(size_t j=0;j<order.size();++j) {
            auto& t=ts[order[j]];
            U next=j+1<order.size()?ts[order[j+1]].offset:fileSize-dataStart;
            if(t.offset>next || add(dataStart,next)>fileSize)throw std::runtime_error("invalid tensor offsets");
            if(j && (ts[order[j-1]].type==0 || ts[order[j-1]].type==28) && ts[order[j-1]].bytes>t.offset-ts[order[j-1]].offset)
                throw std::runtime_error("overlapping F32 tensor payloads");
            if(j && (ts[order[j-1]].type==1 || ts[order[j-1]].type==30) && ts[order[j-1]].bytes>t.offset-ts[order[j-1]].offset)
                throw std::runtime_error("overlapping 16-bit tensor payloads");
            if(t.offset%alignment)throw std::runtime_error("unaligned tensor offset");
            if(t.type==0 || t.type==1 || t.type==30 || t.type==28) {
                U expected=1;
                for(U d:t.dims)expected=mul(expected,d);
                expected=mul(expected,t.type==28?8:(t.type==0?4:2));
                if(t.bytes!=expected)throw std::runtime_error("invalid floating tensor length");
            }
            if(j && t.offset==ts[order[j-1]].offset)throw std::runtime_error("overlapping tensor offsets");
            U span=next-t.offset;
            if(t.bytes && t.bytes>span)throw std::runtime_error("tensor exceeds span");
            if(!t.bytes)t.bytes=span; // Unknown quantized type: preserve complete storage span
            
            // Floating tensor payload sizes are checked before streaming conversion.
        }
        // GGUF tensor descriptors are required to have unique names.
        // Duplicate names make tensor lookup ambiguous in native runtimes;
        // reject malformed input before producing a rewritten artifact.
        {
            std::vector<std::string> names;
            names.reserve(ts.size());
            for(const auto& tensor:ts)names.push_back(tensor.name);
            std::sort(names.begin(),names.end());
            if(std::adjacent_find(names.begin(),names.end())!=names.end())
                throw std::runtime_error("duplicate GGUF tensor name");
        }
        // Never replace an existing destination: a model conversion must not
        // silently destroy an earlier artifact. This is a preflight check,
        // not a cross-process atomic no-clobber guarantee.
        std::error_code destError;
        const auto destStatus=std::filesystem::symlink_status(argv[2],destError);
        if(destError && destError!=std::errc::no_such_file_or_directory)
            throw std::runtime_error("cannot inspect destination");
        if(destStatus.type()!=std::filesystem::file_type::not_found)
            throw std::runtime_error("destination already exists");
        // Never overwrite an unrelated or interrupted conversion's staging file.
        // This preflight protects existing files but is not atomic against races.
        // exists() follows symlinks and misses dangling links. Refuse every
        // existing directory entry, including dangling symlinks, before opening
        // a truncating stream through the staging pathname.
        std::error_code stageError;
        const auto stageStatus=std::filesystem::symlink_status(tmp,stageError);
        if(stageError && stageError!=std::errc::no_such_file_or_directory)
            throw std::runtime_error("cannot inspect temporary output");
        if(stageStatus.type()!=std::filesystem::file_type::not_found)
            throw std::runtime_error("temporary output already exists; remove it manually after inspection");
        std::ofstream out(tmp,std::ios::binary|std::ios::trunc);
        ownsTemporary=true;
        if(!out)throw std::runtime_error("cannot create output");
        seek(in,0);copy(in,out,kvEnd); // preserve original header and all metadata bytes
        // Preflight candidate tensors before writing the tensor descriptor table.
        std::vector<std::vector<uint8_t>> converted(ts.size());
        std::vector<uint32_t> outputTypes(ts.size());
        for(size_t i=0;i<ts.size();++i)outputTypes[i]=ts[i].type;
        U changed=0;
        std::vector<bool> streamF64toQ41(ts.size(),false);
        std::vector<bool> streamF64toQ51(ts.size(),false);
        std::vector<bool> streamF64toQ4(ts.size(),false);
        std::vector<bool> streamF64toQ5(ts.size(),false);
        std::vector<bool> streamF64toQ2K(ts.size(),false);
        std::vector<bool> streamF64toQ8K(ts.size(),false);
        std::vector<bool> streamF64toQ8(ts.size(),false);
        std::vector<bool> streamF64toBf16(ts.size(),false);
        std::vector<bool> streamF64toF16(ts.size(),false);
        std::vector<bool> streamF64toF32(ts.size(),false);
        std::vector<bool> streamHalf(ts.size(),false);
        std::vector<bool> streamBf16(ts.size(),false);
        std::vector<bool> streamQ8(ts.size(),false);
        std::vector<bool> streamQ4(ts.size(),false);
        std::vector<bool> streamQ5(ts.size(),false);
        std::vector<bool> streamQ41(ts.size(),false);
        std::vector<bool> streamQ51(ts.size(),false);
        for(size_t i=0;i<ts.size();++i) {
            auto& t=ts[i];if(!t.convert || (t.type!=0 && !((automatic || f32 || bf16 || (argc==5 && std::string(argv[4])=="f16")) && t.type==28) && !q2k && !q8k && !q8 && !q4 && !q5 && !q41 && !q51 && !automatic))continue;
            if(t.type==28 && (automatic || q41 || q51) &&
               t.dims[0]%32==0 && t.bytes%256==0) {
                for(int candidate=0;candidate<2;++candidate) {
                    if((q41 && candidate!=0)||(q51 && candidate!=1))continue;
                    seek(in,add(dataStart,t.offset));
                    bool valid=true;
                    uint8_t raw[256],narrow[128],encoded[24];
                    for(U off=0;off<t.bytes;off+=256) {
                        if(!in.read(reinterpret_cast<char*>(raw),256))
                            throw std::runtime_error("truncated F64 affine preflight");
                        double original[32];
                        for(int j=0;j<32;++j) {
                            uint64_t bits=0;
                            for(int k=0;k<8;++k)bits|=uint64_t(raw[8*j+k])<<(8*k);
                            std::memcpy(&original[j],&bits,8);
                            const float f=static_cast<float>(original[j]);
                            if(!std::isfinite(original[j])||!std::isfinite(f)){
                                valid=false;break;
                            }
                            uint32_t word;
                            std::memcpy(&word,&f,4);
                            for(int k=0;k<4;++k)narrow[4*j+k]=uint8_t(word>>(8*k));
                        }
                        if(!valid)break;
                        const bool ok=candidate==0
                            ?encodeQ41Block(narrow,0,tolerance,encoded)
                            :encodeQ51Block(narrow,0,tolerance,encoded);
                        if(!ok){valid=false;break;}
                        const float scale=FromHalf(uint16_t(encoded[0])|
                                                  (uint16_t(encoded[1])<<8));
                        const float minimum=FromHalf(uint16_t(encoded[2])|
                                                    (uint16_t(encoded[3])<<8));
                        uint32_t high=0;
                        if(candidate==1)
                            for(int k=0;k<4;++k)high|=uint32_t(encoded[4+k])<<(8*k);
                        for(int j=0;j<32;++j) {
                            const uint8_t packed=encoded[(candidate==0?4:8)+(j%16)];
                            const int nibble=j<16?packed&15:packed>>4;
                            const int q=candidate==0?nibble:
                                (nibble|int((high>>j&1u)<<4));
                            const double restored=double(minimum)+double(scale)*q;
                            if(!(std::fabs(restored-original[j])<=double(tolerance))){
                                valid=false;break;
                            }
                        }
                        if(!valid)break;
                    }
                    if(valid){
                        if(candidate==0){streamF64toQ41[i]=true;outputTypes[i]=3;}
                        else {streamF64toQ51[i]=true;outputTypes[i]=7;}
                        ++changed;break;
                    }
                }
                if(streamF64toQ41[i]||streamF64toQ51[i])continue;
                if(q41||q51)continue;
            }
            if(t.type==28 && (automatic || q4 || q5) &&
               t.dims[0]%32==0 && t.bytes%256==0) {
                // Native GGML Q4_0 / Q5_0 blocks: preflight against F64
                // source values, not only intermediate F32 approximations.
                for(int candidate=0;candidate<2;++candidate) {
                    if((q4 && candidate!=0)||(q5 && candidate!=1))continue;
                    seek(in,add(dataStart,t.offset));
                    bool valid=true;
                    uint8_t raw[256],narrow[128],encoded[22];
                    for(U off=0;off<t.bytes;off+=256) {
                        if(!in.read(reinterpret_cast<char*>(raw),256))
                            throw std::runtime_error("truncated F64 quantization preflight");
                        double original[32];
                        for(int j=0;j<32;++j) {
                            uint64_t bits=0;
                            for(int k=0;k<8;++k)bits|=uint64_t(raw[8*j+k])<<(8*k);
                            std::memcpy(&original[j],&bits,8);
                            const float f=static_cast<float>(original[j]);
                            if(!std::isfinite(original[j])||!std::isfinite(f)){
                                valid=false;break;
                            }
                            uint32_t word;
                            std::memcpy(&word,&f,4);
                            for(int k=0;k<4;++k)narrow[4*j+k]=uint8_t(word>>(8*k));
                        }
                        if(!valid)break;
                        const bool ok=candidate==0
                            ?encodeQ4Block(narrow,0,tolerance,encoded)
                            :encodeQ5Block(narrow,0,tolerance,encoded);
                        if(!ok){valid=false;break;}
                        const float scale=FromHalf(uint16_t(encoded[0])|
                                                  (uint16_t(encoded[1])<<8));
                        uint32_t high=0;
                        if(candidate==1)
                            for(int k=0;k<4;++k)high|=uint32_t(encoded[2+k])<<(8*k);
                        for(int j=0;j<32;++j) {
                            const uint8_t packed=encoded[(candidate==0?2:6)+(j%16)];
                            const int nibble=(j<16?packed&15:packed>>4);
                            const int q=candidate==0?nibble-8:
                                (nibble|int((high>>j&1u)<<4))-16;
                            if(!(std::fabs(double(scale)*q-original[j])<=double(tolerance))){
                                valid=false;break;
                            }
                        }
                        if(!valid)break;
                    }
                    if(valid) {
                        if(candidate==0){streamF64toQ4[i]=true;outputTypes[i]=2;}
                        else {streamF64toQ5[i]=true;outputTypes[i]=6;}
                        ++changed;break;
                    }
                }
                if(streamF64toQ4[i]||streamF64toQ5[i])continue;
                if(q4||q5)continue;
            }
            if(t.type==28 && q2k && t.dims[0]%256==0 &&
               t.bytes%2048==0) {
                // GGML block_q2_K layout: scales[16], qs[64], fp16 d,dmin.
                // Conservative independent per-16 affine fit; validate with
                // the canonical GGML dequantization traversal.
                seek(in,add(dataStart,t.offset));
                bool valid=true;
                uint8_t raw[2048],encoded[84];
                for(U off=0;off<t.bytes;off+=2048) {
                    if(!in.read(reinterpret_cast<char*>(raw),2048))
                        throw std::runtime_error("truncated F64 Q2_K preflight");
                    double v[256],lo[16],hi[16],sc[16],mn[16];
                    double maxSc=0,maxMn=0;
                    for(int j=0;j<256;++j) {
                        uint64_t bits=0;for(int k=0;k<8;++k)bits|=uint64_t(raw[8*j+k])<<(8*k);
                        std::memcpy(&v[j],&bits,8);
                        if(!std::isfinite(v[j])){valid=false;break;}
                    }
                    if(!valid)break;
                    for(int g=0;g<16;++g) {
                        lo[g]=hi[g]=v[g*16];
                        for(int j=1;j<16;++j){lo[g]=std::min(lo[g],v[g*16+j]);hi[g]=std::max(hi[g],v[g*16+j]);}
                        sc[g]=(hi[g]-lo[g])/3.0;mn[g]=std::max(0.0,-lo[g]);
                        maxSc=std::max(maxSc,sc[g]);maxMn=std::max(maxMn,mn[g]);
                    }
                    const uint16_t hd=ToHalf(float(maxSc/15.0)),hm=ToHalf(float(maxMn/15.0));
                    const double d=FromHalf(hd),dm=FromHalf(hm);
                    encoded[80]=uint8_t(hd);encoded[81]=uint8_t(hd>>8);
                    encoded[82]=uint8_t(hm);encoded[83]=uint8_t(hm>>8);
                    std::memset(encoded,0,80);
                    uint8_t qs[64]={};
                    for(int g=0;g<16;++g) {
                        int ls=d?int(std::round(sc[g]/(d*15.0))):0;
                        int lm=dm?int(std::round(mn[g]/(dm*15.0))):0;
                        ls=std::max(0,std::min(15,ls));lm=std::max(0,std::min(15,lm));
                        encoded[g]=uint8_t(ls|(lm<<4));
                        const double ds=d*ls,ms=dm*lm;
                        for(int j=0;j<16;++j) {
                            const int q=ds?std::max(0,std::min(3,int(std::round((v[g*16+j]+ms)/ds)))):0;
                            const double restored=ds*q-ms;
                            if(!(std::fabs(restored-v[g*16+j])<=double(tolerance))){valid=false;break;}
                            const int chunk=g/8,within=g%8,half=within/2,shift=(within%2)*2;
                            const int qi=chunk*32+(within/2)*16+j;
                            qs[qi]|=uint8_t(q<<shift);
                        }
                        if(!valid)break;
                    }
                    if(!valid)break;
                    std::memcpy(encoded+16,qs,64);
                }
                if(valid){streamF64toQ2K[i]=true;outputTypes[i]=10;++changed;continue;}
                continue;
            }
            if(t.type==28 && q8k && t.dims[0]%256==0 &&
               t.bytes%2048==0) {
                // GGML block_q8_K: float d, 256 signed quants, 16 int16
                // subgroup sums. Validate reconstruction against original F64.
                seek(in,add(dataStart,t.offset));
                bool valid=true;
                uint8_t raw[2048],encoded[292];
                for(U off=0;off<t.bytes;off+=2048) {
                    if(!in.read(reinterpret_cast<char*>(raw),2048))
                        throw std::runtime_error("truncated F64 Q8_K preflight");
                    double values[256],maxAbs=0;
                    for(int j=0;j<256;++j) {
                        uint64_t bits=0;
                        for(int k=0;k<8;++k)bits|=uint64_t(raw[8*j+k])<<(8*k);
                        std::memcpy(&values[j],&bits,8);
                        if(!std::isfinite(values[j])){valid=false;break;}
                        maxAbs=std::max(maxAbs,std::fabs(values[j]));
                    }
                    if(!valid)break;
                    const float d=float(maxAbs/127.0);
                    if(!std::isfinite(d)){valid=false;break;}
                    std::memcpy(encoded,&d,4);
                    int16_t sums[16]={};
                    for(int j=0;j<256;++j) {
                        const int q=d?int(std::max(-127.0,std::min(127.0,
                            std::round(values[j]/double(d))))):0;
                        const int8_t qi=int8_t(q);
                        encoded[4+j]=uint8_t(qi);
                        sums[j/16]=int16_t(sums[j/16]+q);
                        if(!(std::fabs(double(d)*q-values[j])<=double(tolerance))) {
                            valid=false;break;
                        }
                    }
                    for(int j=0;j<16;++j)
                        std::memcpy(encoded+260+2*j,&sums[j],2);
                    if(!valid)break;
                }
                if(valid){streamF64toQ8K[i]=true;outputTypes[i]=15;++changed;continue;}
                continue;
            }
            if(t.type==28 && (automatic || q8) && t.dims[0]%32==0 &&
               t.bytes%256==0) {
                seek(in,add(dataStart,t.offset));
                bool valid=true;
                uint8_t raw[256],narrow[128],encoded[34];
                for(U off=0;off<t.bytes;off+=256) {
                    if(!in.read(reinterpret_cast<char*>(raw),256))
                        throw std::runtime_error("truncated F64 Q8 preflight");
                    double original[32];
                    for(int j=0;j<32;++j) {
                        uint64_t bits=0;
                        for(int k=0;k<8;++k)bits|=uint64_t(raw[8*j+k])<<(8*k);
                        std::memcpy(&original[j],&bits,8);
                        const float f=static_cast<float>(original[j]);
                        if(!std::isfinite(original[j]) || !std::isfinite(f)) {
                            valid=false;break;
                        }
                        uint32_t word;
                        std::memcpy(&word,&f,4);
                        for(int k=0;k<4;++k)narrow[4*j+k]=uint8_t(word>>(8*k));
                    }
                    if(!valid || !encodeQ8Block(narrow,0,tolerance,encoded)){
                        valid=false;break;
                    }
                    const float scale=FromHalf(uint16_t(encoded[0])|
                                               (uint16_t(encoded[1])<<8));
                    for(int j=0;j<32;++j) {
                        const double restored=double(scale)*int8_t(encoded[2+j]);
                        if(!(std::fabs(restored-original[j])<=double(tolerance))) {
                            valid=false;break;
                        }
                    }
                    if(!valid)break;
                }
                if(valid){streamF64toQ8[i]=true;outputTypes[i]=8;++changed;continue;}
                if(q8)continue;
            }
            if((automatic || f32 || bf16 || (argc==5 && std::string(argv[4])=="f16")) && t.type==28) {
                // GGML F64 (type 28) to F32: 50% storage reduction only
                // when every finite double survives the precision budget.
                seek(in,add(dataStart,t.offset));
                bool valid=true;
                bool halfValid=automatic || (argc==5 && std::string(argv[4])=="f16");
                bool bf16Valid=automatic || bf16;
                uint8_t block[65536];
                for(U off=0;off<t.bytes && valid;) {
                    const size_t n=size_t(std::min<U>(t.bytes-off,sizeof(block)));
                    if(!in.read(reinterpret_cast<char*>(block),std::streamsize(n)))
                        throw std::runtime_error("truncated F64 preflight");
                    for(size_t j=0;j<n;j+=8) {
                        uint64_t bits=0;
                        for(int k=0;k<8;++k)bits|=uint64_t(block[j+k])<<(8*k);
                        double original;
                        std::memcpy(&original,&bits,8);
                        const float narrowed=static_cast<float>(original);
                        if(halfValid) {
                            const float half=FromHalf(ToHalf(narrowed));
                            if(!std::isfinite(half) ||
                               !(std::fabs(double(half)-original)<=double(tolerance)))
                                halfValid=false;
                        }
                        if(bf16Valid) {
                            uint32_t word;
                            std::memcpy(&word,&narrowed,4);
                            const uint32_t rounded=word+0x7fffu+((word>>16)&1u);
                            const float restored=Float(rounded&0xffff0000u);
                            if(!std::isfinite(restored) ||
                               !(std::fabs(double(restored)-original)<=double(tolerance)))
                                bf16Valid=false;
                        }
                        if(!std::isfinite(original)||!std::isfinite(narrowed)||
                           !(std::fabs(double(narrowed)-original)<=double(tolerance))) {
                            valid=false;break;
                        }
                    }
                    off+=n;
                }
                if(valid && halfValid && !bf16){streamF64toF16[i]=true;outputTypes[i]=1;++changed;}
                else if(valid && bf16Valid && !f32){streamF64toBf16[i]=true;outputTypes[i]=30;++changed;}
                else if(valid && (automatic || f32)){streamF64toF32[i]=true;outputTypes[i]=0;++changed;}
                continue;
            }
            if(f32)continue;
            if(automatic && t.dims[0]>=32 && t.dims[0]%32==0 &&
               (t.type==0 || t.type==1 || t.type==30)) {
                const size_t inputBlock=t.type==0?128:64;
                if(t.bytes%inputBlock==0) {
                    // Select the smallest existing GGML block encoding whose
                    // decoded values meet the requested maximum absolute error.
                    // The whole tensor must pass; never mix formats within it.
                    for(int candidate=0;candidate<5;++candidate) {
                        seek(in,add(dataStart,t.offset));
                        bool valid=true;
                        uint8_t block[128],encoded[34];
                        for(U off=0;off<t.bytes;off+=inputBlock) {
                            if(!in.read(reinterpret_cast<char*>(block),std::streamsize(inputBlock)))
                                throw std::runtime_error("truncated auto quantization preflight");
                            bool ok=false;
                            switch(candidate) {
                                case 0: ok=encodeQ4Block(block,t.type,tolerance,encoded);break;
                                case 1: ok=encodeQ41Block(block,t.type,tolerance,encoded);break;
                                case 2: ok=encodeQ5Block(block,t.type,tolerance,encoded);break;
                                case 3: ok=encodeQ51Block(block,t.type,tolerance,encoded);break;
                                case 4: ok=encodeQ8Block(block,t.type,tolerance,encoded);break;
                            }
                            if(!ok){valid=false;break;}
                        }
                        if(valid) {
                            static constexpr uint32_t types[]={2,3,6,7,8};
                            outputTypes[i]=types[candidate];
                            switch(candidate) {
                                case 0: streamQ4[i]=true;break;
                                case 1: streamQ41[i]=true;break;
                                case 2: streamQ5[i]=true;break;
                                case 3: streamQ51[i]=true;break;
                                case 4: streamQ8[i]=true;break;
                            }
                            ++changed;
                            break;
                        }
                    }
                    if(outputTypes[i]!=t.type)continue;
                }
                // F32 falls through to the existing F16 precision-gated
                // streaming path; F16/BF16 remain unchanged if no quant fits.
                if(t.type!=0)continue;
            }
            if(q8 && t.dims[0]%32==0 && (t.type==0 || t.type==1 || t.type==30)) {
                const size_t inputBlock=t.type==0?128:64;
                if(t.bytes%inputBlock)continue;
                seek(in,add(dataStart,t.offset));
                uint8_t block[128],encoded[34];
                bool valid=true;
                for(U off=0;off<t.bytes;off+=inputBlock) {
                    if(!in.read(reinterpret_cast<char*>(block),std::streamsize(inputBlock)))
                        throw std::runtime_error("truncated Q8 streaming preflight");
                    if(!encodeQ8Block(block,t.type,tolerance,encoded)){valid=false;break;}
                }
                if(valid){streamQ8[i]=true;outputTypes[i]=8;++changed;}
                continue;
            }
            if(q4 && t.dims[0]%32==0 && (t.type==0 || t.type==1 || t.type==30)) {
                const size_t inputBlock=t.type==0?128:64;
                if(t.bytes%inputBlock)continue;
                seek(in,add(dataStart,t.offset));
                uint8_t block[128],encoded[18];
                bool valid=true;
                for(U off=0;off<t.bytes;off+=inputBlock) {
                    if(!in.read(reinterpret_cast<char*>(block),std::streamsize(inputBlock)))
                        throw std::runtime_error("truncated Q4 streaming preflight");
                    if(!encodeQ4Block(block,t.type,tolerance,encoded)){valid=false;break;}
                }
                if(valid){streamQ4[i]=true;outputTypes[i]=2;++changed;}
                continue;
            }
            if(q41 && t.dims[0]%32==0 && (t.type==0 || t.type==1 || t.type==30)) {
                const size_t inputBlock=t.type==0?128:64;
                if(t.bytes%inputBlock)continue;
                seek(in,add(dataStart,t.offset));
                uint8_t block[128],encoded[20];
                bool valid=true;
                for(U off=0;off<t.bytes;off+=inputBlock) {
                    if(!in.read(reinterpret_cast<char*>(block),std::streamsize(inputBlock)))
                        throw std::runtime_error("truncated Q4 streaming preflight");
                    if(!encodeQ41Block(block,t.type,tolerance,encoded)){valid=false;break;}
                }
                if(valid){streamQ41[i]=true;outputTypes[i]=3;++changed;}
                continue;
            }
            if(q51 && t.dims[0]%32==0 && (t.type==0 || t.type==1 || t.type==30)) {
                const size_t inputBlock=t.type==0?128:64;
                if(t.bytes%inputBlock)continue;
                seek(in,add(dataStart,t.offset));
                uint8_t block[128],encoded[24];
                bool valid=true;
                for(U off=0;off<t.bytes;off+=inputBlock) {
                    if(!in.read(reinterpret_cast<char*>(block),std::streamsize(inputBlock)))
                        throw std::runtime_error("truncated Q4 streaming preflight");
                    if(!encodeQ51Block(block,t.type,tolerance,encoded)){valid=false;break;}
                }
                if(valid){streamQ51[i]=true;outputTypes[i]=7;++changed;}
                continue;
            }
            if(q5 && t.dims[0]%32==0 && (t.type==0 || t.type==1 || t.type==30)) {
                const size_t inputBlock=t.type==0?128:64;
                if(t.bytes%inputBlock)continue;
                seek(in,add(dataStart,t.offset));
                uint8_t block[128],encoded[22];
                bool valid=true;
                for(U off=0;off<t.bytes;off+=inputBlock) {
                    if(!in.read(reinterpret_cast<char*>(block),std::streamsize(inputBlock)))
                        throw std::runtime_error("truncated Q5 streaming preflight");
                    if(!encodeQ5Block(block,t.type,tolerance,encoded)){valid=false;break;}
                }
                if(valid){streamQ5[i]=true;outputTypes[i]=6;++changed;}
                continue;
            }
            if(bf16 && t.type==0) {
                seek(in,add(dataStart,t.offset));
                bool valid=true;
                std::vector<uint8_t> chunk(65536);
                for(U off=0;off<t.bytes && valid;) {
                    size_t n=size_t(std::min<U>(t.bytes-off,chunk.size()));
                    if(!in.read(reinterpret_cast<char*>(chunk.data()),std::streamsize(n)))
                        throw std::runtime_error("truncated BF16 preflight");
                    for(size_t j=0;j<n;j+=4) {
                        uint32_t bits=uint32_t(chunk[j])|(uint32_t(chunk[j+1])<<8)|
                                      (uint32_t(chunk[j+2])<<16)|(uint32_t(chunk[j+3])<<24);
                        float original=Float(bits);
                        // Round to nearest even, retaining BF16 sign and exponent.
                        uint32_t rounded=bits+0x7fffu+((bits>>16)&1u);
                        float decoded=Float(rounded&0xffff0000u);
                        if(!std::isfinite(original)||!std::isfinite(decoded)||
                           !(std::fabs(decoded-original)<=tolerance)){valid=false;break;}
                    }
                    off+=n;
                }
                if(valid){streamBf16[i]=true;outputTypes[i]=30;++changed;}
                continue;
            }
            if(t.type==0 && !quantized) {
                // First pass: validate every F32 weight before changing its type.
                // The second pass emits the same half values using fixed memory.
                seek(in,add(dataStart,t.offset));
                bool valid=true;
                std::vector<uint8_t> chunk(65536);
                for(U off=0;off<t.bytes && valid;) {
                    size_t n=size_t(std::min<U>(t.bytes-off,chunk.size()));
                    if(!in.read(reinterpret_cast<char*>(chunk.data()),std::streamsize(n)))
                        throw std::runtime_error("truncated F32 streaming preflight");
                    for(size_t j=0;j<n;j+=4) {
                        uint32_t bits=uint32_t(chunk[j])|(uint32_t(chunk[j+1])<<8)|
                                      (uint32_t(chunk[j+2])<<16)|(uint32_t(chunk[j+3])<<24);
                        float value=Float(bits);
                        if(!std::isfinite(value)){valid=false;break;}
                        float reconstructed=FromHalf(ToHalf(value));
                        if(!std::isfinite(reconstructed) ||
                           !(std::fabs(reconstructed-value)<=tolerance)){valid=false;break;}
                    }
                    off+=n;
                }
                if(valid){streamHalf[i]=true;outputTypes[i]=1;++changed;continue;}
                if(automatic) {
                    // F16 may overflow while BF16 remains representable.
                    // Both occupy two bytes per F32 value. Prefer F16 when
                    // valid; use BF16 only when its full-tensor error passes.
                    seek(in,add(dataStart,t.offset));
                    bool bfValid=true;
                    for(U off=0;off<t.bytes && bfValid;) {
                        size_t n=size_t(std::min<U>(t.bytes-off,chunk.size()));
                        if(!in.read(reinterpret_cast<char*>(chunk.data()),std::streamsize(n)))
                            throw std::runtime_error("truncated auto BF16 preflight");
                        for(size_t j=0;j<n;j+=4) {
                            uint32_t bits=uint32_t(chunk[j])|(uint32_t(chunk[j+1])<<8)|
                                          (uint32_t(chunk[j+2])<<16)|(uint32_t(chunk[j+3])<<24);
                            float original=Float(bits);
                            uint32_t rounded=bits+0x7fffu+((bits>>16)&1u);
                            float decoded=Float(rounded&0xffff0000u);
                            if(!std::isfinite(original)||!std::isfinite(decoded)||
                               !(std::fabs(decoded-original)<=tolerance)){bfValid=false;break;}
                        }
                        off+=n;
                    }
                    if(bfValid){streamBf16[i]=true;outputTypes[i]=30;++changed;}
                }
                continue;
            }
            // The legacy in-memory fallback below consumes F32 words only.
            // Never reinterpret F64, F16 or BF16 source bytes as F32, even
            // when a requested target format has no applicable streaming path.
            if(t.type!=0)continue;
            if(t.bytes>64u*1024u*1024u)continue; // Defensive cap for any remaining non-streamed format
            std::vector<uint8_t> raw(static_cast<size_t>(t.bytes));
            seek(in,add(dataStart,t.offset));
            if(!in.read(reinterpret_cast<char*>(raw.data()),std::streamsize(raw.size())))throw std::runtime_error("truncated F32");
            Result r;
            if(!q8 && !q4 && !q5 && !q41 && !q51 && t.type==0) r=Encode(raw.data(),raw.size(),true,tolerance);
            if(quantized && (t.type==0 || t.type==1 || t.type==30) && t.dims[0]%32==0 && raw.size()%(t.type==0?128:64)==0) {
                std::vector<uint8_t> blocks;
                blocks.reserve(raw.size()/(t.type==0?128:64)*(q4?18:(q5?22:(q41?20:(q51?24:34)))));
                bool valid=true;
                for(size_t off=0;off<raw.size();off+=(t.type==0?128:64)) {
                    float values[32];float maxAbs=0;
                    for(int j=0;j<32;++j) {
                        if(t.type==0) std::memcpy(&values[j],raw.data()+off+4*j,4);
                        else {
                            const uint16_t h=uint16_t(raw[off+2*j])|(uint16_t(raw[off+2*j+1])<<8);
                            if(t.type==1) values[j]=FromHalf(h);
                            else {uint32_t bits=uint32_t(h)<<16;std::memcpy(&values[j],&bits,4);}
                        }
                        if(!std::isfinite(values[j])) {valid=false;break;}
                        maxAbs=std::max(maxAbs,std::fabs(values[j]));
                    }
                    if(!valid)break;
                    if(q51) {
                        // GGML Q5_1: FP16 delta + FP16 minimum, 32 high bits,
                        // 16 packed low nibbles; unsigned codes 0..31.
                        float low=values[0],high=values[0];
                        for(float f:values){low=std::min(low,f);high=std::max(high,f);}
                        uint16_t hm=ToHalf(low);
                        float minimum=FromHalf(hm);
                        uint16_t hd=ToHalf((high-low)/31.0f);
                        float delta=FromHalf(hd);
                        if(!std::isfinite(minimum)||!std::isfinite(delta)||
                           (high>low && delta<=0)) {valid=false;break;}
                        uint32_t highBits=0;
                        uint8_t packed[16]{};
                        for(int j=0;j<32;++j) {
                            float qf=delta?std::round((values[j]-minimum)/delta):0.0f;
                            qf=std::max(0.0f,std::min(31.0f,qf));
                            int qi=int(qf);
                            if(std::fabs(minimum+delta*qi-values[j])>tolerance){valid=false;break;}
                            if(qi&16)highBits|=uint32_t(1)<<j;
                            if(j<16)packed[j]=uint8_t(qi&15);
                            else packed[j-16]|=uint8_t((qi&15)<<4);
                        }
                        if(!valid)break;
                        blocks.push_back(uint8_t(hd));blocks.push_back(uint8_t(hd>>8));
                        blocks.push_back(uint8_t(hm));blocks.push_back(uint8_t(hm>>8));
                        for(int j=0;j<4;++j)blocks.push_back(uint8_t(highBits>>(8*j)));
                        blocks.insert(blocks.end(),packed,packed+16);
                    } else if(q41) {
                        // GGML Q4_1: unsigned 4-bit values with half-precision
                        // delta and minimum, low nibble j, high nibble j+16.
                        float low=values[0],high=values[0];
                        for(float f:values){low=std::min(low,f);high=std::max(high,f);}
                        uint16_t hm=ToHalf(low);
                        float minimum=FromHalf(hm);
                        float step=(high-low)/15.0f;
                        uint16_t hd=ToHalf(step);
                        float delta=FromHalf(hd);
                        if(!std::isfinite(minimum) || !std::isfinite(delta) ||
                           (high>low && delta<=0)) {valid=false;break;}
                        uint8_t packed[16]{};
                        for(int j=0;j<32;++j) {
                            float qf=delta?std::round((values[j]-minimum)/delta):0.0f;
                            qf=std::max(0.0f,std::min(15.0f,qf));
                            int qi=int(qf);
                            if(std::fabs((minimum+delta*qi)-values[j])>tolerance){valid=false;break;}
                            if(j<16)packed[j]=uint8_t(qi);
                            else packed[j-16]|=uint8_t(qi<<4);
                        }
                        if(!valid)break;
                        blocks.push_back(uint8_t(hd));blocks.push_back(uint8_t(hd>>8));
                        blocks.push_back(uint8_t(hm));blocks.push_back(uint8_t(hm>>8));
                        blocks.insert(blocks.end(),packed,packed+16);
                    } else if(q5) {
                        // GGML Q5_0: half scale, 4-byte high-bit mask, 16 packed nibbles.
                        // The extremal signed value maps to -16; each 5-bit code is biased by 16.
                        float extremum=0.0f;
                        for(float f:values)if(std::fabs(f)>std::fabs(extremum))extremum=f;
                        float scale=extremum/-16.0f;
                        uint16_t h=ToHalf(scale);
                        float actual=FromHalf(h);
                        if(maxAbs && (!std::isfinite(actual) || actual==0)) {valid=false;break;}
                        uint32_t high=0;
                        uint8_t packed[16]{};
                        for(int j=0;j<32;++j) {
                            float qf=actual?std::round(values[j]/actual):0.0f;
                            qf=std::max(-16.0f,std::min(15.0f,qf));
                            int qi=int(qf);
                            if(std::fabs(actual*qi-values[j])>tolerance){valid=false;break;}
                            unsigned code=unsigned(qi+16);
                            if(code&16u)high|=uint32_t(1)<<j;
                            if(j<16)packed[j]=uint8_t(code&15u);
                            else packed[j-16]|=uint8_t((code&15u)<<4);
                        }
                        if(!valid)break;
                        blocks.push_back(uint8_t(h));blocks.push_back(uint8_t(h>>8));
                        for(int j=0;j<4;++j)blocks.push_back(uint8_t(high>>(8*j)));
                        blocks.insert(blocks.end(),packed,packed+16);
                    } else if(q4) {
                        // GGML Q4_0: 32 weights, FP16 scale, 16 packed signed nibbles.
                        // Low nibble holds index j, high nibble index j+16.
                        // GGML Q4_0 uses a signed scale: the largest-magnitude
                        // value is mapped to quantized -8 (not +7).
                        float extremum=0.0f;
                        for(float f:values) if(std::fabs(f)>std::fabs(extremum))extremum=f;
                        float scale=extremum/-8.0f;
                        uint16_t h=ToHalf(scale);
                        float actual=FromHalf(h);
                        if(maxAbs && (!std::isfinite(actual) || actual==0)) {valid=false;break;}
                        uint8_t packed[16]{};
                        for(int j=0;j<32;++j) {
                            float qf=actual?std::round(values[j]/actual):0.0f;
                            qf=std::max(-8.0f,std::min(7.0f,qf));
                            int qi=int(qf);
                            if(std::fabs(actual*qi-values[j])>tolerance) {valid=false;break;}
                            if(j<16) packed[j]=uint8_t(qi+8);
                            else packed[j-16]|=uint8_t((qi+8)<<4);
                        }
                        if(!valid)break;
                        blocks.push_back(uint8_t(h));blocks.push_back(uint8_t(h>>8));
                        blocks.insert(blocks.end(),packed,packed+16);
                    } else {
                        float scale=maxAbs/127.0f;
                        uint16_t h=ToHalf(scale);
                        float actual=FromHalf(h);
                        if(maxAbs && (!std::isfinite(actual) || actual==0)) {valid=false;break;}
                        if(maxAbs && maxAbs/actual>127.5f) {valid=false;break;}
                        blocks.push_back(uint8_t(h));blocks.push_back(uint8_t(h>>8));
                        for(float f:values) {
                            float qf=actual?std::round(f/actual):0.0f;
                            qf=std::max(-128.0f,std::min(127.0f,qf));
                            int qi=int(qf);
                            if(std::fabs(actual*qi-f)>tolerance) {valid=false;break;}
                            blocks.push_back(uint8_t(int8_t(qi)));
                        }
                    }
                    if(!valid)break;
                }
                if(valid && blocks.size()<raw.size()) {
                    converted[i]=std::move(blocks);outputTypes[i]=q4?2:(q5?6:(q41?3:(q51?7:8)));++changed;
                }
            } else if(!q8 && !q4 && !q5 && !q41 && !q51 && r.encoding==Encoding::F16) {
                converted[i]=std::move(r.payload);outputTypes[i]=1;++changed;
            }
        }
        // Preserve original tensor ordering by physical offset, even when
        // the GGUF descriptor table uses a different order.
        U cursor=0;
        for(size_t i:order) {
            auto& t=ts[i];
            cursor=align(cursor,alignment);
            t.newOffset=cursor;
            U encodedBytes=t.bytes;
            if(streamF64toQ41[i])encodedBytes=mul(t.bytes/256,20);
            else if(streamF64toQ51[i])encodedBytes=mul(t.bytes/256,24);
            else if(streamF64toQ4[i])encodedBytes=mul(t.bytes/256,18);
            else if(streamF64toQ5[i])encodedBytes=mul(t.bytes/256,22);
            else if(streamF64toQ8[i])encodedBytes=mul(t.bytes/256,34);
            else if(streamF64toF16[i] || streamF64toBf16[i])encodedBytes=t.bytes/4;
            else if(streamF64toF32[i] || streamBf16[i] || streamHalf[i])encodedBytes=t.bytes/2;
            else if(streamQ4[i])encodedBytes=mul(t.bytes/(t.type==0?128:64),18);
            else if(streamQ41[i])encodedBytes=mul(t.bytes/(t.type==0?128:64),20);
            else if(streamQ5[i])encodedBytes=mul(t.bytes/(t.type==0?128:64),22);
            else if(streamQ51[i])encodedBytes=mul(t.bytes/(t.type==0?128:64),24);
            else if(streamQ8[i])encodedBytes=mul(t.bytes/(t.type==0?128:64),34);
            else if(!converted[i].empty())encodedBytes=converted[i].size();
            cursor=add(cursor,encodedBytes);
        }
        for(size_t i=0;i<ts.size();++i) {
            const auto& t=ts[i];
            write(out,t.name.size(),8);out.write(t.name.data(),std::streamsize(t.name.size()));
            write(out,t.dims.size(),4);for(U d:t.dims)write(out,d,8);
            write(out,outputTypes[i],4);write(out,t.newOffset,8);
        }
        U outStart=align(U(out.tellp()),alignment);
        while(U(out.tellp())<outStart)out.put(0);
        for(size_t i:order) {
            const auto& t=ts[i];
            U destination=add(outStart,t.newOffset);
            if(U(out.tellp())>destination)throw std::runtime_error("output tensor overlap");
            while(U(out.tellp())<destination)out.put(0);
            if(streamF64toQ2K[i]) {
                seek(in,add(dataStart,t.offset));
                uint8_t raw[2048],encoded[84];
                for(U off=0;off<t.bytes;off+=2048) {
                    if(!in.read(reinterpret_cast<char*>(raw),2048))throw std::runtime_error("truncated F64 Q2_K payload");
                    double v[256],lo[16],hi[16],sc[16],mn[16],maxSc=0,maxMn=0;
                    for(int j=0;j<256;++j){uint64_t bits=0;for(int k=0;k<8;++k)bits|=uint64_t(raw[8*j+k])<<(8*k);std::memcpy(&v[j],&bits,8);}
                    for(int g=0;g<16;++g){lo[g]=hi[g]=v[g*16];for(int j=1;j<16;++j){lo[g]=std::min(lo[g],v[g*16+j]);hi[g]=std::max(hi[g],v[g*16+j]);}sc[g]=(hi[g]-lo[g])/3.0;mn[g]=std::max(0.0,-lo[g]);maxSc=std::max(maxSc,sc[g]);maxMn=std::max(maxMn,mn[g]);}
                    const uint16_t hd=ToHalf(float(maxSc/15.0)),hm=ToHalf(float(maxMn/15.0));const double d=FromHalf(hd),dm=FromHalf(hm);
                    std::memset(encoded,0,84);encoded[80]=uint8_t(hd);encoded[81]=uint8_t(hd>>8);encoded[82]=uint8_t(hm);encoded[83]=uint8_t(hm>>8);
                    for(int g=0;g<16;++g){int ls=d?int(std::round(sc[g]/(d*15.0))):0,lm=dm?int(std::round(mn[g]/(dm*15.0))):0;ls=std::max(0,std::min(15,ls));lm=std::max(0,std::min(15,lm));encoded[g]=uint8_t(ls|(lm<<4));const double ds=d*ls,ms=dm*lm;for(int j=0;j<16;++j){const int q=ds?std::max(0,std::min(3,int(std::round((v[g*16+j]+ms)/ds)))):0;const int within=g%8,qi=(g/8)*32+(within/2)*16+j,shift=(within%2)*2;encoded[16+qi]|=uint8_t(q<<shift);}}
                    out.write(reinterpret_cast<const char*>(encoded),84);if(!out)throw std::runtime_error("F64 Q2_K write failure");
                }
            } else if(streamF64toQ8K[i]) {
                seek(in,add(dataStart,t.offset));
                uint8_t raw[2048],encoded[292];
                for(U off=0;off<t.bytes;off+=2048) {
                    if(!in.read(reinterpret_cast<char*>(raw),2048))
                        throw std::runtime_error("truncated F64 Q8_K payload");
                    double values[256],maxAbs=0;
                    for(int j=0;j<256;++j) {
                        uint64_t bits=0;
                        for(int k=0;k<8;++k)bits|=uint64_t(raw[8*j+k])<<(8*k);
                        std::memcpy(&values[j],&bits,8);
                        maxAbs=std::max(maxAbs,std::fabs(values[j]));
                    }
                    const float d=float(maxAbs/127.0);
                    std::memcpy(encoded,&d,4);
                    int16_t sums[16]={};
                    for(int j=0;j<256;++j) {
                        const int q=d?int(std::max(-127.0,std::min(127.0,
                            std::round(values[j]/double(d))))):0;
                        encoded[4+j]=uint8_t(int8_t(q));
                        sums[j/16]=int16_t(sums[j/16]+q);
                    }
                    for(int j=0;j<16;++j)
                        std::memcpy(encoded+260+2*j,&sums[j],2);
                    out.write(reinterpret_cast<const char*>(encoded),292);
                    if(!out)throw std::runtime_error("F64 Q8_K write failure");
                }
            } else if(streamF64toQ41[i]||streamF64toQ51[i]) {
                seek(in,add(dataStart,t.offset));
                uint8_t raw[256],narrow[128],encoded[24];
                for(U off=0;off<t.bytes;off+=256) {
                    if(!in.read(reinterpret_cast<char*>(raw),256))
                        throw std::runtime_error("truncated F64 affine payload");
                    for(int j=0;j<32;++j) {
                        uint64_t bits=0;
                        for(int k=0;k<8;++k)bits|=uint64_t(raw[8*j+k])<<(8*k);
                        double original;
                        std::memcpy(&original,&bits,8);
                        const float f=static_cast<float>(original);
                        uint32_t word;
                        std::memcpy(&word,&f,4);
                        for(int k=0;k<4;++k)narrow[4*j+k]=uint8_t(word>>(8*k));
                    }
                    const bool ok=streamF64toQ41[i]
                        ?encodeQ41Block(narrow,0,tolerance,encoded)
                        :encodeQ51Block(narrow,0,tolerance,encoded);
                    if(!ok)throw std::runtime_error("F64 affine preflight/write mismatch");
                    out.write(reinterpret_cast<const char*>(encoded),
                              streamF64toQ41[i]?20:24);
                    if(!out)throw std::runtime_error("F64 affine write failure");
                }
            } else if(streamF64toQ4[i]||streamF64toQ5[i]) {
                seek(in,add(dataStart,t.offset));
                uint8_t raw[256],narrow[128],encoded[22];
                for(U off=0;off<t.bytes;off+=256) {
                    if(!in.read(reinterpret_cast<char*>(raw),256))
                        throw std::runtime_error("truncated F64 Q4/Q5 payload");
                    for(int j=0;j<32;++j) {
                        uint64_t bits=0;
                        for(int k=0;k<8;++k)bits|=uint64_t(raw[8*j+k])<<(8*k);
                        double original;
                        std::memcpy(&original,&bits,8);
                        const float f=static_cast<float>(original);
                        uint32_t word;
                        std::memcpy(&word,&f,4);
                        for(int k=0;k<4;++k)narrow[4*j+k]=uint8_t(word>>(8*k));
                    }
                    const bool ok=streamF64toQ4[i]
                        ?encodeQ4Block(narrow,0,tolerance,encoded)
                        :encodeQ5Block(narrow,0,tolerance,encoded);
                    if(!ok)throw std::runtime_error("F64 Q4/Q5 preflight/write mismatch");
                    out.write(reinterpret_cast<const char*>(encoded),
                              streamF64toQ4[i]?18:22);
                    if(!out)throw std::runtime_error("F64 Q4/Q5 write failure");
                }
            } else if(streamF64toQ8[i]) {
                seek(in,add(dataStart,t.offset));
                uint8_t raw[256],narrow[128],encoded[34];
                for(U off=0;off<t.bytes;off+=256) {
                    if(!in.read(reinterpret_cast<char*>(raw),256))
                        throw std::runtime_error("truncated F64 Q8 payload");
                    for(int j=0;j<32;++j) {
                        uint64_t bits=0;
                        for(int k=0;k<8;++k)bits|=uint64_t(raw[8*j+k])<<(8*k);
                        double original;
                        std::memcpy(&original,&bits,8);
                        const float f=static_cast<float>(original);
                        uint32_t word;
                        std::memcpy(&word,&f,4);
                        for(int k=0;k<4;++k)narrow[4*j+k]=uint8_t(word>>(8*k));
                    }
                    if(!encodeQ8Block(narrow,0,tolerance,encoded))
                        throw std::runtime_error("F64 Q8 preflight/write mismatch");
                    out.write(reinterpret_cast<const char*>(encoded),34);
                    if(!out)throw std::runtime_error("F64 Q8 write failure");
                }
            } else if(streamF64toBf16[i]) {
                seek(in,add(dataStart,t.offset));
                uint8_t source[65536],packed[16384];
                for(U off=0;off<t.bytes;) {
                    const size_t n=size_t(std::min<U>(t.bytes-off,sizeof(source)));
                    if(!in.read(reinterpret_cast<char*>(source),std::streamsize(n)))
                        throw std::runtime_error("truncated F64 to BF16 streaming payload");
                    for(size_t j=0;j<n;j+=8) {
                        uint64_t bits=0;
                        for(int k=0;k<8;++k)bits|=uint64_t(source[j+k])<<(8*k);
                        double original;
                        std::memcpy(&original,&bits,8);
                        const float narrowed=static_cast<float>(original);
                        uint32_t word;
                        std::memcpy(&word,&narrowed,4);
                        const uint16_t bf=uint16_t((word+0x7fffu+((word>>16)&1u))>>16);
                        packed[j/4]=uint8_t(bf);
                        packed[j/4+1]=uint8_t(bf>>8);
                    }
                    out.write(reinterpret_cast<const char*>(packed),std::streamsize(n/4));
                    if(!out)throw std::runtime_error("F64 to BF16 streaming write failure");
                    off+=n;
                }
            } else if(streamF64toF16[i]) {
                seek(in,add(dataStart,t.offset));
                uint8_t source[65536],packed[16384];
                for(U off=0;off<t.bytes;) {
                    const size_t n=size_t(std::min<U>(t.bytes-off,sizeof(source)));
                    if(!in.read(reinterpret_cast<char*>(source),std::streamsize(n)))
                        throw std::runtime_error("truncated F64 to F16 streaming payload");
                    for(size_t j=0;j<n;j+=8) {
                        uint64_t bits=0;
                        for(int k=0;k<8;++k)bits|=uint64_t(source[j+k])<<(8*k);
                        double original;
                        std::memcpy(&original,&bits,8);
                        const uint16_t half=ToHalf(static_cast<float>(original));
                        packed[j/4]=uint8_t(half);
                        packed[j/4+1]=uint8_t(half>>8);
                    }
                    out.write(reinterpret_cast<const char*>(packed),std::streamsize(n/4));
                    if(!out)throw std::runtime_error("F64 to F16 streaming write failure");
                    off+=n;
                }
            } else if(streamF64toF32[i]) {
                seek(in,add(dataStart,t.offset));
                uint8_t source[65536],packed[32768];
                for(U off=0;off<t.bytes;) {
                    const size_t n=size_t(std::min<U>(t.bytes-off,sizeof(source)));
                    if(!in.read(reinterpret_cast<char*>(source),std::streamsize(n)))
                        throw std::runtime_error("truncated F64 streaming payload");
                    for(size_t j=0;j<n;j+=8) {
                        uint64_t bits=0;
                        for(int k=0;k<8;++k)bits|=uint64_t(source[j+k])<<(8*k);
                        double original;
                        std::memcpy(&original,&bits,8);
                        const float narrowed=static_cast<float>(original);
                        uint32_t word;
                        std::memcpy(&word,&narrowed,4);
                        for(int k=0;k<4;++k)packed[j/2+k]=uint8_t(word>>(8*k));
                    }
                    out.write(reinterpret_cast<const char*>(packed),std::streamsize(n/2));
                    if(!out)throw std::runtime_error("F64 to F32 streaming write failure");
                    off+=n;
                }
            } else if(streamQ5[i]) {
                seek(in,add(dataStart,t.offset));
                const size_t inputBlock=t.type==0?128:64;
                uint8_t block[128],encoded[22];
                std::vector<uint8_t> buffered;
                buffered.reserve(65536);
                for(U off=0;off<t.bytes;off+=inputBlock) {
                    if(!in.read(reinterpret_cast<char*>(block),std::streamsize(inputBlock)))
                        throw std::runtime_error("truncated Q5 streaming payload");
                    if(!encodeQ5Block(block,t.type,tolerance,encoded))
                        throw std::runtime_error("Q5 preflight mismatch");
                    buffered.insert(buffered.end(),encoded,encoded+22);
                    if(buffered.size()>=65536-22) {
                        out.write(reinterpret_cast<const char*>(buffered.data()),std::streamsize(buffered.size()));
                        buffered.clear();
                    }
                    if(!out)throw std::runtime_error("Q5 streaming write failure");
                }

                if(!buffered.empty())out.write(reinterpret_cast<const char*>(buffered.data()),std::streamsize(buffered.size()));
                if(!out)throw std::runtime_error("quantized streaming write failure");
            } else if(streamQ4[i]) {
                seek(in,add(dataStart,t.offset));
                const size_t inputBlock=t.type==0?128:64;
                uint8_t block[128],encoded[18];
                std::vector<uint8_t> buffered;
                buffered.reserve(65536);
                for(U off=0;off<t.bytes;off+=inputBlock) {
                    if(!in.read(reinterpret_cast<char*>(block),std::streamsize(inputBlock)))
                        throw std::runtime_error("truncated Q4 streaming payload");
                    if(!encodeQ4Block(block,t.type,tolerance,encoded))
                        throw std::runtime_error("Q4 preflight mismatch");
                    buffered.insert(buffered.end(),encoded,encoded+18);
                    if(buffered.size()>=65536-18) {
                        out.write(reinterpret_cast<const char*>(buffered.data()),std::streamsize(buffered.size()));
                        buffered.clear();
                    }
                    if(!out)throw std::runtime_error("Q4 streaming write failure");
                }

                if(!buffered.empty())out.write(reinterpret_cast<const char*>(buffered.data()),std::streamsize(buffered.size()));
                if(!out)throw std::runtime_error("quantized streaming write failure");
            } else if(streamQ41[i]) {
                seek(in,add(dataStart,t.offset));
                const size_t inputBlock=t.type==0?128:64;
                uint8_t block[128],encoded[20];
                std::vector<uint8_t> buffered;
                buffered.reserve(65536);
                for(U off=0;off<t.bytes;off+=inputBlock) {
                    if(!in.read(reinterpret_cast<char*>(block),std::streamsize(inputBlock)))
                        throw std::runtime_error("truncated Q4 streaming payload");
                    if(!encodeQ41Block(block,t.type,tolerance,encoded))
                        throw std::runtime_error("Q4 preflight mismatch");
                    buffered.insert(buffered.end(),encoded,encoded+20);
                    if(buffered.size()>=65536-20) {
                        out.write(reinterpret_cast<const char*>(buffered.data()),std::streamsize(buffered.size()));
                        buffered.clear();
                    }
                    if(!out)throw std::runtime_error("Q4 streaming write failure");
                }

                if(!buffered.empty())out.write(reinterpret_cast<const char*>(buffered.data()),std::streamsize(buffered.size()));
                if(!out)throw std::runtime_error("quantized streaming write failure");
            } else if(streamQ51[i]) {
                seek(in,add(dataStart,t.offset));
                const size_t inputBlock=t.type==0?128:64;
                uint8_t block[128],encoded[24];
                std::vector<uint8_t> buffered;
                buffered.reserve(65536);
                for(U off=0;off<t.bytes;off+=inputBlock) {
                    if(!in.read(reinterpret_cast<char*>(block),std::streamsize(inputBlock)))
                        throw std::runtime_error("truncated Q5_1 streaming payload");
                    if(!encodeQ51Block(block,t.type,tolerance,encoded))
                        throw std::runtime_error("Q5_1 preflight mismatch");
                    buffered.insert(buffered.end(),encoded,encoded+24);
                    if(buffered.size()>=65536-24) {
                        out.write(reinterpret_cast<const char*>(buffered.data()),std::streamsize(buffered.size()));
                        buffered.clear();
                    }
                    if(!out)throw std::runtime_error("Q5_1 streaming write failure");
                }

                if(!buffered.empty())out.write(reinterpret_cast<const char*>(buffered.data()),std::streamsize(buffered.size()));
                if(!out)throw std::runtime_error("quantized streaming write failure");
            } else if(streamQ8[i]) {
                seek(in,add(dataStart,t.offset));
                const size_t inputBlock=t.type==0?128:64;
                uint8_t block[128],encoded[34];
                std::vector<uint8_t> buffered;
                buffered.reserve(65536);
                for(U off=0;off<t.bytes;off+=inputBlock) {
                    if(!in.read(reinterpret_cast<char*>(block),std::streamsize(inputBlock)))
                        throw std::runtime_error("truncated Q8 streaming payload");
                    if(!encodeQ8Block(block,t.type,tolerance,encoded))
                        throw std::runtime_error("Q8 preflight mismatch");
                    buffered.insert(buffered.end(),encoded,encoded+34);
                    if(buffered.size()>=65536-34) {
                        out.write(reinterpret_cast<const char*>(buffered.data()),std::streamsize(buffered.size()));
                        buffered.clear();
                    }
                    if(!out)throw std::runtime_error("Q8 streaming write failure");
                }

                if(!buffered.empty())out.write(reinterpret_cast<const char*>(buffered.data()),std::streamsize(buffered.size()));
                if(!out)throw std::runtime_error("quantized streaming write failure");
            } else if(streamBf16[i]) {
                seek(in,add(dataStart,t.offset));
                // Reuse fixed-size buffers to avoid one write syscall per weight.
                std::vector<uint8_t> chunk(65536), packed(chunk.size()/2);
                for(U off=0;off<t.bytes;) {
                    size_t n=size_t(std::min<U>(t.bytes-off,chunk.size()));
                    if(!in.read(reinterpret_cast<char*>(chunk.data()),std::streamsize(n)))
                        throw std::runtime_error("truncated BF16 streaming payload");
                    for(size_t j=0;j<n;j+=4) {
                        uint32_t bits=uint32_t(chunk[j])|(uint32_t(chunk[j+1])<<8)|
                                      (uint32_t(chunk[j+2])<<16)|(uint32_t(chunk[j+3])<<24);
                        uint16_t h=uint16_t((bits+0x7fffu+((bits>>16)&1u))>>16);
                        packed[j/2]=uint8_t(h);
                        packed[j/2+1]=uint8_t(h>>8);
                    }
                    out.write(reinterpret_cast<const char*>(packed.data()),std::streamsize(n/2));
                    if(!out)throw std::runtime_error("BF16 streaming write failure");
                    off+=n;
                }
            } else if(streamHalf[i]) {
                seek(in,add(dataStart,t.offset));
                std::vector<uint8_t> chunk(65536);
                std::vector<uint8_t> half(chunk.size()/2);
                for(U off=0;off<t.bytes;) {
                    size_t n=size_t(std::min<U>(t.bytes-off,chunk.size()));
                    if(!in.read(reinterpret_cast<char*>(chunk.data()),std::streamsize(n)))
                        throw std::runtime_error("truncated F32 streaming conversion");
                    for(size_t j=0;j<n;j+=4) {
                        uint32_t bits=uint32_t(chunk[j])|(uint32_t(chunk[j+1])<<8)|
                                      (uint32_t(chunk[j+2])<<16)|(uint32_t(chunk[j+3])<<24);
                        uint16_t h=ToHalf(Float(bits));
                        half[j/2]=uint8_t(h);half[j/2+1]=uint8_t(h>>8);
                    }
                    out.write(reinterpret_cast<const char*>(half.data()),std::streamsize(n/2));
                    if(!out)throw std::runtime_error("F16 streaming write failed");
                    off+=n;
                }
            } else if(!converted[i].empty())
                out.write(reinterpret_cast<const char*>(converted[i].data()),std::streamsize(converted[i].size()));
            else {seek(in,add(dataStart,t.offset));copy(in,out,t.bytes);}
        }
        // The tensor table advertises exactly 'cursor' bytes of aligned data.
        // Reject a short or overlong payload rather than publishing a GGUF
        // whose offsets disagree with its actual file length.
        const U expectedEnd=add(outStart,cursor);
        const auto finalPosition=out.tellp();
        if(finalPosition<0 || U(finalPosition)!=expectedEnd)
            throw std::runtime_error("GGUF payload size disagrees with tensor descriptors");
        out.flush();if(!out)throw std::runtime_error("output write failure");
        out.close();in.close();
        // Report actual on-disk savings, including GGUF headers, tensor
        // descriptors and alignment padding. Never estimate from dtype alone.
        std::error_code sizeError;
        const auto outputBytes=std::filesystem::file_size(tmp,sizeError);
        if(sizeError)throw std::runtime_error("cannot measure compressed output");
        if(outputBytes!=expectedEnd)
            throw std::runtime_error("compressed GGUF disk length mismatch");
        // Reject obvious source mutation during the two-pass conversion.
        // A same-length concurrent rewrite still requires an external lock
        // or immutable input snapshot for full protection.
        std::error_code sourceSizeError;
        const auto currentSourceBytes=std::filesystem::file_size(inputPath,sourceSizeError);
        if(sourceSizeError || currentSourceBytes!=fileSize)
            throw std::runtime_error("source model size changed during conversion");
        if(std::rename(tmp.c_str(),argv[2]))throw std::runtime_error("rename failed");
        std::cout<<"converted tensors: "<<changed<<"/"<<ts.size()<<"\n";
        std::cout<<"file bytes: "<<fileSize<<" -> "<<outputBytes
                 <<" (saved "<<(fileSize>outputBytes?fileSize-outputBytes:0)
                 <<", ratio "<<(outputBytes?double(fileSize)/double(outputBytes):0.0)
                 <<"x)\n";
        if(outputBytes>fileSize)
            std::cerr<<"warning: output file is larger than input due to layout/alignment\n";
        return 0;
    } catch(const std::exception& e) {
        // Cleanup must not unlink an input aliased by the temporary path.
        std::error_code ec;
        bool same=false;
        if(std::filesystem::exists(tmp,ec) && !ec)
            same=std::filesystem::equivalent(argv[1],tmp,ec) && !ec;
        if(ownsTemporary && !same && !ec)std::remove(tmp.c_str());
        std::cerr<<e.what()<<"\n";return 1;
    }
}
