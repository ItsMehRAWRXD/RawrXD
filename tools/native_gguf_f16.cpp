// Native GGUF v2/v3 F32->F16 rewriter. All other tensor payloads copied byte-for-byte.
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
struct Tensor {std::string name;std::vector<U> dims;uint32_t type;U offset;U bytes;U newOffset;bool convert;};
}
int main(int argc,char** argv) {
    if(argc!=4 && argc!=5) {std::cerr<<"usage: native_gguf_f16 INPUT.gguf OUTPUT.gguf MAX_ABS_ERROR [f16|q8_0|q4_0]\n";return 2;}
    if(std::string(argv[1])==argv[2]) {std::cerr<<"input and output must differ\n";return 2;}
    std::string tmp=std::string(argv[2])+".partial";
    try {
        const bool q8=argc==5 && std::string(argv[4])=="q8_0";
        const bool q4=argc==5 && std::string(argv[4])=="q4_0";
        if(argc==5 && !q8 && !q4 && std::string(argv[4])!="f16")throw std::runtime_error("unknown encoding");
        float tolerance=std::stof(argv[3]);if(!std::isfinite(tolerance)||tolerance<0)throw std::runtime_error("invalid tolerance");
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
            t.convert=((t.type==0 || t.type==1 || t.type==30) && elements<=std::numeric_limits<size_t>::max()/4);
            t.bytes=t.type==0?mul(elements,4):((t.type==1 || t.type==30)?mul(elements,2):0);
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
            if(j && ts[order[j-1]].type==0 && ts[order[j-1]].bytes>t.offset-ts[order[j-1]].offset)
                throw std::runtime_error("overlapping F32 tensor payloads");
            if(j && (ts[order[j-1]].type==1 || ts[order[j-1]].type==30) && ts[order[j-1]].bytes>t.offset-ts[order[j-1]].offset)
                throw std::runtime_error("overlapping 16-bit tensor payloads");
            if(t.offset%alignment)throw std::runtime_error("unaligned tensor offset");
            if(t.type==0 || t.type==1 || t.type==30) {
                U expected=1;
                for(U d:t.dims)expected=mul(expected,d);
                expected=mul(expected,t.type==0?4:2);
                if(t.bytes!=expected)throw std::runtime_error("invalid floating tensor length");
            }
            if(j && t.offset==ts[order[j-1]].offset)throw std::runtime_error("overlapping tensor offsets");
            U span=next-t.offset;
            if(t.bytes && t.bytes>span)throw std::runtime_error("tensor exceeds span");
            if(!t.bytes)t.bytes=span; // Unknown quantized type: preserve complete storage span
            
            if(t.convert && t.bytes>64u*1024u*1024u) t.convert=false; // bounded allocation
        }
        std::ofstream out(tmp,std::ios::binary|std::ios::trunc);
        if(!out)throw std::runtime_error("cannot create output");
        seek(in,0);copy(in,out,kvEnd); // preserve original header and all metadata bytes
        // Preflight each F32 candidate before writing tensor table.
        std::vector<std::vector<uint8_t>> converted(ts.size());
        std::vector<uint32_t> outputTypes(ts.size());
        for(size_t i=0;i<ts.size();++i)outputTypes[i]=ts[i].type;
        U changed=0;
        for(size_t i=0;i<ts.size();++i) {
            auto& t=ts[i];if(!t.convert || (t.type!=0 && !q8 && !q4))continue;
            if(t.bytes>64u*1024u*1024u)continue;
            std::vector<uint8_t> raw(static_cast<size_t>(t.bytes));
            seek(in,add(dataStart,t.offset));
            if(!in.read(reinterpret_cast<char*>(raw.data()),std::streamsize(raw.size())))throw std::runtime_error("truncated F32");
            Result r;
            if(!q8 && !q4 && t.type==0) r=Encode(raw.data(),raw.size(),true,tolerance);
            if((q8 || q4) && t.dims[0]%32==0 && raw.size()%(t.type==0?128:64)==0) {
                std::vector<uint8_t> blocks;
                blocks.reserve(raw.size()/(t.type==0?128:64)*(q4?18:34));
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
                    if(q4) {
                        // GGML Q4_0: 32 weights, FP16 scale, 16 packed signed nibbles.
                        // Low nibble holds index j, high nibble index j+16.
                        float scale=maxAbs/7.0f;
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
                    converted[i]=std::move(blocks);outputTypes[i]=q4?2:8;++changed;
                }
            } else if(!q8 && !q4 && r.encoding==Encoding::F16) {
                converted[i]=std::move(r.payload);outputTypes[i]=1;++changed;
            }
        }
        U cursor=0;
        for(auto& t:ts) {
            cursor=align(cursor,alignment);t.newOffset=cursor;
            size_t i=size_t(&t-ts.data());
            cursor=add(cursor,converted[i].empty()?t.bytes:converted[i].size());
            write(out,t.name.size(),8);out.write(t.name.data(),std::streamsize(t.name.size()));
            write(out,t.dims.size(),4);for(U d:t.dims)write(out,d,8);
            write(out,outputTypes[i],4);write(out,t.newOffset,8);
        }
        U outStart=align(U(out.tellp()),alignment);
        while(U(out.tellp())<outStart)out.put(0);
        for(size_t i=0;i<ts.size();++i) {
            const auto& t=ts[i];
            while(U(out.tellp())<add(outStart,t.newOffset))out.put(0);
            if(!converted[i].empty())out.write(reinterpret_cast<const char*>(converted[i].data()),std::streamsize(converted[i].size()));
            else {seek(in,add(dataStart,t.offset));copy(in,out,t.bytes);}
        }
        out.flush();if(!out)throw std::runtime_error("output write failure");
        out.close();in.close();
        if(std::rename(tmp.c_str(),argv[2]))throw std::runtime_error("rename failed");
        std::cout<<"converted tensors: "<<changed<<"/"<<ts.size()<<"\n";
        return 0;
    } catch(const std::exception& e) {std::remove(tmp.c_str());std::cerr<<e.what()<<"\n";return 1;}
}
