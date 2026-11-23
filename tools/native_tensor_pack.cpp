// Standalone native lossless file compressor. This is a RawrXD container, NOT GGUF.
// Build: c++ -std=c++17 -O2 -I src/deep2 tools/native_tensor_pack.cpp -o native_tensor_pack
#include "../src/deep2/NativeTensorCompression.hpp"
#include <fstream>
#include <iostream>
#include <string>
#include <array>
#include <cstdio>
#include <limits>
using namespace RawrXD::TensorCompression;
namespace {
constexpr size_t Chunk = 1u<<20;
void put64(std::ostream& o, uint64_t n) { for(int i=0;i<8;++i) o.put(char(n>>(8*i))); }
uint64_t get64(std::istream& in) {
    uint64_t n=0;
    for(int i=0;i<8;++i) { int c=in.get(); if(c==EOF) throw std::runtime_error("truncated header"); n|=uint64_t(uint8_t(c))<<(8*i); }
    return n;
}
uint32_t crc32(const uint8_t* p,size_t n) {
    uint32_t c=~0u;
    for(size_t i=0;i<n;++i) {c^=p[i]; for(int j=0;j<8;++j) c=(c>>1)^((c&1)?0xedb88320u:0u);}
    return ~c;
}
void put32(std::ostream& o,uint32_t n) {for(int i=0;i<4;++i) o.put(char(n>>(8*i)));}
uint32_t get32(std::istream& in) {
    uint32_t n=0;
    for(int i=0;i<4;++i) {int c=in.get(); if(c==EOF) throw std::runtime_error("truncated checksum"); n|=uint32_t(uint8_t(c))<<(8*i);}
    return n;
}
void exact(std::istream& in,char* p,size_t n) {
    if(n>static_cast<size_t>(std::numeric_limits<std::streamsize>::max())) throw std::runtime_error("read too large");
    if(!in.read(p,static_cast<std::streamsize>(n))) throw std::runtime_error("truncated payload");
}
void pack(std::istream& in,std::ostream& out) {
    out.write("RXTC1\r\n\032\n",8);
    std::array<uint8_t,Chunk> buf{};
    while(true) {
        in.read(reinterpret_cast<char*>(buf.data()),buf.size());
        size_t n=static_cast<size_t>(in.gcount());
        if(!n) { if(in.bad()) throw std::runtime_error("input error"); break; }
        Result r=Encode(buf.data(),n); // strictly lossless: no FP16 without tensor type metadata
        out.put(char(r.encoding)); put64(out,r.original_bytes); put64(out,r.payload.size());
        put32(out,crc32(buf.data(),n));
        out.write(reinterpret_cast<const char*>(r.payload.data()),static_cast<std::streamsize>(r.payload.size()));
        if(!out) throw std::runtime_error("write error");
    }
    out.put(char(255)); // end-of-stream sentinel
}
void unpack(std::istream& in,std::ostream& out) {
    char magic[8]; exact(in,magic,8);
    if(std::string(magic,8)!=std::string("RXTC1\r\n\032\n",8)) throw std::runtime_error("wrong container magic");
    for(;;) {
        int kind=in.get();
        if(kind==EOF) throw std::runtime_error("missing terminator");
        if(kind==255) {
            if(in.peek()!=EOF) throw std::runtime_error("trailing bytes");
            if(in.bad()) throw std::runtime_error("input error");
            return;
        }
        if(kind!=int(Encoding::Raw) && kind!=int(Encoding::RLE))
            throw std::runtime_error("unsupported encoding");
        uint64_t original=get64(in), stored=get64(in);
        uint32_t expected=get32(in);
        if(original==0 || original>Chunk || stored>Chunk || stored==0)
            throw std::runtime_error("invalid chunk sizes");
        Result r; r.encoding=static_cast<Encoding>(kind); r.original_bytes=original;
        r.payload.resize(static_cast<size_t>(stored));
        exact(in,reinterpret_cast<char*>(r.payload.data()),r.payload.size());
        auto decoded=Decode(r);
        if(crc32(decoded.data(),decoded.size())!=expected) throw std::runtime_error("checksum mismatch");
        out.write(reinterpret_cast<const char*>(decoded.data()),static_cast<std::streamsize>(decoded.size()));
        if(!out) throw std::runtime_error("write error");
    }
}
}
int main(int argc,char** argv) {
    if(argc!=4 || (std::string(argv[1])!="pack" && std::string(argv[1])!="unpack")) {
        std::cerr<<"usage: native_tensor_pack pack|unpack INPUT OUTPUT\n";
        return 2;
    }
    if(std::string(argv[2])==argv[3]) {std::cerr<<"input and output must differ\n";return 2;}
    std::ifstream in(argv[2],std::ios::binary);
    if(!in) {std::cerr<<"cannot open input\n";return 1;}
    std::string temp=std::string(argv[3])+".partial";
    std::ofstream out(temp,std::ios::binary|std::ios::trunc);
    if(!out) {std::cerr<<"cannot create output\n";return 1;}
    try {
        if(std::string(argv[1])=="pack") pack(in,out); else unpack(in,out);
        out.flush();
        if(!out) throw std::runtime_error("flush error");
        out.close();
        if(std::rename(temp.c_str(),argv[3])!=0) throw std::runtime_error("output rename failed");
        return 0;
    } catch(const std::exception& e) {
        out.close(); std::remove(temp.c_str());
        std::cerr<<"compression failed: "<<e.what()<<"\n";
        return 1;
    }
}
