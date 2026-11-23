// v2_bench.cpp -- measure TensorAwareLosslessV2 (format-aware deinterleave)
// on real GGUF tensors, with byte-exact roundtrip verification.
// Build: g++ -std=c++17 -O2 -I. -I include -I src tools/v2_bench.cpp -lz -o v2bench
// Usage: v2bench <model.gguf> [max_tensors=N]
#include "src/deep2/TensorAwareLosslessV2.hpp"
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace rawrxd::weights::v2;

static bool read_str(std::ifstream& f, std::string& s) {
    uint64_t len = 0;
    if (!f.read(reinterpret_cast<char*>(&len), sizeof(len))) return false;
    if (len > (1u << 20)) return false;
    s.resize(static_cast<size_t>(len));
    return f.read(s.data(), static_cast<std::streamsize>(len)).good();
}
static bool read_u32(std::ifstream& f, uint32_t& v) { return f.read(reinterpret_cast<char*>(&v), sizeof(v)).good(); }
static bool read_u64(std::ifstream& f, uint64_t& v) { return f.read(reinterpret_cast<char*>(&v), sizeof(v)).good(); }

static uint64_t type_bytes(uint32_t t, uint64_t n_elem) {
    switch (t) {
        case 0: return n_elem*4; case 1: return n_elem*2;
        case 2: return (n_elem/32)*18; case 3: return (n_elem/32)*20;
        case 6: return (n_elem/32)*22; case 7: return (n_elem/32)*24;
        case 8: return (n_elem/32)*34; case 9: return (n_elem/32)*36;
        case 10: return (n_elem/256)*84; case 11: return (n_elem/256)*110;
        case 12: return (n_elem/256)*144; case 13: return (n_elem/256)*176;
        case 14: return (n_elem/256)*210; case 15: return (n_elem/256)*292;
        default: return 0;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) { std::cerr << "usage: v2bench <model.gguf> [max_tensors=N]\n"; return 2; }
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) { std::cerr << "cannot open\n"; return 1; }
    size_t max_tensors = 16;
    if (argc > 2) { std::string a = argv[2]; if (a.rfind("max_tensors=",0)==0) max_tensors = std::stoul(a.substr(12)); }
    char magic[4]; uint32_t ver=0; uint64_t nt=0, nkv=0;
    if (!f.read(magic,4) || std::memcmp(magic,"GGUF",4)!=0 || !read_u32(f,ver) || !read_u64(f,nt) || !read_u64(f,nkv)) { std::cerr<<"not gguf\n"; return 1; }
    auto skip = [&](uint32_t vt)->bool{
        auto sk=[&](uint64_t n){ return n<=(1ull<<32) && f.seekg((std::streamoff)n,std::ios::cur).good(); };
        switch(vt){case 0:case 1:case 7:return sk(1);case 2:case 3:return sk(2);case 4:case 5:case 6:return sk(4);case 10:case 11:case 12:return sk(8);
        case 8:{std::string s;return read_str(f,s);}
        case 9:{uint32_t at=0;uint64_t al=0;if(!read_u32(f,at)||!read_u64(f,al))return false;if(at==8){for(uint64_t i=0;i<al;++i){std::string s;if(!read_str(f,s))return false;}return true;}
          uint64_t e=0;switch(at){case 0:case 1:case 7:e=1;break;case 2:case 3:e=2;break;case 4:case 5:case 6:e=4;break;case 10:case 11:case 12:e=8;break;default:return false;}return sk(al*e);}
        default:return false;}
    };
    for (uint64_t i=0;i<nkv;++i){std::string k;uint32_t vt=0;if(!read_str(f,k)||!read_u32(f,vt)||!skip(vt))return 1;}
    struct TI{std::string name;uint64_t dim[4];uint32_t nd;uint32_t type;uint64_t off;};
    std::vector<TI> infos(nt);
    for(uint64_t i=0;i<nt;++i){auto&t=infos[i];if(!read_str(f,t.name)||!read_u32(f,t.nd)||t.nd>4)return 1;for(uint32_t d=0;d<t.nd;++d)if(!read_u64(f,t.dim[d]))return 1;if(!read_u32(f,t.type)||!read_u64(f,t.off))return 1;}
    uint64_t ds=((uint64_t)f.tellg()+31)&~31ull;

    size_t done=0, ok=0, fail=0, skipped=0;
    uint64_t raw_tot=0, comp_tot=0, v2_tot=0;
    for(uint64_t i=0;i<nt && done<max_tensors;++i){
        auto&t=infos[i];
        uint64_t ne=1;for(uint32_t d=0;d<t.nd;++d)ne*=t.dim[d];
        uint64_t bytes=type_bytes(t.type,ne);
        if(bytes==0){++skipped;continue;}
        std::vector<uint8_t> buf(bytes);
        f.seekg((std::streamoff)(ds+t.off),std::ios::beg);
        if(!f.read((char*)buf.data(),(std::streamsize)bytes)){++skipped;continue;}
        // baseline zlib
        uLongf cap=compressBound((uLong)bytes);
        std::vector<uint8_t> zl(cap);
        compress2(zl.data(),&cap,buf.data(),(uLong)bytes,Z_BEST_COMPRESSION);
        zl.resize(cap);
        uint64_t zlsize = zl.size() < bytes ? zl.size() : bytes;
        // v2
        uint64_t v2size = bytes;
        bool v2ok=false;
        try {
            auto enc = EncodeV2(buf.data(), buf.size(), t.type);
            auto wire = SerializeV2(enc);
            auto dec = DeserializeV2(wire);
            auto out = DecodeV2(dec);
            if(out==buf){ v2ok=true; v2size=wire.size(); }
        } catch(...) { v2ok=false; }
        if(v2ok)++ok; else ++fail;
        raw_tot+=bytes; comp_tot+=zlsize; v2_tot+=v2size;
        if(v2ok){
            double zr=zlsize/(double)bytes, vr=v2size/(double)bytes;
            std::cout<<"OK "<<t.name<<" type="<<t.type<<" bytes="<<bytes
                     <<" zlib="<<zlsize<<"("<<zr<<") v2="<<v2size<<"("<<vr<<")\n";
        } else {
            std::cout<<"FAIL "<<t.name<<" type="<<t.type<<"\n";
        }
        ++done;
    }
    std::cout<<"SUMMARY tensors="<<done<<" ok="<<ok<<" fail="<<fail<<" skipped="<<skipped
             <<" raw="<<raw_tot<<" zlib="<<comp_tot<<" zlib_ratio="<<(raw_tot?(double)comp_tot/raw_tot:0)
             <<" v2="<<v2_tot<<" v2_ratio="<<(raw_tot?(double)v2_tot/raw_tot:0)
             <<" v2_savings_pct="<<(raw_tot?(1.0-(double)v2_tot/raw_tot)*100.0:0)<<"\n";
    return fail==0?0:1;
}