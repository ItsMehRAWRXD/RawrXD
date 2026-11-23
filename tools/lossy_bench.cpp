// lossy_bench.cpp -- lossy quantization benchmark on REAL F32 GGUF tensors.
// Quantizes F32 tensors to INT8/INT4/INT2, reports reduction + quality
// (cosine similarity, relative MSE) vs the original F32.
// Build: g++ -std=c++17 -O2 -I. -I include -I src tools/lossy_bench.cpp -o lossy
// Usage: lossy <model.gguf> [max_tensors=N]
#include "src/deep2/LossyQuant.hpp"
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace rawrxd::lossy;

static bool rd_str(std::ifstream& f, std::string& s){ uint64_t n=0; if(!f.read((char*)&n,8))return false; if(n>(1u<<20))return false; s.resize((size_t)n); return f.read(s.data(),(std::streamsize)n).good(); }
static bool rd_u32(std::ifstream& f, uint32_t& v){ return f.read((char*)&v,4).good(); }
static bool rd_u64(std::ifstream& f, uint64_t& v){ return f.read((char*)&v,8).good(); }

int main(int argc, char** argv){
    if(argc<2){ std::cerr<<"usage: lossy <model.gguf> [max_tensors=N]\n"; return 2; }
    std::ifstream f(argv[1], std::ios::binary);
    if(!f){ std::cerr<<"cannot open\n"; return 1; }
    size_t maxT = 16; if(argc>2){ std::string a=argv[2]; if(a.rfind("max_tensors=",0)==0) maxT=std::stoul(a.substr(12)); }
    char magic[4]; uint32_t ver=0; uint64_t nt=0, nkv=0;
    if(!f.read(magic,4)||std::memcmp(magic,"GGUF",4)!=0||!rd_u32(f,ver)||!rd_u64(f,nt)||!rd_u64(f,nkv)){ std::cerr<<"not gguf\n"; return 1; }
    auto skip=[&](uint32_t vt)->bool{ auto sk=[&](uint64_t n){ return n<=(1ull<<32)&&f.seekg((std::streamoff)n,std::ios::cur).good(); };
        switch(vt){case 0:case 1:case 7:return sk(1);case 2:case 3:return sk(2);case 4:case 5:case 6:return sk(4);case 10:case 11:case 12:return sk(8);
        case 8:{std::string s;return rd_str(f,s);} case 9:{uint32_t at=0;uint64_t al=0;if(!rd_u32(f,at)||!rd_u64(f,al))return false;if(at==8){for(uint64_t i=0;i<al;++i){std::string s;if(!rd_str(f,s))return false;}return true;}
          uint64_t e=0;switch(at){case 0:case 1:case 7:e=1;break;case 2:case 3:e=2;break;case 4:case 5:case 6:e=4;break;case 10:case 11:case 12:e=8;break;default:return false;}return sk(al*e);}
        default:return false;}};
    for(uint64_t i=0;i<nkv;++i){std::string k;uint32_t vt=0;if(!rd_str(f,k)||!rd_u32(f,vt)||!skip(vt))return 1;}
    struct TI{std::string name;uint64_t dim[4];uint32_t nd;uint32_t type;uint64_t off;};
    std::vector<TI> infos(nt);
    for(uint64_t i=0;i<nt;++i){auto&t=infos[i];if(!rd_str(f,t.name)||!rd_u32(f,t.nd)||t.nd>4)return 1;for(uint32_t d=0;d<t.nd;++d)if(!rd_u64(f,t.dim[d]))return 1;if(!rd_u32(f,t.type)||!rd_u64(f,t.off))return 1;}
    uint64_t ds=((uint64_t)f.tellg()+31)&~31ull;

    // Only F32 tensors (type 0) are valid input for this lossy quantizer.
    size_t done=0; uint64_t rawTot=0, i4Tot=0, i2Tot=0, i8Tot=0;
    double cos4=0, cos2=0, mse4=0, mse2=0;
    for(uint64_t i=0;i<nt && done<maxT;++i){
        auto&t=infos[i];
        if(t.type!=0){ continue; } // F32 only
        uint64_t ne=1; for(uint32_t d=0;d<t.nd;++d) ne*=t.dim[d];
        uint64_t bytes=ne*4;
        std::vector<float> w(ne);
        f.seekg((std::streamoff)(ds+t.off), std::ios::beg);
        if(!f.read((char*)w.data(),(std::streamsize)bytes)) continue;

        BlockCfg cfg; cfg.bits=QBits::Int4; cfg.block=64;
        QuantTensor q4; Quantize(w.data(), w.size(), cfg, q4);
        auto d4 = Dequantize(q4); auto Q4 = Measure(w, d4);

        cfg.bits=QBits::Int2; QuantTensor q2; Quantize(w.data(), w.size(), cfg, q2);
        auto d2 = Dequantize(q2); auto Q2 = Measure(w, d2);

        cfg.bits=QBits::Int8; QuantTensor q8; Quantize(w.data(), w.size(), cfg, q8);

        uint64_t b4 = q4.packed.size()+q4.scales.size()*2;
        uint64_t b2 = q2.packed.size()+q2.scales.size()*2;
        uint64_t b8 = q8.packed.size()+q8.scales.size()*2;
        rawTot+=bytes; i4Tot+=b4; i2Tot+=b2; i8Tot+=b8;
        cos4+=Q4.cosine; cos2+=Q2.cosine; mse4+=Q4.rel_mse; mse2+=Q2.rel_mse;
        std::cout<<"OK "<<t.name<<" f32_bytes="<<bytes<<" int4="<<b4<<"("<<(double)b4/bytes<<")"
                 <<" int2="<<b2<<"("<<(double)b2/bytes<<") cos4="<<Q4.cosine<<" mse4="<<Q4.rel_mse
                 <<" cos2="<<Q2.cosine<<" mse2="<<Q2.rel_mse<<"\n";
        ++done;
    }
    size_t n = done ? done : 1;
    std::cout<<"SUMMARY f32_tensors="<<done
             <<" int4_ratio="<<(rawTot?(double)i4Tot/rawTot:0)<<" int4_savings_pct="<<(rawTot?(1.0-(double)i4Tot/rawTot)*100.0:0)
             <<" int2_ratio="<<(rawTot?(double)i2Tot/rawTot:0)<<" int2_savings_pct="<<(rawTot?(1.0-(double)i2Tot/rawTot)*100.0:0)
             <<" int8_ratio="<<(rawTot?(double)i8Tot/rawTot:0)
             <<" avg_cos_int4="<<(cos4/n)<<" avg_mse_int4="<<(mse4/n)
             <<" avg_cos_int2="<<(cos2/n)<<" avg_mse_int2="<<(mse2/n)<<"\n";
    return 0;
}