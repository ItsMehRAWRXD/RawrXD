// int4_fused_bench.cpp -- combine BOTH advantages: INT4 resident (7.5x less
// memory) AND near-RAW speed, via a block-tiled INT4 matvec that decodes one
// 64-value block into a 256-byte stack buffer and then does 64 MACs from it.
// No full F32 weight matrix is materialized. Compares:
//   RAW        -- F32 matvec from a full F32 buffer (baseline, full memory)
//   INT4_NAIVE -- per-element dequant (slow: division/modulo per element)
//   INT4_TILED -- block-decode into stack buffer then dot (fast, low memory)
//
// Build: g++ -std=c++17 -O2 -I. -I include -I src tools/int4_fused_bench.cpp -o i4f
// Usage: i4f <model.gguf> [name_substr=attn_q] [steps=300]
#include "src/deep2/LossyQuant.hpp"
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace lossy = rawrxd::lossy;

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
static uint64_t PeakWS(){ PROCESS_MEMORY_COUNTERS p; if(GetProcessMemoryInfo(GetCurrentProcess(),&p,sizeof(p))) return (uint64_t)p.PeakWorkingSetSize; return 0; }
#else
static uint64_t PeakWS(){ return 0; }
#endif

static bool rd_str(std::ifstream& f,std::string& s){uint64_t n=0;if(!f.read((char*)&n,8))return false;if(n>(1u<<20))return false;s.resize((size_t)n);return f.read(s.data(),(std::streamsize)n).good();}
static bool rd_u32(std::ifstream& f,uint32_t& v){return f.read((char*)&v,4).good();}
static bool rd_u64(std::ifstream& f,uint64_t& v){return f.read((char*)&v,8).good();}

int main(int argc,char** argv){
    if(argc<2){ std::cerr<<"usage: i4f <model.gguf> [name_substr=attn_q] [steps=300]\n"; return 2; }
    std::string path=argv[1]; std::string sub="attn_q"; size_t steps=300;
    if(argc>2) sub=argv[2]; if(argc>3) steps=std::stoull(argv[3]);
    std::ifstream f(path,std::ios::binary); if(!f){std::cerr<<"cannot open\n";return 1;}
    char magic[4];uint32_t ver=0;uint64_t nt=0,nkv=0;
    if(!f.read(magic,4)||std::memcmp(magic,"GGUF",4)!=0||!rd_u32(f,ver)||!rd_u64(f,nt)||!rd_u64(f,nkv)){std::cerr<<"not gguf\n";return 1;}
    auto skip=[&](uint32_t vt)->bool{auto sk=[&](uint64_t n){return n<=(1ull<<32)&&f.seekg((std::streamoff)n,std::ios::cur).good();};
        switch(vt){case 0:case 1:case 7:return sk(1);case 2:case 3:return sk(2);case 4:case 5:case 6:return sk(4);case 10:case 11:case 12:return sk(8);
        case 8:{std::string s;return rd_str(f,s);}case 9:{uint32_t at=0;uint64_t al=0;if(!rd_u32(f,at)||!rd_u64(f,al))return false;if(at==8){for(uint64_t i=0;i<al;++i){std::string s;if(!rd_str(f,s))return false;}return true;}
          uint64_t e=0;switch(at){case 0:case 1:case 7:e=1;break;case 2:case 3:e=2;break;case 4:case 5:case 6:e=4;break;case 10:case 11:case 12:e=8;break;default:return false;}return sk(al*e);}
        default:return false;}};
    for(uint64_t i=0;i<nkv;++i){std::string k;uint32_t vt=0;if(!rd_str(f,k)||!rd_u32(f,vt)||!skip(vt))return 1;}
    struct TI{std::string name;uint64_t dim[4];uint32_t nd;uint32_t type;uint64_t off;};
    std::vector<TI> infos(nt);
    for(uint64_t i=0;i<nt;++i){auto&t=infos[i];if(!rd_str(f,t.name)||!rd_u32(f,t.nd)||t.nd>4)return 1;for(uint32_t d=0;d<t.nd;++d)if(!rd_u64(f,t.dim[d]))return 1;if(!rd_u32(f,t.type)||!rd_u64(f,t.off))return 1;}
    uint64_t ds=((uint64_t)f.tellg()+31)&~31ull;

    const TI* pick=nullptr;
    for(auto&t:infos){ if(t.nd==2 && t.name.find(sub)!=std::string::npos){ pick=&t; break; } }
    if(!pick){ std::cerr<<"no matching 2D matrix\n"; return 1; }
    uint64_t rows=pick->dim[0], cols=pick->dim[1];
    uint64_t bytes=rows*cols*(pick->type==0?4:1);
    std::vector<uint8_t> raw(bytes);
    f.seekg((std::streamoff)(ds+pick->off),std::ios::beg);
    if(!f.read((char*)raw.data(),(std::streamsize)bytes)){ std::cerr<<"read fail\n"; return 1; }

    std::vector<float> W(rows*cols);
    if(pick->type==0){ std::memcpy(W.data(),raw.data(),bytes); }
    else { for(size_t i=0;i<W.size();++i) W[i]=((raw[i%bytes]/255.0f)-0.5f)*0.02f; }
    std::vector<float> x(cols), yref(rows);
    for(size_t i=0;i<cols;++i) x[i]=std::sin((double)i)*0.1f;
    auto matvec_raw=[&](){ for(uint64_t r=0;r<rows;++r){ double a=0; const float* wr=&W[r*cols]; for(uint64_t c=0;c<cols;++c) a+=wr[c]*x[c]; yref[r]=(float)a; } };
    matvec_raw();

    // Quantize to INT4.
    lossy::BlockCfg cfg; cfg.bits=lossy::QBits::Int4; cfg.block=64;
    lossy::QuantTensor q; lossy::Quantize(W.data(), W.size(), cfg, q);
    const uint32_t blk=q.block;
    const uint64_t colsPerRow = cols/blk; // requires cols % 64 == 0
    if(cols % blk != 0){ std::cerr<<"cols not multiple of block ("<<cols<<"% "<<blk<<") -- tiled path needs alignment\n"; return 1; }

    // INT4 naive (per-element).
    auto matvec_naive=[&](){
        for(uint64_t r=0;r<rows;++r){ double a=0; uint64_t base=r*cols;
            for(uint64_t c=0;c<cols;++c){ uint64_t idx=base+c; uint32_t b=(uint32_t)(idx/blk);
                float scale=lossy::F16ToF32(q.scales[b]); size_t bi=(size_t)(idx>>1);
                uint32_t nib=(idx&1)?(q.packed[bi]>>4):(q.packed[bi]&0x0f); int v=(int)nib; if(v>=8)v-=16;
                a+=(float)v*scale*x[c]; }
            yref[r]=(float)a; }
    };

    // INT4 tiled: decode 64-value block into stack buffer, then 64 MACs.
    int8_t lut[16]; for(int i=0;i<16;++i) lut[i]=(int8_t)((i<8)?i:(i-16));
    auto matvec_tiled=[&](){
        float tmp[64];
        for(uint64_t r=0;r<rows;++r){ double a=0; uint64_t base=r*cols;
            for(uint64_t cb=0;cb<colsPerRow;++cb){
                uint64_t flat=(base/blk)+cb;
                float scale=lossy::F16ToF32(q.scales[flat]);
                size_t byteBase=(size_t)(flat*32);
                const uint8_t* pb=&q.packed[byteBase];
                for(uint32_t i=0;i<32;++i){ uint8_t byte=pb[i];
                    tmp[2*i]  =(float)lut[byte&0x0f]*scale;
                    tmp[2*i+1]=(float)lut[byte>>4]*scale; }
                uint64_t c=cb*64;
                for(uint32_t i=0;i<64;++i) a+=tmp[i]*x[c+i];
            }
            yref[r]=(float)a; }
    };

    auto bench=[&](const char* label, auto&& fn){
        fn(); fn(); uint64_t ws0=PeakWS();
        auto t0=std::chrono::steady_clock::now();
        for(size_t s=0;s<steps;++s) fn();
        auto t1=std::chrono::steady_clock::now();
        double sec=std::chrono::duration<double>(t1-t0).count();
        std::cout<<label<<" steps="<<steps<<" time_s="<<sec<<" matvec_per_s="<<(sec>0?steps/sec:0)<<" peak_ws_bytes="<<PeakWS()<<"\n";
    };

    bench("RAW       ", matvec_raw);
    bench("INT4_NAIVE", matvec_naive);
    bench("INT4_TILED", matvec_tiled);

    // Parity of tiled vs raw.
    matvec_raw(); std::vector<float> yr=yref; matvec_tiled();
    double maxd=0; for(uint64_t r=0;r<rows;++r) maxd=std::max(maxd,(double)std::fabs(yr[r]-yref[r]));
    std::cout<<"tiled_vs_raw_max_diff="<<maxd
             <<" int4_residency_bytes="<<(q.packed.size()+q.scales.size()*2)
             <<" f32_bytes="<<(W.size()*sizeof(float))
             <<" ratio="<<(double)(q.packed.size()+q.scales.size()*2)/(W.size()*sizeof(float))<<"\n";
    return 0;
}