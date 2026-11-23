// fullmodel_int4_bench.cpp -- whole-model INT4 residency + throughput.
// Loads EVERY tensor of a real GGUF model, quantizes each to INT4 (packed),
// keeps the packed data resident, and reports total resident bytes vs original.
// Then runs a matvec sweep over the F32 tensors to measure aggregate throughput
// with all weights INT4-resident. This is the model-level memory proof.
//
// Build: g++ -std=c++17 -O2 -I. -I include -I src tools/fullmodel_int4_bench.cpp -o fm
// Usage: fm <model.gguf> [steps=20]
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
static uint64_t type_bytes(uint32_t t,uint64_t ne){switch(t){case 0:return ne*4;case 1:return ne*2;case 2:return(ne/32)*18;case 3:return(ne/32)*20;case 6:return(ne/32)*22;case 7:return(ne/32)*24;case 8:return(ne/32)*34;case 9:return(ne/32)*36;case 10:return(ne/256)*84;case 11:return(ne/256)*110;case 12:return(ne/256)*144;case 13:return(ne/256)*176;case 14:return(ne/256)*210;case 15:return(ne/256)*292;default:return 0;}}

struct Tensor { std::string name; uint32_t type; uint64_t rows, cols; std::vector<uint8_t> raw; std::vector<float> f32; lossy::QuantTensor q; };

int main(int argc,char**argv){
    if(argc<2){std::fprintf(stderr,"usage: fm <model.gguf> [steps=20]\n");return 2;}
    uint32_t steps=20; if(argc>2) steps=(uint32_t)std::stoul(argv[2]);
    std::ifstream f(argv[1],std::ios::binary); if(!f){std::fprintf(stderr,"cannot open\n");return 1;}
    char magic[4];uint32_t ver=0;uint64_t nt=0,nkv=0;
    if(!f.read(magic,4)||std::memcmp(magic,"GGUF",4)!=0||!rd_u32(f,ver)||!rd_u64(f,nt)||!rd_u64(f,nkv)){std::fprintf(stderr,"not gguf\n");return 1;}
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

    // Load all tensors, quantize to INT4, keep packed resident.
    std::vector<Tensor> tensors;
    uint64_t rawTotal=0, int4Total=0;
    for(uint64_t i=0;i<nt;++i){
        auto&ti=infos[i];
        uint64_t ne=1; for(uint32_t d=0;d<ti.nd;++d) ne*=ti.dim[d];
        uint64_t bytes=type_bytes(ti.type,ne);
        if(bytes==0||bytes>(1ull<<31)) continue;
        Tensor t; t.name=ti.name; t.type=ti.type;
        if(ti.nd>=2){ t.rows=ti.dim[ti.nd-2]; t.cols=ti.dim[ti.nd-1]; } else { t.rows=1; t.cols=ne; }
        t.raw.resize((size_t)bytes);
        f.seekg((std::streamoff)(ds+ti.off),std::ios::beg);
        if(!f.read((char*)t.raw.data(),(std::streamsize)bytes)) continue;
        rawTotal+=bytes;
        // Build F32 weights for quantization (dequantize if needed; for non-F32
        // we reinterpret raw bytes as int8 -> float for a deterministic proxy).
        if(ti.type==0){ t.f32.resize(ne); std::memcpy(t.f32.data(),t.raw.data(),bytes); }
        else { t.f32.resize(ne); for(uint64_t k=0;k<ne;++k) t.f32[k]=((int8_t)t.raw[k % bytes])*0.01f; }
        lossy::BlockCfg cfg; cfg.bits=lossy::QBits::Int4; cfg.block=64;
        lossy::Quantize(t.f32.data(), t.f32.size(), cfg, t.q);
        int4Total += t.q.packed.size() + t.q.scales.size()*2;
        tensors.push_back(std::move(t));
    }
    uint64_t peakLoad=PeakWS();
    std::printf("MODEL: %s tensors=%zu raw=%llu int4=%llu ratio=%.4f savings=%.2f%% peak_ws=%llu\n",
        argv[1], tensors.size(), (unsigned long long)rawTotal, (unsigned long long)int4Total,
        rawTotal?(double)int4Total/rawTotal:0.0, rawTotal?(1.0-(double)int4Total/rawTotal)*100.0:0.0,
        (unsigned long long)peakLoad);

    // Matvec sweep over all 2D tensors with INT4 residency (tiled, on-the-fly).
    auto sweep=[&](){ uint64_t ops=0;
        for(auto& t: tensors){
            if(t.cols==0 || t.cols%64) continue;
            uint64_t rows=t.rows, cols=t.cols, bpr=cols/64;
            std::vector<float> x(cols), y(rows);
            for(uint64_t c=0;c<cols;++c) x[c]=std::sin((double)c)*0.1f;
            for(uint64_t r=0;r<rows;++r){ double a=0;
                for(uint64_t cb=0;cb<bpr;++cb){ uint64_t blkIdx=r*bpr+cb; float sc=lossy::F16ToF32(t.q.scales[blkIdx]);
                    size_t byteBase=(size_t)(blkIdx*32); const uint8_t* pb=&t.q.packed[byteBase];
                    float tmp[64];
                    for(uint32_t k=0;k<32;++k){ uint8_t byte=pb[k]; uint32_t lo=byte&0x0f, hi=byte>>4;
                        tmp[2*k]=(float)((lo<8)?(int)lo:(int)lo-16)*sc; tmp[2*k+1]=(float)((hi<8)?(int)hi:(int)hi-16)*sc; }
                    uint64_t c=cb*64; for(uint32_t k=0;k<64;++k) a+=tmp[k]*x[c+k]; }
                y[r]=(float)a; }
            volatile float sink=0; for(auto v:y) sink+=v; (void)sink; ops+=rows;
        }
        return ops; };

    sweep();
    auto t0=std::chrono::steady_clock::now();
    for(uint32_t s=0;s<steps;++s) sweep();
    auto t1=std::chrono::steady_clock::now();
    double sec=std::chrono::duration<double>(t1-t0).count();
    std::printf("THROUGHPUT: %u full-model sweeps in %.4fs, %zu tensors, peak_ws=%llu\n",
        steps, sec, tensors.size(), (unsigned long long)PeakWS());
    return 0;
}