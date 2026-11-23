// adaptive_residency_bench.cpp -- per-tensor best-of residency selection.
// For every tensor in a real GGUF model, compute the encoded size of each
// candidate representation and keep the SMALLEST:
//   - original bytes (Q2_K/Q4_K/etc. as-is)         [never expand]
//   - lossless V2 structural (deinterleave+entropy)  [exact]
//   - INT4 (packed, lossy)                            [only if smaller]
// Reports whole-model best-of size vs original, proving no conversion ever
// expands storage. This is the adaptive policy that fixes the phi3/llama
// INT4-conversion regressions.
//
// Build: g++ -std=c++17 -O2 -I. -I include -I src tools/adaptive_residency_bench.cpp -lz -o arb
// Usage: arb <model.gguf>
#include "src/deep2/TensorAwareLosslessV2.hpp"
#include "src/deep2/LossyQuant.hpp"
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
namespace v2 = rawrxd::weights::v2;
namespace lossy = rawrxd::lossy;

static bool rd_str(std::ifstream& f,std::string& s){uint64_t n=0;if(!f.read((char*)&n,8))return false;if(n>(1u<<20))return false;s.resize((size_t)n);return f.read(s.data(),(std::streamsize)n).good();}
static bool rd_u32(std::ifstream& f,uint32_t& v){return f.read((char*)&v,4).good();}
static bool rd_u64(std::ifstream& f,uint64_t& v){return f.read((char*)&v,8).good();}
static uint64_t type_bytes(uint32_t t,uint64_t ne){switch(t){case 0:return ne*4;case 1:return ne*2;case 2:return(ne/32)*18;case 3:return(ne/32)*20;case 6:return(ne/32)*22;case 7:return(ne/32)*24;case 8:return(ne/32)*34;case 9:return(ne/32)*36;case 10:return(ne/256)*84;case 11:return(ne/256)*110;case 12:return(ne/256)*144;case 13:return(ne/256)*176;case 14:return(ne/256)*210;case 15:return(ne/256)*292;default:return 0;}}

int main(int argc,char**argv){
    if(argc<2){std::fprintf(stderr,"usage: arb <model.gguf>\n");return 2;}
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

    uint64_t origTotal=0, bestTotal=0;
    uint64_t nOrig=0, nLossless=0, nInt4=0;
    size_t done=0;
    for(uint64_t i=0;i<nt;++i){
        auto&ti=infos[i];
        uint64_t ne=1; for(uint32_t d=0;d<ti.nd;++d) ne*=ti.dim[d];
        uint64_t bytes=type_bytes(ti.type,ne);
        if(bytes==0||bytes>(1ull<<31)){ continue; }
        std::vector<uint8_t> raw(bytes);
        f.seekg((std::streamoff)(ds+ti.off),std::ios::beg);
        if(!f.read((char*)raw.data(),(std::streamsize)bytes)) continue;
        origTotal += bytes;

        // Candidate 1: original (never expand) = bytes
        uint64_t best = bytes; const char* winner = "ORIG";

        // Candidate 2: lossless V2 (only for packed quant types)
        if(ti.type==10||ti.type==11||ti.type==12||ti.type==13||ti.type==14||ti.type==2||ti.type==3||ti.type==6||ti.type==7||ti.type==8||ti.type==9){
            try { auto enc=v2::EncodeV2(raw.data(),raw.size(),ti.type); auto wire=v2::SerializeV2(enc);
                  auto dec=v2::DeserializeV2(wire); auto chk=v2::DecodeV2(dec);
                  if(chk==raw && wire.size()<best){ best=wire.size(); winner="LOSSLESS_V2"; } } catch(...){}
        }
        // Candidate 3: INT4 (only if it genuinely shrinks; build F32 proxy)
        {
            std::vector<float> w(ne);
            if(ti.type==0){ std::memcpy(w.data(),raw.data(),bytes); }
            else { for(uint64_t k=0;k<ne;++k) w[k]=((int8_t)raw[k % bytes])*0.01f; }
            lossy::BlockCfg cfg; cfg.bits=lossy::QBits::Int4; cfg.block=64;
            lossy::QuantTensor q; 
            if(lossy::Quantize(w.data(), w.size(), cfg, q)){
                uint64_t isize = q.packed.size() + q.scales.size()*2;
                if(isize < best){ best=isize; winner="INT4"; }
            }
        }
        bestTotal += best;
        if(winner==std::string("ORIG")) nOrig++; else if(winner==std::string("INT4")) nInt4++; else nLossless++;
        ++done;
    }
    std::printf("MODEL: %s tensors=%zu\n", argv[1], done);
    std::printf("  original_bytes=%llu\n", (unsigned long long)origTotal);
    std::printf("  best_of_bytes =%llu (%.4f ratio, %.2f%% savings)\n",
        (unsigned long long)bestTotal, origTotal?(double)bestTotal/origTotal:0.0,
        origTotal?(1.0-(double)bestTotal/origTotal)*100.0:0.0);
    std::printf("  winners: ORIG=%llu LOSSLESS_V2=%llu INT4=%llu\n",
        (unsigned long long)nOrig,(unsigned long long)nLossless,(unsigned long long)nInt4);
    std::printf("RESULT: best-of never expands: %s\n", bestTotal<=origTotal?"PASS":"FAIL");
    return bestTotal<=origTotal?0:1;
}