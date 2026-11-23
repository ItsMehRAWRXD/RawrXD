// avwm_bench.cpp -- compare mmap-style full model load vs AVWM bounded
// compressed residency. Measures peak PHYSICAL RAM (Total-Avail) for each,
// proving whether AVWM actually reduces resident weight memory vs mmap.
//
// Build: g++ -std=c++17 -O2 -I. -I include -I src tools/avwm_bench.cpp -lz -o avwm
// Usage: avwm <model.gguf> <mode:mmap|avwm> [decode_budget_mb=128]
#include "deep2/AdaptiveVirtualWeightMemory.hpp"
#include "deep2/TensorAwareLosslessV2.hpp"
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#ifdef _WIN32
#include <windows.h>
static uint64_t TotalPhys(){ MEMORYSTATUSEX m; m.dwLength=sizeof(m); GlobalMemoryStatusEx(&m); return (uint64_t)m.ullTotalPhys; }
static uint64_t AvailPhys(){ MEMORYSTATUSEX m; m.dwLength=sizeof(m); GlobalMemoryStatusEx(&m); return (uint64_t)m.ullAvailPhys; }
#else
static uint64_t TotalPhys(){ return 0; } static uint64_t AvailPhys(){ return 0; }
#endif

using namespace rawrxd::weights;
namespace avwm = rawrxd::avwm;

static bool rd_str(std::ifstream& f,std::string& s){uint64_t n=0;if(!f.read((char*)&n,8))return false;if(n>(1u<<20))return false;s.resize((size_t)n);return f.read(s.data(),(std::streamsize)n).good();}
static bool rd_u32(std::ifstream& f,uint32_t& v){return f.read((char*)&v,4).good();}
static bool rd_u64(std::ifstream& f,uint64_t& v){return f.read((char*)&v,8).good();}
static uint64_t type_bytes(uint32_t t,uint64_t ne){switch(t){case 0:return ne*4;case 1:return ne*2;case 2:return(ne/32)*18;case 3:return(ne/32)*20;case 6:return(ne/32)*22;case 7:return(ne/32)*24;case 8:return(ne/32)*34;case 9:return(ne/32)*36;case 10:return(ne/256)*84;case 11:return(ne/256)*110;case 12:return(ne/256)*144;case 13:return(ne/256)*176;case 14:return(ne/256)*210;case 15:return(ne/256)*292;default:return 0;}}

int main(int argc,char**argv){
    if(argc<3){std::fprintf(stderr,"usage: avwm <model.gguf> <mmap|avwm> [budget_mb=128]\n");return 2;}
    std::string path=argv[1], mode=argv[2];
    size_t budgetMB = argc>3 ? std::stoul(argv[3]) : 128;
    uint64_t baseAvail = AvailPhys();

    std::ifstream f(path,std::ios::binary); if(!f){std::fprintf(stderr,"cannot open\n");return 1;}
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

    if(mode=="mmap"){
        // Baseline: load all tensor bytes into RAM (simulates mmap full residency).
        std::vector<std::vector<uint8_t>> raw;
        uint64_t total=0;
        for(uint64_t i=0;i<nt;++i){ auto&ti=infos[i]; uint64_t ne=1; for(uint32_t d=0;d<ti.nd;++d)ne*=ti.dim[d]; uint64_t bytes=type_bytes(ti.type,ne); if(bytes==0||bytes>(1ull<<31))continue;
            std::vector<uint8_t> buf(bytes); f.seekg((std::streamoff)(ds+ti.off),std::ios::beg); if(!f.read((char*)buf.data(),bytes))continue; total+=bytes; raw.push_back(std::move(buf)); }
        uint64_t peak = TotalPhys()-AvailPhys();
        volatile uint8_t s=0; for(auto&r:raw) for(auto b:r) s^=b; (void)s;
        uint64_t after = TotalPhys()-AvailPhys();
        std::printf("MODE=mmap tensors=%zu raw_bytes=%llu used_before=%llu used_after=%llu delta=%llu peak_delta=%llu\n",
            raw.size(),(unsigned long long)total,(unsigned long long)(TotalPhys()-baseAvail)/1024/1024,
            (unsigned long long)(TotalPhys()-AvailPhys())/1024/1024,
            (unsigned long long)((TotalPhys()-AvailPhys())-(TotalPhys()-baseAvail))/1024/1024,
            (unsigned long long)(peak-baseAvail)/1024/1024);
    } else {
        // AVWM: build compressed blocks, keep compressed store + bounded decode cache.
        avwm::WeightResidencyManager avwmgr;
        avwmgr.setDecodeBudget(budgetMB*1024*1024);
        uint64_t rawTotal=0, compTotal=0;
        // Quant block bytes per GGUF type (for V2 alignment).
        auto quantBlockBytes = [](uint32_t t)->uint32_t{
            switch(t){case 2:return 18;case 3:return 20;case 6:return 22;case 7:return 24;case 8:return 34;case 9:return 36;
            case 10:return 84;case 11:return 110;case 12:return 144;case 13:return 176;case 14:return 210;case 15:return 292;default:return 0;}
        };
        for(uint64_t i=0;i<nt;++i){ auto&ti=infos[i]; uint64_t ne=1; for(uint32_t d=0;d<ti.nd;++d)ne*=ti.dim[d]; uint64_t bytes=type_bytes(ti.type,ne); if(bytes==0||bytes>(1ull<<31))continue;
            std::vector<uint8_t> buf(bytes); f.seekg((std::streamoff)(ds+ti.off),std::ios::beg); if(!f.read((char*)buf.data(),bytes))continue;
            avwm::TensorBlocks tb; tb.name=ti.name; tb.type=ti.type; tb.raw_bytes=bytes;
            uint32_t qb = quantBlockBytes(ti.type);
            bool packed = (qb != 0);
            // Choose a V2-compatible block size (multiple of the quant block bytes)
            // so each chunk is an independent, decompressable V2 unit.
            uint32_t blk = 0;
            if(packed && bytes % qb == 0){
                blk = (uint32_t)std::min<uint64_t>(65536, bytes);
                // round down to a multiple of qb
                blk = (blk / qb) * qb; if(blk==0) blk=qb;
            }
            tb.block_size = blk ? blk : 4096;
            if(packed && blk){
                for(uint64_t off=0; off<bytes; off+=blk){ uint32_t len=(uint32_t)std::min<uint64_t>(blk,bytes-off);
                    avwm::CompressedBlock cb; cb.raw_offset=off; cb.raw_len=len;
                    try{ auto e=v2::EncodeV2(buf.data()+off,len,ti.type); auto w=v2::SerializeV2(e);
                         if(w.size()<len){ cb.codec=1; cb.payload=std::move(w);} else { cb.codec=0; cb.payload.assign(buf.begin()+off,buf.begin()+off+len);} }
                    catch(...){ cb.codec=0; cb.payload.assign(buf.begin()+off,buf.begin()+off+len); }
                    compTotal += cb.payload.size(); tb.blocks.push_back(std::move(cb));
                }
            } else {
                for(uint64_t off=0; off<bytes; off+=4096){ uint32_t len=(uint32_t)std::min<uint64_t>(4096,bytes-off);
                    avwm::CompressedBlock cb; cb.raw_offset=off; cb.raw_len=len; cb.codec=0; cb.payload.assign(buf.begin()+off,buf.begin()+off+len);
                    compTotal += cb.payload.size(); tb.blocks.push_back(std::move(cb));
                }
            }
            rawTotal+=bytes; avwmgr.addTensor(std::move(tb));
        }
        // touch all tensors once (forces compressed store resident + decode cache activity)
        for(uint64_t i=0;i<nt && i<infos.size();++i){ auto&ti=infos[i]; auto lease=avwmgr.acquire(ti.name,0,4096); volatile uint8_t s=0; std::vector<uint8_t> tmp(4096); if(lease.read(0,4096,tmp.data())) for(auto b:tmp) s^=b; (void)s; }
        auto st = avwmgr.stats();
        uint64_t usedAfter = (TotalPhys()-AvailPhys());
        std::printf("MODE=avwm tensors=%zu raw_bytes=%llu compressed_bytes=%llu ratio=%.4f budget_mb=%zu\n",
            (size_t)st.tensors,(unsigned long long)rawTotal,(unsigned long long)compTotal,
            rawTotal?(double)compTotal/rawTotal:0.0, budgetMB);
        std::printf("  decode_resident=%llu peak=%llu hits=%llu misses=%llu evictions=%llu decode_us=%llu\n",
            (unsigned long long)st.decode_resident,(unsigned long long)st.decode_peak,
            (unsigned long long)st.hits,(unsigned long long)st.misses,
            (unsigned long long)st.evictions,(unsigned long long)st.decode_us);
        std::printf("  used_after_MB=%llu delta_vs_base_MB=%llu\n",
            (unsigned long long)usedAfter/1024/1024,
            (unsigned long long)(usedAfter-(TotalPhys()-baseAvail))/1024/1024);
    }
    return 0;
}