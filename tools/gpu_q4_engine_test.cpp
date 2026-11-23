// gpu_q4_engine_test.cpp -- Stage 6K: prove Deep2Engine::gpuMatvecQ4 executes
// with REAL GGUF tensors. Creates a Deep2Engine, initializes Vulkan, extracts a
// real Q4_0/Q4_K tensor from the model, dispatches gpuMatvecQ4, and verifies
// against a CPU reference.
// Build: g++ -std=c++17 -O2 -I include -I src tools/gpu_q4_engine_test.cpp src/Deep2Engine.cpp src/VulkanDevice.cpp -o gqe -lvulkan-1
// Usage: gqe <model.gguf>
#include "Deep2Engine.hpp"
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// Read a full tensor's raw bytes from a GGUF (self-contained parser).
static bool ReadTensor(const std::string& path, const std::string& want,
                       std::vector<uint8_t>& out, uint32_t& outType, uint32_t& outRows, uint32_t& outCols) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    char magic[4]; uint32_t ver=0; uint64_t nt=0, nkv=0;
    auto rds=[&](auto& v){ return f.read((char*)&v, sizeof(v)).good(); };
    auto rdus=[&](std::string& s){ uint64_t n=0; if(!f.read((char*)&n,8))return false; s.resize((size_t)n); return f.read(s.data(),n).good(); };
    if(!f.read(magic,4)||std::memcmp(magic,"GGUF",4)!=0||!rds(ver)||!rds(nt)||!rds(nkv)) return false;
    auto skip=[&](uint32_t vt)->bool{ auto sk=[&](uint64_t n){ return f.seekg((std::streamoff)n,std::ios::cur).good(); };
        switch(vt){case 0:case 1:case 7:return sk(1);case 2:case 3:return sk(2);case 4:case 5:case 6:return sk(4);case 10:case 11:case 12:return sk(8);
        case 8:{std::string s;return rdus(s);}case 9:{uint32_t at=0;uint64_t al=0;if(!rds(at)||!rds(al))return false;if(at==8){for(uint64_t i=0;i<al;++i){std::string s;if(!rdus(s))return false;}return true;}
          uint64_t e=0;switch(at){case 0:case 1:case 7:e=1;break;case 2:case 3:e=2;break;case 4:case 5:case 6:e=4;break;case 10:case 11:case 12:e=8;break;default:return false;}return sk(al*e);}
        default:return false;}};
    uint32_t alignment = 32; // GGUF default; overridden by general.alignment
    for(uint64_t i=0;i<nkv;++i){
        std::string k; uint32_t vt=0;
        if(!rdus(k)||!rds(vt)) return false;
        if(k=="general.alignment" && vt==4){ uint32_t a=0; if(!rds(a)) return false; if(a>0) alignment=a; continue; }
        if(!skip(vt)) return false;
    }
    struct TI{std::string name;uint64_t dim[4];uint32_t nd;uint32_t type;uint64_t off;};
    std::vector<TI> infos(nt);
    for(uint64_t i=0;i<nt;++i){auto&t=infos[i];if(!rdus(t.name)||!rds(t.nd)||t.nd>4)return false;for(uint32_t d=0;d<t.nd;++d)if(!rds(t.dim[d]))return false;if(!rds(t.type)||!rds(t.off))return false;}
    // General alignment (works for any alignment, not just powers of two).
    uint64_t ds = ((uint64_t)f.tellg() + alignment - 1) / alignment * alignment;
    auto tb=[](uint32_t t,uint64_t ne)->uint64_t{switch(t){case 0:return ne*4;case 1:return ne*2;case 2:return(ne/32)*18;case 3:return(ne/32)*20;case 6:return(ne/32)*22;case 7:return(ne/32)*24;case 8:return(ne/32)*34;case 9:return(ne/32)*36;case 10:return(ne/256)*84;case 11:return(ne/256)*110;case 12:return(ne/256)*144;case 13:return(ne/256)*176;case 14:return(ne/256)*210;case 15:return(ne/256)*292;default:return 0;}};
    for(auto&t:infos){
        if(t.name.find(want)==std::string::npos) continue;
        if(t.nd != 2) continue; // only 2D matrices for unambiguous reference
        uint64_t ne=1; for(uint32_t d=0;d<t.nd;++d) ne*=t.dim[d];
        uint64_t bytes=tb(t.type,ne);
        if(bytes==0) continue;
        out.resize((size_t)bytes);
        f.seekg((std::streamoff)(ds+t.off),std::ios::beg);
        if(!f.read((char*)out.data(),bytes)) return false;
        outType=t.type;
        // GGUF stores dim[0]=fastest (in_features), dim[1]=out_features.
        // For a row-major [out][in] matvec: rows=out=dim[1], cols=in=dim[0].
        outCols=(uint32_t)t.dim[t.nd-2]; // in_features (fastest)
        outRows=(uint32_t)t.dim[t.nd-1]; // out_features
        return true;
    }
    return false;
}

// CPU reference: dequantize Q4_0/Q4_K + matvec.
#include "deep2/GgufQuantAdapter.hpp"
using namespace rawrxd::gguf;

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: gqe <model.gguf>\n"); return 2; }
    std::string model = argv[1];

    // Find a Q4_0 or Q4_K 2D tensor.
    for (const char* sub : {"attn_q", "attn_k", "attn_v", "ffn_gate", "ffn_up", "attn_output", "ffn_down"}) {
        std::vector<uint8_t> raw; uint32_t type=0, rows=0, cols=0;
        if (!ReadTensor(model, sub, raw, type, rows, cols)) continue;
        if (type != 2 && type != 12) continue; // Q4_0 or Q4_K only
        std::printf(" Found %s: type=%u rows=%u cols=%u bytes=%zu\n", sub, type, rows, cols, raw.size());

        // CPU reference dequant + matvec.
        std::vector<float> W;
        if (type == 2) DequantizeQ4_0(raw.data(), raw.size()/18, W);
        else DequantizeQ4_K(raw.data(), raw.size()/144, W);
        std::vector<float> x(cols); for (size_t i=0;i<cols;++i) x[i]=std::sin((double)i)*0.1f;
        std::vector<float> yCpu(rows);
        for (uint32_t r=0;r<rows;++r){ double a=0; const float* wr=&W[(size_t)r*cols]; for(uint32_t c=0;c<cols;++c) a+=(double)wr[c]*x[c]; yCpu[r]=(float)a; }

        // Deep2Engine + gpuMatvecQ4.
        Deep2Engine engine;
        if (!engine.Initialize(model)) { std::fprintf(stderr, "Deep2Engine init failed\n"); return 1; }
        std::vector<float> y(rows);
        bool ok = engine.gpuMatvecQ4(sub, raw.data(), raw.size(), x.data(), y.data(), rows, cols, type);
        double maxd=0; for(uint32_t r=0;r<rows;++r) maxd=std::max(maxd,(double)std::fabs(y[r]-yCpu[r]));
        std::printf("  gpuMatvecQ4 -> ok=%d maxDiff=%g %s\n", ok?1:0, maxd, (ok && maxd<1e-3)?"PASS":"FAIL");
        return (ok && maxd<1e-3) ? 0 : 1;
    }
    std::fprintf(stderr, "no Q4_0/Q4_K 2D tensor found\n");
    return 1;
}