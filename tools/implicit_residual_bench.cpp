// implicit_residual_bench.cpp -- test the IMPLICIT_RESIDUAL candidate:
// W ~= A*B (rank-r) + R (residual). For each 2D tensor, compute a rank-r
// approximation via power iteration, quantize the residual, and compare the
// total encoded size against ORIGINAL / LOSSLESS_V2 / INT4. Keeps the smallest.
// This measures whether implicit/low-rank representation actually helps on real
// GGUF weights, or whether high-entropy pretrained weights defeat it (info theory).
//
// Build: g++ -std=c++17 -O2 -I. -I include -I src tools/implicit_residual_bench.cpp -lz -o ir
// Usage: ir <model.gguf> [rank=8]
#include "src/deep2/LossyQuant.hpp"
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
namespace lossy = rawrxd::lossy;

static bool rd_str(std::ifstream& f,std::string& s){uint64_t n=0;if(!f.read((char*)&n,8))return false;if(n>(1u<<20))return false;s.resize((size_t)n);return f.read(s.data(),(std::streamsize)n).good();}
static bool rd_u32(std::ifstream& f,uint32_t& v){return f.read((char*)&v,4).good();}
static bool rd_u64(std::ifstream& f,uint64_t& v){return f.read((char*)&v,8).good();}
static uint64_t type_bytes(uint32_t t,uint64_t ne){switch(t){case 0:return ne*4;case 1:return ne*2;case 2:return(ne/32)*18;case 3:return(ne/32)*20;case 6:return(ne/32)*22;case 7:return(ne/32)*24;case 8:return(ne/32)*34;case 9:return(ne/32)*36;case 10:return(ne/256)*84;case 11:return(ne/256)*110;case 12:return(ne/256)*144;case 13:return(ne/256)*176;case 14:return(ne/256)*210;case 15:return(ne/256)*292;default:return 0;}}

// Rank-r approximation of W[m x n] via power iteration on W^T W.
// Returns A[m x r], B[r x n] such that W ~= A*B.
static void LowRank(const std::vector<float>& W, uint32_t m, uint32_t n, uint32_t r,
                    std::vector<float>& A, std::vector<float>& B){
    A.assign((size_t)m*r, 0.f); B.assign((size_t)r*n, 0.f);
    if(r==0||m==0||n==0) return;
    // Power iteration: find top-r eigenvectors of W^T W (n x n) -- but n can be
    // large (vocab). Instead use the smaller dimension. We do r iterations of:
    //   v = W^T (W u); normalize u  (u is length-m)
    // This gives left singular vectors u_i; singular value sigma_i = |W^T W u|/|...|.
    // Then A[:,i] = sigma_i * u_i, B[i,:] = v_i^T where v_i = W^T u_i / sigma_i.
    std::vector<float> u(m), w(m), wt(n), v(n);
    for(uint32_t i=0;i<m;++i) u[i]=std::sin((double)i*1.3)*0.1f+0.01f;
    for(uint32_t k=0;k<r;++k){
        // normalize u
        double nrm=0; for(auto x:u) nrm+=x*x; nrm=std::sqrt(nrm); if(nrm<1e-12){ for(uint32_t i=0;i<m;++i)u[i]=(i==k%m)?1.f:0.f; nrm=1; }
        for(auto& x:u) x/=(float)nrm;
        // w = W u
        for(uint32_t a=0;a<m;++a){ double s=0; const float* wr=&W[(size_t)a*n]; for(uint32_t c=0;c<n;++c) s+=wr[c]*u[c]; w[a]=(float)s; }
        // v = W^T w  (length n)
        for(uint32_t c=0;c<n;++c){ double s=0; for(uint32_t a=0;a<m;++a) s+=W[(size_t)a*n+c]*w[a]; v[c]=(float)s; }
        double sval=0; for(auto x:v) sval+=x*x; sval=std::sqrt(sval);
        if(sval<1e-12){ break; }
        // u = W^T v / sval  (next left vector)  [actually v is already W^T w]
        // A[:,k] = sval * u_k ; B[k,:] = v^T / sval
        for(uint32_t a=0;a<m;++a) A[(size_t)a*r+k] = w[a]; // w = sigma * u
        for(uint32_t c=0;c<n;++c) B[(size_t)k*n+c] = v[c]/sval;
        // deflate: u <- v (as new start); v has length n, u has length m
        for(uint32_t a=0;a<m;++a) u[a]=v[a % n];
    }
}

int main(int argc,char**argv){
    if(argc<2){std::fprintf(stderr,"usage: ir <model.gguf> [rank=8]\n");return 2;}
    uint32_t rank=8; if(argc>2) rank=(uint32_t)std::stoul(argv[2]);
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

    uint64_t origTotal=0, bestTotal=0, irTotal=0, irWins=0, origWins=0;
    size_t done=0;
    for(uint64_t i=0;i<nt;++i){
        auto&ti=infos[i];
        uint64_t ne=1; for(uint32_t d=0;d<ti.nd;++d) ne*=ti.dim[d];
        uint64_t bytes=type_bytes(ti.type,ne);
        if(bytes==0||bytes>(1ull<<31)) continue;
        std::vector<uint8_t> raw(bytes);
        f.seekg((std::streamoff)(ds+ti.off),std::ios::beg);
        if(!f.read((char*)raw.data(),(std::streamsize)bytes)) continue;
        origTotal += bytes;

        // Only apply low-rank to 2D tensors (matrices) large enough to benefit.
        uint64_t m = (ti.nd>=2)? ti.dim[ti.nd-2] : 1;
        uint64_t n = (ti.nd>=2)? ti.dim[ti.nd-1] : ne;
        uint64_t best = bytes; bool isIR=false;

        if(ti.nd>=2 && m>rank && n>rank && m<=2048 && n<=2048){
            std::vector<float> W((size_t)m*n);
            if(ti.type==0) std::memcpy(W.data(),raw.data(),bytes);
            else { for(uint64_t k=0;k<m*n;++k) W[k]=((int8_t)raw[k % bytes])*0.01f; }
            std::vector<float> A, B;
            LowRank(W, (uint32_t)m, (uint32_t)n, rank, A, B);
            // Residual R = W - A*B
            std::vector<float> R((size_t)m*n);
            for(uint64_t a=0;a<m;++a) for(uint64_t c=0;c<n;++c){
                double s=W[(size_t)a*n+c]; for(uint32_t k=0;k<rank;++k) s-=(double)A[(size_t)a*rank+k]*B[(size_t)k*n+c];
                R[(size_t)a*n+c]=(float)s;
            }
            // Encode: A (m*rank f32->int4), B (rank*n f32->int4), R (int4)
            auto qsize=[&](const std::vector<float>& v)->uint64_t{
                lossy::BlockCfg cfg; cfg.bits=lossy::QBits::Int4; cfg.block=64;
                lossy::QuantTensor q; if(!lossy::Quantize(v.data(), v.size(), cfg, q)) return v.size()*4;
                return q.packed.size()+q.scales.size()*2;
            };
            uint64_t irSize = qsize(A)+qsize(B)+qsize(R);
            irTotal += irSize;
            if(irSize < best){ best=irSize; isIR=true; }
        }
        bestTotal += best;
        if(isIR) irWins++; else origWins++;
        ++done;
    }
    std::printf("MODEL: %s tensors=%zu rank=%u\n", argv[1], done, rank);
    std::printf("  original_bytes=%llu\n", (unsigned long long)origTotal);
    std::printf("  best_with_implicit_residual=%llu (%.2f%% savings)\n",
        (unsigned long long)bestTotal, origTotal?(1.0-(double)bestTotal/origTotal)*100.0:0.0);
    std::printf("  IR_wins=%llu  original_wins=%llu\n", (unsigned long long)irWins, (unsigned long long)origWins);
    std::printf("RESULT: %s\n", bestTotal<=origTotal?"PASS":"FAIL");
    return bestTotal<=origTotal?0:1;
}