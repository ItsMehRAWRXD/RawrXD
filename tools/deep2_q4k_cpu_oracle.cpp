// ============================================================================
// deep2_q4k_cpu_oracle.cpp -- REC-05B independent numerical oracle
// ============================================================================
// Standalone CPU reference for the Deep2 tiled4x Q4_K GEMV kernel. NO GPU and
// NO Deep2/GPU arithmetic is used: Q4_K block decoding and the Q8_K activation
// quantization are transcribed independently from the authoritative ggml spec
// (get_scale_min_k4 / dequantize_row_q4_K) and the production shader's
// quantized-dot contract (q8InvScale = -127/maxValue, q8D = 1/q8InvScale,
// q8 = round(q8InvScale*x), acc += q8D*q8*w).
//
// Two references are produced per row:
//   * FP32 GEMV  : y = sum_col dequant_q4k(col) * x[col]      (math reference)
//   * Q4_K x Q8_K: y = sum_col (q8D*q8[col]) * dequant(col)   (production contract)
//
// Usage:
//   deep2_q4k_cpu_oracle <model.gguf> <tensor_name> <expert> <cols> <rows>
//                          <in.bin|-> <out_fp32.bin> <out_q8.bin> [--selftest]
// If in.bin is "-", a deterministic input x[col]=sin(col*0.01)+0.5*cos(col*0.37)
// is generated. Outputs are raw float32 arrays of length <rows>.
// ============================================================================
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <fstream>
#include <string>
#include <vector>

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifdef _WIN32
static inline int fseek64(FILE* f, int64_t o, int o2){ return _fseeki64(f,o,o2); }
#else
static inline int fseek64(FILE* f, int64_t o, int o2){ return fseek(f,(long)o,o2); }
#endif
static bool rd(FILE* f, void* d, size_t n){ return fread(d,1,n,f)==n; }
static uint64_t ru64(FILE* f){ uint64_t v=0; rd(f,&v,8); return v; }
static uint32_t ru32(FILE* f){ uint32_t v=0; rd(f,&v,4); return v; }
static std::string rs(FILE* f){ uint64_t n=ru64(f); std::string s(n,'\0'); if(n) rd(f,&s[0],n); return s; }

static bool skipVal(FILE* f, uint32_t t){
    switch(t){
        case 0: case 1: case 7: { uint8_t v; return rd(f,&v,1); }
        case 2: case 3: { uint16_t v; return rd(f,&v,2); }
        case 4: case 5: case 6: { uint32_t v; return rd(f,&v,4); }
        case 8: { uint64_t n=ru64(f); return fseek64(f,(int64_t)n,SEEK_CUR)==0; }
        case 9: { uint32_t et=ru32(f); uint64_t n=ru64(f);
            if(et==8){ for(uint64_t i=0;i<n;++i){ uint64_t l=ru64(f); if(fseek64(f,(int64_t)l,SEEK_CUR)) return false; } return true; }
            size_t es=1; switch(et){case 0:case 1:case 7:es=1;break;case 2:case 3:es=2;break;case 4:case 5:case 6:es=4;break;case 10:case 11:case 12:es=8;break;default:return false;}
            return fseek64(f,(int64_t)(n*es),SEEK_CUR)==0; }
        case 10: case 11: case 12: { uint64_t v; return rd(f,&v,8); }
        default: return false;
    }
}

static float fp16(uint16_t h){
    uint32_t sign=(h>>15)&1, exp=(h>>10)&0x1f, mant=h&0x3ff;
    uint32_t f;
    if(exp==0){ if(mant==0) f=sign<<31; else { exp=127-15+1; while((mant&0x400)==0){ mant<<=1; --exp; } mant&=0x3ff; f=(sign<<31)|(exp<<23)|(mant<<13); } }
    else if(exp==0x1f) f=(sign<<31)|0x7f800000|(mant<<13);
    else f=(sign<<31)|((exp-15+127)<<23)|(mant<<13);
    float o; std::memcpy(&o,&f,4); return o;
}

// Authoritative ggml get_scale_min_k4 (6-bit packed scales/mins).
static inline void get_scale_min_k4(int j, const uint8_t* q, uint8_t& d, uint8_t& m){
    if(j<4){ d=q[j]&63; m=q[j+4]&63; }
    else { d=(q[j+4]&0xF)|((q[j-4]>>6)<<4); m=(q[j+4]>>4)|((q[j]>>6)<<4); }
}

// Decode one 144-byte Q4_K block into 256 float weights.
static void dequant_q4k_block(const uint8_t* b, float* y){
    const float d=fp16((uint16_t)(b[0]|(b[1]<<8)));
    const float mn=fp16((uint16_t)(b[2]|(b[3]<<8)));
    const uint8_t* sc=b+4;   // 12 bytes
    const uint8_t* q=b+16;   // 128 bytes
    int is=0;
    for(int j=0;j<256;j+=64){
        uint8_t s0,m0,s1,m1; get_scale_min_k4(is+0,sc,s0,m0);
        const float d1=d*s0, m1f=mn*m0;
        get_scale_min_k4(is+1,sc,s1,m1); const float d2=d*s1, m2f=mn*m1;
        for(int l=0;l<32;++l) *y++=d1*(q[l]&0xF)-m1f;
        for(int l=0;l<32;++l) *y++=d2*(q[l]>>4)-m2f;
        q+=32; is+=2;
    }
}

// Replicate the shader's round-to-nearest via the 12582912 magic constant.
static inline int round_q8(float v){
    float magic=v+12582912.0f; int32_t bits; std::memcpy(&bits,&magic,4);
    return (bits&0x007fffff)-0x00400000;
}

int main(int argc, char** argv){
    if(argc>=2 && std::strcmp(argv[1],"--selftest")==0){
        // Known-answer: an all-zero block (d=0,dmin=0) must decode to 0.
        uint8_t blk[144]; std::memset(blk,0,sizeof(blk));
        float y[256]; dequant_q4k_block(blk,y);
        double s=0; for(float v:y) s+=v;
        std::printf("SELFTEST zero_block_sum=%.1f %s\n", s, (s==0.0?"PASS":"FAIL"));
        // Round-trip of the q8 magic rounding on a known value.
        int r=round_q8(1.0f); std::printf("SELFTEST round_q8(1.0)=%d %s\n", r, (r==1?"PASS":"FAIL"));
        return (s==0.0 && r==1)?0:1;
    }
    if(argc<9){ std::fprintf(stderr,"usage: %s <model.gguf> <tensor> <expert> <cols> <rows> <in.bin|-> <out_fp32.bin> <out_q8.bin>\n",argv[0]); return 2; }
    const char* model=argv[1]; const char* tname=argv[2];
    uint32_t expert=(uint32_t)std::strtoul(argv[3],nullptr,10);
    uint64_t cols=std::strtoull(argv[4],nullptr,10);
    uint64_t rows=std::strtoull(argv[5],nullptr,10);
    const char* inPath=argv[6]; const char* outFp=argv[7]; const char* outQ8=argv[8];

    FILE* f=std::fopen(model,"rb"); if(!f){ std::fprintf(stderr,"open fail\n"); return 2; }
    char magic[4]; if(!rd(f,magic,4)||std::memcmp(magic,"GGUF",4)){ std::fprintf(stderr,"not gguf\n"); return 2; }
    uint32_t ver=ru32(f); uint64_t nT=ru64(f), nM=ru64(f); uint64_t align=32;
    for(uint64_t i=0;i<nM;++i){ std::string k=rs(f); uint32_t t=ru32(f);
        if(k=="general.alignment"&&t==4){ uint32_t v; rd(f,&v,4); align=v; }
        else if(!skipVal(f,t)){ std::fprintf(stderr,"meta fail\n"); return 2; } }
    struct T{ std::string name; std::vector<int64_t> dims; uint32_t type; uint64_t off; } tgt; bool found=false;
    for(uint64_t i=0;i<nT;++i){ std::string name=rs(f); uint32_t nd=ru32(f); T t; t.name=name; t.dims.resize(nd);
        for(uint32_t d=0;d<nd;++d) t.dims[d]=(int64_t)ru64(f); t.type=ru32(f); t.off=ru64(f); if(name==tname){ tgt=t; found=true; } }
    if(!found){ std::fprintf(stderr,"tensor not found\n"); return 2; }
    uint64_t dataStart=((uint64_t)std::ftell(f)+align-1)/align*align;
    if(tgt.type!=12){ std::fprintf(stderr,"tensor type %u is not Q4_K\n",tgt.type); return 2; }
    // Row geometry: contiguous dim is dims[0]; rows are the product of dims[1..].
    uint64_t rowBytes=((cols+255)/256)*144;
    std::vector<uint8_t> block(144); std::vector<float> w(256);
    std::vector<float> x(cols);
    if(std::strcmp(inPath,"-")==0){ for(uint64_t c=0;c<cols;++c) x[c]=(float)std::sin((double)c*0.01)+0.5f*(float)std::cos((double)c*0.37); }
    else { std::ifstream in(inPath,std::ios::binary); in.read((char*)x.data(),cols*sizeof(float)); if(!in){ std::fprintf(stderr,"input read fail\n"); return 2; } }

    std::ofstream ofp(outFp,std::ios::binary|std::ios::trunc), oq8(outQ8,std::ios::binary|std::ios::trunc);
    if(!ofp||!oq8){ std::fprintf(stderr,"out open fail\n"); return 2; }
    uint64_t nonfinite=0;
    for(uint64_t r=0;r<rows;++r){
        // Q8_K activation quantization (shader contract), shared across rows.
        float amax=0, maxv=0;
        for(uint64_t c=0;c<cols;++c){ float a=std::fabs(x[c]); if(a>amax){ amax=a; maxv=x[c]; } }
        float q8Inv=0, q8D=0;
        if(amax!=0){ q8Inv=-127.0f/maxv; q8D=1.0f/q8Inv; }
        std::vector<int> q8(cols);
        for(uint64_t c=0;c<cols;++c){ int v=0; if(q8Inv!=0) v=round_q8(q8Inv*x[c]+12582912.0f); v=std::max(-127,std::min(127,v)); q8[c]=v; }
        uint64_t base=dataStart+tgt.off+r*rowBytes;
        double accFp=0, accQ8=0;
        for(uint64_t blk=0;blk<cols;blk+=256){
            if(fseek64(f,(int64_t)(base+(blk/256)*144),SEEK_SET)){ std::fprintf(stderr,"seek fail\n"); return 2; }
            if(!rd(f,block.data(),144)){ std::fprintf(stderr,"read fail\n"); return 2; }
            dequant_q4k_block(block.data(),w.data());
            for(int l=0;l<256;++l){ uint64_t c=blk+l; if(c>=cols) break; accFp+=(double)w[l]*x[c]; accQ8+=(double)q8D*q8[c]*w[l]; }
        }
        float yfp=(float)accFp, yq8=(float)accQ8;
        if(!std::isfinite(yfp)||!std::isfinite(yq8)) ++nonfinite;
        ofp.write((char*)&yfp,4); oq8.write((char*)&yq8,4);
    }
    ofp.close(); oq8.close(); std::fclose(f);
    std::printf("ORACLE tensor=%s type=Q4_K expert=%u cols=%llu rows=%llu nonfinite=%llu\n",tname,expert,(unsigned long long)cols,(unsigned long long)rows,(unsigned long long)nonfinite);
    return nonfinite?1:0;
}