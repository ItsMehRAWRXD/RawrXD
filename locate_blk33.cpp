// locate_blk33.cpp — RAWRXD_DEEPSEEK_BLK33_LOCATION_001
//
// Finds blk.33.ffn_gate_exps.weight by name across all shards, computes the
// shard-local absolute file offset (DATA_START + tensor.offset), verifies
// alignment and range containment, and dumps the four block headers.
//
// Correctness notes on this instrument:
//  * GGUF value types are 0-based per spec (8=STRING, 9=ARRAY with elem_type).
//  * Tensor offset validity is checked against general.alignment (default 32),
//    NOT against divisibility by the tensor's own size.
//  * Every fp16 field is decoded by explicit bit extraction with integer types,
//    never via PowerShell -bor (which coerces to the left operand's type).
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>

struct R {
    std::FILE* f = nullptr;
    uint64_t pos = 0;
    uint8_t  u8 () { uint8_t v; if(std::fread(&v,1,1,f)!=1) v=0; pos+=1; return v; }
    uint16_t u16(){ uint16_t v; if(std::fread(&v,2,1,f)!=1) v=0; pos+=2; return v; }
    uint32_t u32(){ uint32_t v; if(std::fread(&v,4,1,f)!=1) v=0; pos+=4; return v; }
    uint64_t u64(){ uint64_t v; if(std::fread(&v,8,1,f)!=1) v=0; pos+=8; return v; }
    std::string str(){ uint64_t n=u64(); std::string s; s.resize((size_t)n);
        if(n&&std::fread(&s[0],1,(size_t)n,f)!=(size_t)n) s.clear(); return s; }
    void skip(int64_t n){ if(std::fseek(f,(long)n,SEEK_CUR)==0) pos+=(uint64_t)n; }
};

static void skip_val(R& r, uint32_t t) {
    switch (t) {
        case 0: case 1: case 7: r.u8(); break;
        case 2: case 3:         r.u16(); break;
        case 4: case 5:         r.u32(); break;
        case 6: { uint32_t v; if(std::fread(&v,4,1,r.f)!=1) v=0; r.pos+=4; } break;
        case 8: r.str(); break;
        case 9: { uint32_t et=r.u32(); uint64_t n=r.u64();
                  int w=0;
                  switch(et){ case 0:case 1:case 7: w=1; break;
                              case 2:case 3: w=2; break;
                              case 4:case 5:case 6: w=4; break;
                              case 10:case 11:case 12: w=8; break;
                              case 8: { for(uint64_t i=0;i<n;i++) r.str(); } break;
                              default: break; }
                  if(w>0) r.skip((int64_t)(n*(uint64_t)w));
                  break; }
        case 10: case 11: r.u64(); break;
        case 12: { uint64_t v; if(std::fread(&v,8,1,r.f)!=1) v=0; r.pos+=8; } break;
        default: break;
    }
}

// fp16 -> fp64 by explicit integer bit manipulation.
static double fp16_to_f64(uint16_t h) {
    const int sign = (h >> 15) & 1;
    const int exp  = (h >> 10) & 0x1F;
    const int frac = h & 0x3FF;
    double v;
    if (exp == 0) {
        v = (frac == 0) ? 0.0 : (double)frac * 5.9604644775390625e-08; // 2^-24
    } else if (exp == 31) {
        // Report symbolically. Producing a real Inf/NaN here requires defeating
        // compile-time constant folding (C2124), and the decoded fp16 of a
        // NaN/Inf scale is a diagnostic string, not a number anyone compares.
        v = (frac == 0) ? (sign ? -999999.0 : 999999.0) : -888888.0;
    } else {
        v = (1.0 + (double)frac / 1024.0) * std::pow(2.0, (double)(exp - 15));
    }
    return sign ? -v : v;
}

static void dump32(R& r, uint64_t off, const char* label) {
    uint8_t b[32];
    if (std::fseek(r.f,(long)off,SEEK_SET)!=0) { std::printf("%s SEEK_FAIL\n",label); return; }
    if (std::fread(b,1,32,r.f)!=32) { std::printf("%s READ_FAIL\n",label); return; }
    std::printf("%s off=%llu hex=", label, (unsigned long long)off);
    for (int i=0;i<32;i++) std::printf("%02x", b[i]);
    const uint16_t d  = (uint16_t)(b[0] | (b[1]<<8));
    const uint16_t dm = (uint16_t)(b[2] | (b[3]<<8));
    std::printf("\n%s   d  bits=0x%04X  val=%.9g\n", label, d, fp16_to_f64(d));
    std::printf("%s   dmin bits=0x%04X val=%.9g\n", label, dm, fp16_to_f64(dm));
}

int main() {
    const char* target = "blk.33.ffn_gate_exps.weight";
    const char* dir = "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\";
    char path[512];
    int shardMatches = 0, totalTensors = 0;

    for (int s=1; s<=11; s++) {
        std::snprintf(path,sizeof(path),
            "%sDeepSeek-R1-Q4_K_M-%05d-of-00011.gguf", dir, s);
        R r; r.f = std::fopen(path,"rb");
        if (!r.f) { std::printf("SHARD %02d OPEN_FAIL\n", s); continue; }
        std::fseek(r.f,0,SEEK_END);
        uint64_t fsize = (uint64_t)_ftelli64(r.f);
        std::fseek(r.f,0,SEEK_SET); r.pos=0;

        char magic[4]; if(std::fread(magic,1,4,r.f)!=4){ std::fclose(r.f); continue; }
        r.pos=4;
        uint32_t ver = r.u32();
        uint64_t nTensors = r.u64();
        uint64_t nKV = r.u64();
        totalTensors += (int)nTensors;

        uint64_t splitNo=0, splitCount=0, splitTensorsCount=0, alignment=32;
        std::string arch;
        for (uint64_t i=0;i<nKV;i++) {
            std::string key = r.str();
            uint32_t vt = r.u32();
            if (key=="split.no"                && vt==4) { splitNo=r.u32(); continue; }
            if (key=="split.count"             && vt==4) { splitCount=r.u32(); continue; }
            if (key=="split.tensors.count"     && vt==4) { splitTensorsCount=r.u32(); continue; }
            if (key=="general.alignment"       && vt==4) { alignment=r.u32(); continue; }
            if (key=="general.architecture"     && vt==8) { arch=r.str(); continue; }
            skip_val(r, vt);
        }

        bool found=false; uint32_t tt=0; uint64_t toff=0, nel=0; uint32_t nd=0;
        uint64_t d0=0,d1=0,d2=0;
        for (uint64_t i=0;i<nTensors;i++) {
            std::string name = r.str();
            uint32_t dim = r.u32();
            std::vector<uint64_t> dims(dim);
            for (uint32_t j=0;j<dim;j++) dims[j]=r.u64();
            uint32_t type = r.u32();
            uint64_t off = r.u64();
            if (name == target) {
                found=true; tt=type; toff=off; nd=dim;
                if(dim>0)d0=dims[0]; if(dim>1)d1=dims[1]; if(dim>2)d2=dims[2];
                nel = (dim>0?dims[0]:1)*(dim>1?dims[1]:1)*(dim>2?dims[2]:1);
            }
        }
        uint64_t headerEnd = r.pos;
        uint64_t dataStart = (headerEnd + alignment - 1) / alignment * alignment;
        std::printf("SHARD %02d arch=%s split.no=%llu split.count=%llu "
                    "split.tensors.count=%llu localTensors=%llu alignment=%llu "
                    "headerEnd=%llu dataStart=%llu fileSize=%llu\n",
            s, arch.c_str(), (unsigned long long)splitNo, (unsigned long long)splitCount,
            (unsigned long long)splitTensorsCount, (unsigned long long)nTensors,
            (unsigned long long)alignment, (unsigned long long)headerEnd,
            (unsigned long long)dataStart, (unsigned long long)fsize);

        if (found) {
            ++shardMatches;
            const uint64_t rowStride   = (d0/256ull)*144ull;
            const uint64_t expertStride= rowStride * d1;
            const uint64_t tensorBytes = expertStride * d2;
            const uint64_t absOff      = dataStart + toff;
            const bool aligned = alignment ? (toff % alignment) == 0 : false;
            const bool fits = (absOff <= fsize) && (tensorBytes <= fsize - absOff);
            std::printf("\nTARGET_FOUND=1  TARGET=%s\n", target);
            std::printf("  SHARD=%02d SPLIT_NO=%llu\n", s, (unsigned long long)splitNo);
            std::printf("  TYPE=%u DIMS=%llu,%llu,%llu NEL=%llu\n",
                        tt,(unsigned long long)d0,(unsigned long long)d1,(unsigned long long)d2,
                        (unsigned long long)nel);
            std::printf("  ROW_STRIDE=%llu EXPERT_STRIDE=%llu TENSOR_BYTES=%llu\n",
                        (unsigned long long)rowStride,(unsigned long long)expertStride,
                        (unsigned long long)tensorBytes);
            std::printf("  DATA_START=%llu REL_OFF=%llu ABS_FILE_OFF=%llu\n",
                        (unsigned long long)dataStart,(unsigned long long)toff,
                        (unsigned long long)absOff);
            std::printf("  REL_OFF_ALIGNED=%d TENSOR_RANGE_IN_FILE=%d\n",
                        aligned?1:0, fits?1:0);
            std::printf("  RANGE_END=%llu\n", (unsigned long long)(absOff+tensorBytes));
            std::printf("\n");
            dump32(r, absOff,              "BASE_E0R0B0");
            dump32(r, absOff+144,          "BLOCK1_E0R0");
            dump32(r, absOff+rowStride,    "ROW1_E0");
            dump32(r, absOff+expertStride, "EXPERT1_R0B0");
        }
        std::fclose(r.f);
    }
    std::printf("\nSHARD_SCAN_COUNT=11 TARGET_MATCH_COUNT=%d TOTAL_TENSORS_SEEN=%d\n",
                shardMatches, totalTensors);
    return shardMatches==1 ? 0 : 1;
}