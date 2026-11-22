// ============================================================================
// gguf_embd_row.cpp — Independent Q4_K GGUF embedding-row decoder.
//
// Reads a GGUF with CHECKED parsing (bounds-safe, correct string/array skip),
// locates token_embd.weight, and dequantizes one row using an INDEPENDENT
// scalar Q4_K decoder. Compares against a captured Deep2 embedding .f32.
// ============================================================================
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <string>
#include <vector>

namespace {

struct Reader {
    const uint8_t* data;
    size_t size;
    size_t pos = 0;
    bool ok = true;

    bool need(size_t n) {
        if (!ok || pos + n > size) { ok = false; return false; }
        return true;
    }
    uint16_t u16() { if (!need(2)) return 0; uint16_t v; std::memcpy(&v, data+pos, 2); pos += 2; return v; }
    uint32_t u32() { if (!need(4)) return 0; uint32_t v; std::memcpy(&v, data+pos, 4); pos += 4; return v; }
    uint64_t u64() { if (!need(8)) return 0; uint64_t v; std::memcpy(&v, data+pos, 8); pos += 8; return v; }
    bool skip(size_t n) { if (!need(n)) return false; pos += n; return true; }
    bool str(std::string& out) {
        uint64_t len = u64();
        if (!ok || len > (1ull<<32)) { ok = false; return false; }
        if (!need((size_t)len)) return false;
        out.assign((const char*)data + pos, (size_t)len);
        pos += (size_t)len;
        return true;
    }
};

// GGUF value types.
enum : uint32_t {
    T_UINT8=0, T_INT8=1, T_UINT16=2, T_INT16=3, T_UINT32=4, T_INT32=5,
    T_FLOAT32=6, T_BOOL=7, T_STRING=8, T_ARRAY=9, T_UINT64=10, T_INT64=11, T_FLOAT64=12
};

// Skip one metadata value. Works with any reader exposing u32/u64/str/skip.
template<class R>
bool skipValue(R& r, uint32_t type) {
    switch (type) {
        case T_UINT8: case T_INT8: case T_BOOL: return r.skip(1);
        case T_UINT16: case T_INT16: return r.skip(2);
        case T_UINT32: case T_INT32: case T_FLOAT32: return r.skip(4);
        case T_UINT64: case T_INT64: case T_FLOAT64: return r.skip(8);
        case T_STRING: { std::string s; return r.str(s); }
        case T_ARRAY: {
            uint32_t elemType = r.u32();
            uint64_t count = r.u64();
            if (!r.ok) return false;
            if (elemType == T_STRING) {
                for (uint64_t i = 0; i < count; ++i) { std::string s; if (!r.str(s)) return false; }
                return true;
            }
            if (elemType == T_ARRAY) return false;
            uint64_t esz = 0;
            switch (elemType) {
                case T_UINT8: case T_INT8: case T_BOOL: esz=1; break;
                case T_UINT16: case T_INT16: esz=2; break;
                case T_UINT32: case T_INT32: case T_FLOAT32: esz=4; break;
                case T_UINT64: case T_INT64: case T_FLOAT64: esz=8; break;
                default: return false;
            }
            if (count != 0 && esz > (uint64_t)(1ull<<40) / count) return false;
            return r.skip((uint64_t)(count * esz));
        }
        default: return false;
    }
}

struct TensorInfo {
    std::string name;
    uint32_t nDims = 0;
    uint64_t dims[4] = {0,0,0,0};
    uint32_t ggmlType = 0;
    uint64_t offset = 0;
    uint64_t bytes = 0;
};

// Q4_K block: 256 elements, 144 bytes.
void dequantQ4K(const uint8_t* b, float* out) {
    auto fp16 = [](uint16_t h) -> float {
        uint32_t sign=(h&0x8000)<<16, exp=(h>>10)&0x1F, mant=h&0x3FF, bits;
        if (exp==0) { if(mant==0) bits=sign; else { uint32_t e=0,m=mant; while(!(m&0x400)){m<<=1;++e;} m&=0x3FF; bits=sign|((127-15-e+1)<<23)|(m<<13); } }
        else if (exp==31) bits = sign|0x7F800000|(mant<<13);
        else bits = sign|((exp-15+127)<<23)|(mant<<13);
        float f; std::memcpy(&f,&bits,4); return f;
    };
    const float d = fp16([&]{ uint16_t v; std::memcpy(&v,b,2); return v; }());
    const float dmin = fp16([&]{ uint16_t v; std::memcpy(&v,b+2,2); return v; }());
    const uint8_t* sc = b + 4;
    uint8_t scales[8], mins[8];
    for (int g = 0; g < 4; ++g) {
        scales[g]   = sc[g] & 0x3F;
        mins[g]     = sc[g+4] & 0x3F;
        scales[g+4] = ((sc[g] >> 6) & 0x3) | ((sc[g+4] >> 2) & 0x30);
        mins[g+4]   = ((sc[g+4] >> 6) & 0x3) | ((sc[g] >> 2) & 0x30);
    }
    const uint8_t* qs = b + 12;
    for (int g = 0; g < 8; ++g) {
        const float sc_g = d * scales[g], mn_g = dmin * mins[g];
        for (int i = 0; i < 32; ++i) {
            const uint8_t q = (qs[g*32 + i/2] >> (4*(i%2))) & 0xF;
            out[g*32 + i] = sc_g * q - mn_g;
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr, "usage: %s <model.gguf> <token> <deep2_embd.f32>\n", argv[0]);
        return 2;
    }
    const uint32_t token = (uint32_t)std::strtoul(argv[2], nullptr, 10);
    std::FILE* f = std::fopen(argv[1], "rb");
    if (!f) { std::fprintf(stderr, "OPEN_FAIL\n"); return 1; }
    _fseeki64(f, 0, SEEK_END);
    long long fsize = _ftelli64(f);
    _fseeki64(f, 0, SEEK_SET);
    if (fsize < 24) { std::fclose(f); std::fprintf(stderr, "TOO_SMALL fsize=%lld\n", fsize); return 1; }

    // Streaming reader: reads from the file directly, no full-file allocation.
    struct FileReader {
        std::FILE* f;
        uint64_t size;
        uint64_t pos = 0;
        bool ok = true;
        bool need(uint64_t n) { if (!ok || pos + n > size) { ok=false; return false; } return true; }
        bool read(void* dst, uint64_t n) { if (!need(n)) return false; if (std::fread(dst,1,(size_t)n,f)!=(size_t)n){ok=false;return false;} pos+=n; return true; }
        bool seek(uint64_t p) { if (p > size) { ok=false; return false; } if (_fseeki64(f,(long long)p,SEEK_SET)!=0){ok=false;return false;} pos=p; return true; }
        uint16_t u16(){ uint16_t v=0; if(!read(&v,2))return 0; return v; }
        uint32_t u32(){ uint32_t v=0; if(!read(&v,4))return 0; return v; }
        uint64_t u64(){ uint64_t v=0; if(!read(&v,8))return 0; return v; }
        bool skip(uint64_t n){ if(!need(n))return false; if(_fseeki64(f,(long long)(pos+n),SEEK_SET)!=0){ok=false;return false;} pos+=n; return true; }
        bool str(std::string& out){
            uint64_t len=u64(); if(!ok||len>(1ull<<32)){ok=false;return false;}
            if(!need(len))return false;
            out.resize((size_t)len);
            if(len && std::fread(out.data(),1,(size_t)len,f)!=(size_t)len){ok=false;return false;}
            pos+=len; return true;
        }
    };
    FileReader r{f, (uint64_t)fsize, 0, true};

    char magic[4];
    if (!r.read(magic,4) || std::memcmp(magic,"GGUF",4)!=0) { std::fclose(f); std::fprintf(stderr,"NOT_GGUF\n"); return 1; }
    uint32_t version = r.u32();
    uint64_t nTensors = r.u64();
    uint64_t nKV = r.u64();
    if (!r.ok || version < 2) { std::fclose(f); std::fprintf(stderr,"BAD_HEADER\n"); return 1; }

    for (uint64_t i=0;i<nKV && r.ok;++i) {
        std::string key;
        if (!r.str(key)) break;
        uint32_t vtype = r.u32();
        if (!r.ok || !skipValue(r, vtype)) { std::fclose(f); std::fprintf(stderr,"KV_PARSE_FAIL at %llu\n",(unsigned long long)i); return 1; }
    }
    if (!r.ok) { std::fclose(f); std::fprintf(stderr,"KV trunc\n"); return 1; }

    TensorInfo target; bool found=false;
    for (uint64_t i=0;i<nTensors && r.ok;++i) {
        TensorInfo ti;
        if (!r.str(ti.name)) break;
        ti.nDims = r.u32();
        if (!r.ok || ti.nDims > 4) { std::fclose(f); std::fprintf(stderr,"BAD_NDIMS\n"); return 1; }
        for (uint32_t d=0;d<ti.nDims;++d) ti.dims[d]=r.u64();
        ti.ggmlType = r.u32();
        ti.offset = r.u64();
        if (!r.ok) break;
        size_t typeSize=0, blck=1;
        switch (ti.ggmlType) {
            case 0: typeSize=4; blck=1; break;
            case 1: typeSize=2; blck=1; break;
            case 12: typeSize=144; blck=256; break;
            case 14: typeSize=210; blck=256; break;
            default: break;
        }
        uint64_t elems=1;
        for (uint32_t d=0;d<ti.nDims;++d) elems*=ti.dims[d];
        ti.bytes = (typeSize>0 && blck>0) ? (elems/blck)*typeSize : 0;
        if (ti.name=="token_embd.weight") { target=ti; found=true; }
    }
    if (!found || !r.ok) { std::fclose(f); std::fprintf(stderr,"NO_TOKEN_EMD ok=%d\n",(int)r.ok); return 1; }

    uint64_t dataStart = (r.pos + 31) & ~(uint64_t)31;
    const uint64_t vocab = target.dims[target.nDims - 1];
    const uint64_t nIn = target.dims[0];
    const uint64_t rowBytes = target.bytes / (vocab ? vocab : 1);

    std::fprintf(stderr, "dims=[%llu,%llu,%llu] type=%u bytes=%llu vocab=%llu nIn=%llu rowBytes=%llu\n",
                 (unsigned long long)target.dims[0],
                 (unsigned long long)(target.nDims>1?target.dims[1]:0),
                 (unsigned long long)(target.nDims>2?target.dims[2]:0),
                 target.ggmlType, (unsigned long long)target.bytes,
                 (unsigned long long)vocab, (unsigned long long)nIn, (unsigned long long)rowBytes);

    if (token >= vocab || target.ggmlType != 12 || rowBytes == 0 || nIn == 0) {
        std::fclose(f); std::fprintf(stderr,"BAD_GEOM token=%u type=%u\n",token,target.ggmlType); return 1;
    }
    uint64_t rowOffset = dataStart + target.offset + (uint64_t)token * rowBytes;
    if (rowOffset + rowBytes > (uint64_t)fsize) { std::fclose(f); std::fprintf(stderr,"ROW_OOB\n"); return 1; }
    if (!r.seek(rowOffset)) { std::fclose(f); std::fprintf(stderr,"SEEK_FAIL\n"); return 1; }

    const uint64_t blocksPerRow = nIn / 256;
    std::vector<uint8_t> rowBuf((size_t)(blocksPerRow * 144));
    if (std::fread(rowBuf.data(), 1, rowBuf.size(), f) != rowBuf.size()) { std::fclose(f); std::fprintf(stderr,"ROW_READ_FAIL\n"); return 1; }
    std::fclose(f);

    std::vector<float> embd(nIn);
    for (uint64_t b = 0; b < blocksPerRow; ++b) dequantQ4K(rowBuf.data() + b*144, embd.data() + b*256);

    std::FILE* cf = std::fopen(argv[3], "rb");
    if (!cf) { std::fprintf(stderr, "CMP_OPEN_FAIL\n"); return 1; }
    std::vector<float> cmp(nIn);
    if (std::fread(cmp.data(), sizeof(float), nIn, cf) != nIn) { std::fclose(cf); std::fprintf(stderr, "CMP_READ_FAIL\n"); return 1; }
    std::fclose(cf);

    double maxAbs=0, ss=0, dot=0, na=0, nb=0; size_t firstBad=0; bool bad=false;
    for (size_t i = 0; i < nIn; ++i) {
        double d = std::fabs((double)embd[i]-(double)cmp[i]);
        if (d>maxAbs) maxAbs=d;
        if (d>1e-3 && !bad) { firstBad=i; bad=true; }
        ss+=d*d; dot+=(double)embd[i]*(double)cmp[i];
        na+=(double)embd[i]*(double)embd[i]; nb+=(double)cmp[i]*(double)cmp[i];
    }
    double rms = std::sqrt(ss/nIn);
    double cos = (na>0&&nb>0)?dot/(std::sqrt(na)*std::sqrt(nb)):0;
    std::printf("EMBD_PARITY n=%zu maxAbs=%.6g rms=%.6g cos=%.6f firstBad=%zu e0_ref=%.6g e0_deep2=%.6g\n",
                nIn, maxAbs, rms, cos, firstBad, embd[0], cmp[0]);
    return (maxAbs < 1e-3 && cos > 0.999) ? 0 : 1;
}