// RawrXD ModelGenie parity diagnostic -- independent packed Q6_K LM-head oracle.
// Source-only, standard C++17, no ggml/Ollama/Python dependencies.
// NOTE: MODEL-SPECIFIC OFFSETS. This does not implement a general GGUF parser.
#include <array>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace audit {
constexpr uint64_t kModelBytes = 10364416768ULL;
constexpr uint64_t kDataStart = 3996416ULL;
constexpr uint64_t kOutputTensorOffset = 0ULL;
constexpr size_t kHidden = 2048;
constexpr size_t kVocab = 102400;
constexpr size_t kQuantBlockSize = 256;
constexpr size_t kEncodedBlockBytes = 210;
constexpr size_t kBlocksPerRow = kHidden/kQuantBlockSize;
constexpr size_t kRowBytes = kBlocksPerRow*kEncodedBlockBytes;
constexpr size_t kOutputBytes = kVocab*kRowBytes;
static_assert(kOutputBytes == 172032000ULL, "output.weight expected Q6_K bytes");

#pragma pack(push, 1)
struct Q6K { uint8_t ql[128], qh[64]; int8_t scales[16]; uint16_t d; };
#pragma pack(pop)
static_assert(sizeof(Q6K) == 210, "GGML block_q6_K ABI mismatch");
static_assert(offsetof(Q6K,scales)==192 && offsetof(Q6K,d)==208, "Q6K field offsets");

float fp16_to_f32(uint16_t h) {
    const uint32_t sign = (uint32_t(h & 0x8000) << 16);
    uint32_t exp = (h >> 10) & 31u;
    uint32_t mant = h & 1023u;
    uint32_t bits;
    if (exp == 0) {
        if (mant == 0) bits = sign;
        else {
            // Normalize FP16 subnormal into FP32 without dropping leading bits.
            int e = -14;
            while ((mant & 1024u) == 0) { mant <<= 1; --e; }
            mant &= 1023u;
            bits = sign | (uint32_t(e + 127) << 23) | (mant << 13);
        }
    } else if (exp == 31u) bits = sign | 0x7f800000u | (mant << 13);
    else bits = sign | ((exp + (127 - 15)) << 23) | (mant << 13);
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

// ggml quant layout: 2 x 128-value halves, each with 4 x 32-value streams.
// The signed scales index two 16-value groups per 32-value stream.
void decode_q6_block(const Q6K &src, float out[256]) {
    const float d = fp16_to_f32(src.d);
    for (size_t half = 0; half < 2; ++half) {
        const uint8_t *ql = src.ql + 64*half;
        const uint8_t *qh = src.qh + 32*half;
        const int8_t *s = src.scales + 8*half;
        float *dst = out + 128*half;
        for (size_t l = 0; l < 32; ++l) {
            const size_t group = l/16;
            const int q0 = int((ql[l]      & 0x0f) | ((qh[l] & 0x03) << 4)) - 32;
            const int q1 = int((ql[l+32]   & 0x0f) | (((qh[l] >> 2) & 0x03) << 4)) - 32;
            const int q2 = int((ql[l]      >> 4)   | (((qh[l] >> 4) & 0x03) << 4)) - 32;
            const int q3 = int((ql[l+32]   >> 4)   | (((qh[l] >> 6) & 0x03) << 4)) - 32;
            dst[l]    = d * float(s[group+0] * q0);
            dst[l+32] = d * float(s[group+2] * q1);
            dst[l+64] = d * float(s[group+4] * q2);
            dst[l+96] = d * float(s[group+6] * q3);
        }
    }
}

void test_self() {
    if (fp16_to_f32(0x3c00)!=1.0f || fp16_to_f32(0xbc00)!=-1.0f ||
        fp16_to_f32(0x0001)!=std::ldexp(1.0f,-24) ||
        fp16_to_f32(0x0400)!=std::ldexp(1.0f,-14)) throw std::runtime_error("FP16 conversion test failed");
    Q6K blk{};
    blk.d=0x3c00;
    for (size_t i=0; i<16; ++i) blk.scales[i] = (i%2) ? -2 : 3;
    float result[256]{};
    decode_q6_block(blk,result);
    if (result[0]!=-96.0f || result[16]!=64.0f || result[32]!=-96.0f || result[48]!=64.0f ||
        result[128]!=-96.0f || result[144]!=64.0f) throw std::runtime_error("signed scale group test failed");
    // nibble and upper two bits: distinct quant values in each of four streams
    blk.qh[0] = 0b11100100;
    blk.ql[0] = 0xA5;
    blk.ql[32] = 0xB6;
    decode_q6_block(blk,result);
    if (result[0]!=(5-32)*3 || result[32]!=(6+16-32)*3 ||
        result[64]!=(10+32-32)*3 || result[96]!=(11+48-32)*3)
        throw std::runtime_error("packed Q6 component test failed");
    std::cout << "Q6_LAYOUT_SELFTEST=PASS FP16_SUBNORMAL=PASS SIGNED_SCALES=PASS PACKED_BITS=PASS\n";
}

std::vector<float> read_vector(const std::string& path,size_t n) {
    std::ifstream in(path,std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error("cannot open vector: "+path);
    if (in.tellg() != std::streamoff(n*sizeof(float))) throw std::runtime_error("vector byte count mismatch: "+path);
    in.seekg(0);
    std::vector<float> v(n);
    in.read(reinterpret_cast<char*>(v.data()),std::streamsize(n*sizeof(float)));
    if (!in) throw std::runtime_error("short vector read: "+path);
    for (float x:v) if (!std::isfinite(x)) throw std::runtime_error("nonfinite input: "+path);
    return v;
}

struct Candidate {double logit=-std::numeric_limits<double>::infinity(); size_t token=0;};
void update(Candidate& best,size_t token,double score) { if (score>best.logit) best={score,token}; }

int audit_lm(const std::string& gguf,const std::string& hiddenFile,const std::string& logitsFile) {
    auto hidden=read_vector(hiddenFile,kHidden);
    std::vector<float> claimed;
    if (!logitsFile.empty()) claimed=read_vector(logitsFile,kVocab);
    std::ifstream in(gguf,std::ios::binary|std::ios::ate);
    if (!in) throw std::runtime_error("cannot open GGUF: "+gguf);
    const auto filesize=in.tellg();
    if (filesize!=std::streamoff(kModelBytes)) throw std::runtime_error("GGUF byte size does not match frozen ROM authority");
    in.seekg(0);
    char magic[4]{};
    in.read(magic,4);
    if (std::memcmp(magic,"GGUF",4)!=0) throw std::runtime_error("GGUF magic mismatch");
    if (kDataStart+kOutputTensorOffset+kOutputBytes > uint64_t(filesize)) throw std::runtime_error("ROM range check failed");
    in.seekg(std::streamoff(kDataStart+kOutputTensorOffset));
    std::array<Q6K,kBlocksPerRow> blocks{};
    std::array<float,kQuantBlockSize> decoded{};
    Candidate direct, saved;
    double maxAbs=0.0, sumSq=0.0, maxRelative=0.0;
    size_t maxToken=0, mismatches=0;
    for(size_t token=0;token<kVocab;++token) {
        in.read(reinterpret_cast<char*>(blocks.data()),std::streamsize(kRowBytes));
        if (!in) throw std::runtime_error("GGUF short Q6_K row read token="+std::to_string(token));
        double acc=0.0;
        for(size_t b=0;b<kBlocksPerRow;++b) {
            decode_q6_block(blocks[b],decoded.data());
            for(size_t j=0;j<kQuantBlockSize;++j)
                acc+=double(hidden[b*kQuantBlockSize+j])*double(decoded[j]);
        }
        if(!std::isfinite(acc)) throw std::runtime_error("nonfinite direct logit token="+std::to_string(token));
        update(direct,token,acc);
        if(token==0||token==93633||token==102005||token==102399||token==28247||token==36190)
            std::cout<<"DIRECT_LOGIT TOKEN="<<token<<" LOGIT="<<std::setprecision(9)<<acc
                     <<(claimed.empty()?"":" SAVED_LOGIT="+std::to_string(claimed[token]))<<"\n";
        if(!claimed.empty()) {
            const double err=std::abs(acc-double(claimed[token]));
            const double rel=err/std::max({1.0,std::abs(acc),std::abs(double(claimed[token]))});
            if(err>maxAbs){maxAbs=err;maxToken=token;}
            maxRelative=std::max(maxRelative,rel);
            sumSq+=err*err;
            if(err>0.01 && rel>0.0001) ++mismatches;
            update(saved,token,claimed[token]);
        }
    }
    std::cout<<std::setprecision(10);
    std::cout<<"DIRECT_Q6_ARGMAX="<<direct.token<<" DIRECT_Q6_MAX_LOGIT="<<direct.logit<<"\n";
    std::cout<<"DIRECT_Q6_TARGET_93633="<<(direct.token==93633?1:0)<<"\n";
    if(!claimed.empty()){
        std::cout<<"EXECUTOR_ARGMAX="<<saved.token<<" EXECUTOR_MAX_LOGIT="<<saved.logit<<"\n";
        std::cout<<"LMHEAD_ARGMAX_MATCH="<<(direct.token==saved.token?1:0)<<"\n";
        std::cout<<"LMHEAD_MAX_ABS_DIFF="<<maxAbs<<" AT_TOKEN="<<maxToken<<"\n";
        std::cout<<"LMHEAD_RMSE="<<std::sqrt(sumSq/kVocab)<<" MAX_RELATIVE_DIFF="<<maxRelative<<"\n";
        std::cout<<"LMHEAD_OUTLIERS="<<mismatches<<"\n";
        // These are practical diagnostic tolerances, not a strict bit-exact parity certificate.
        std::cout<<"LMHEAD_NUMERIC_CLOSE="<<(mismatches==0?1:0)<<"\n";
    }
    return 0;
}
}

int main(int argc,char**argv){
    try {
        audit::test_self();
        if(argc==2&&std::string(argv[1])=="--selftest")return 0;
        if(argc!=3 && argc!=4){
            std::cerr<<"Usage: rawrxd_q6_lmhead_audit.exe <model.gguf> <op_298.bin> [op_299.bin]\n";
            std::cerr<<"Requires exact DeepSeek-V2-Lite-Chat frozen ROM described in README.\n";
            return 2;
        }
        return audit::audit_lm(argv[1],argv[2],argc==4?argv[3]:"");
    }catch(const std::exception&e){std::cerr<<"AUDIT_ERROR="<<e.what()<<"\n";return 1;}
}
