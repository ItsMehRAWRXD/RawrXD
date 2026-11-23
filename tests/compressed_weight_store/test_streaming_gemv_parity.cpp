// End-to-end CPU GEMV consuming bounded decoded weight tiles, not full tensors.
// Dense oracle is independent of CompressedWeightStore's read/decode implementation.
#include "deep2/compression/CompressedWeightStore.hpp"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
using rawrxd::compression::CompressedWeightStore;
int main() {
    constexpr std::size_t rows=512, cols=2048, tileCols=256;
    constexpr std::size_t blockBytes=4096, cacheBudget=2*blockBytes;
    std::vector<float> dense(rows*cols), input(cols), oracle(rows,0.0f), actual(rows,0.0f);
    for (std::size_t c=0;c<cols;++c)
        input[c]=static_cast<float>(static_cast<int>(c%23)-11)/23.0f;
    for (std::size_t r=0;r<rows;++r) {
        for (std::size_t c=0;c<cols;++c) {
            const float v=static_cast<float>(static_cast<int>((r*17+c*13)%31)-15)/31.0f;
            dense[r*cols+c]=v;
            oracle[r]+=v*input[c];
        }
    }
    CompressedWeightStore store(cacheBudget,blockBytes);
    std::string error;
    if (!store.addTensor("linear.weight",dense.data(),dense.size()*sizeof(float),
                         &error,rawrxd::compression::GGML_TYPE_F32)) {
        std::fprintf(stderr,"admission failed: %s\n",error.c_str());return 1;
    }
    const auto before=store.stats();
    if (before.cached_decoded_bytes!=0) return 2;
    std::vector<float> tile(tileCols);
    for (std::size_t r=0;r<rows;++r) {
        for (std::size_t c=0;c<cols;c+=tileCols) {
            const auto take=std::min(tileCols,cols-c);
            const auto byteOffset=(r*cols+c)*sizeof(float);
            if (!store.readRange("linear.weight",byteOffset,tile.data(),
                                 take*sizeof(float),&error)) {
                std::fprintf(stderr,"tile read failed: %s\n",error.c_str());return 3;
            }
            for (std::size_t i=0;i<take;++i) actual[r]+=tile[i]*input[c+i];
            if (store.stats().cached_decoded_bytes>cacheBudget) return 4;
        }
    }
    float maxAbs=0;
    for (std::size_t r=0;r<rows;++r) {
        if (!std::isfinite(actual[r])) return 5;
        maxAbs=std::max(maxAbs,std::fabs(actual[r]-oracle[r]));
    }
    if (maxAbs>1e-4f) {
        std::fprintf(stderr,"GEMV mismatch maxAbs=%g\n",maxAbs);return 6;
    }
    const auto after=store.stats();
    if (!after.cache_misses || !after.blocks) return 7;
    std::printf("STREAMING_GEMV_PARITY=PASS maxAbs=%g raw=%llu encoded=%llu resident_estimate=%llu\n",
                maxAbs,
                static_cast<unsigned long long>(after.raw_bytes),
                static_cast<unsigned long long>(after.compressed_bytes),
                static_cast<unsigned long long>(after.resident_bytes_estimate));
    return 0;
}
