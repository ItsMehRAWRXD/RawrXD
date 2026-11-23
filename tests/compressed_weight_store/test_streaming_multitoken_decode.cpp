// Synthetic 16-token autoregressive recurrent decode using the production
// CompressedWeightStore streaming FP32 matvec primitive at every token.
#include "deep2/compression/StreamingWeightMatVec.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>
int main() {
    constexpr std::size_t hidden=128, vocab=64, steps=16;
    constexpr std::size_t block=4096, cache=8192;
    std::vector<float> recurrent(hidden*hidden), head(vocab*hidden);
    for (std::size_t i=0;i<recurrent.size();++i)
        recurrent[i]=static_cast<float>(static_cast<int>(i*13%37)-18)/512.0f;
    for (std::size_t i=0;i<head.size();++i)
        head[i]=static_cast<float>(static_cast<int>(i*7%43)-21)/128.0f;
    rawrxd::compression::CompressedWeightStore store(cache,block);
    std::string error;
    if (!store.addTensor("recurrent",recurrent.data(),recurrent.size()*sizeof(float),
                         &error,rawrxd::compression::GGML_TYPE_F32)) return 1;
    if (!store.addTensor("head",head.data(),head.size()*sizeof(float),
                         &error,rawrxd::compression::GGML_TYPE_F32)) return 2;
    std::vector<float> denseState(hidden,0), streamedState(hidden,0);
    std::vector<float> denseNext(hidden), streamedNext(hidden);
    std::vector<float> denseLogits(vocab), streamedLogits(vocab);
    int token=3;
    float maxAbs=0;
    for (std::size_t step=0;step<steps;++step) {
        // Token embedding is deterministic, generated without a materialized table.
        for (std::size_t j=0;j<hidden;++j) {
            const float embed=static_cast<float>(static_cast<int>((token*17+j*5)%31)-15)/128.0f;
            denseState[j]+=embed;
            streamedState[j]+=embed;
        }
        if (!rawrxd::compression::streamingF32MatVec(store,"recurrent",
             streamedState.data(),hidden,hidden,streamedNext.data(),64,&error)) return 3;
        for (std::size_t row=0;row<hidden;++row) {
            float sum=0;
            for (std::size_t col=0;col<hidden;++col)
                sum+=recurrent[row*hidden+col]*denseState[col];
            denseNext[row]=sum;
        }
        for (std::size_t j=0;j<hidden;++j) {
            denseState[j]=std::tanh(denseNext[j]);
            streamedState[j]=std::tanh(streamedNext[j]);
        }
        if (!rawrxd::compression::streamingF32MatVec(store,"head",
             streamedState.data(),vocab,hidden,streamedLogits.data(),64,&error)) return 4;
        for (std::size_t row=0;row<vocab;++row) {
            float sum=0;
            for (std::size_t col=0;col<hidden;++col)
                sum+=head[row*hidden+col]*denseState[col];
            denseLogits[row]=sum;
            if (!std::isfinite(streamedLogits[row])) return 5;
            maxAbs=std::max(maxAbs,std::fabs(sum-streamedLogits[row]));
        }
        const auto oracle=static_cast<int>(std::max_element(denseLogits.begin(),denseLogits.end())-denseLogits.begin());
        const auto predicted=static_cast<int>(std::max_element(streamedLogits.begin(),streamedLogits.end())-streamedLogits.begin());
        if (oracle!=predicted || maxAbs>1e-5f) {
            std::fprintf(stderr,"decode parity failure at step=%zu oracle=%d predicted=%d maxAbs=%g\n",
                         step,oracle,predicted,maxAbs);return 6;
        }
        if (store.stats().cached_decoded_bytes>cache) return 7;
        token=predicted;
    }
    const auto stats=store.stats();
    if (!stats.cache_misses || stats.cached_decoded_bytes>cache) return 8;
    std::printf("STREAMING_MULTITOKEN_DECODE=PASS steps=%zu maxAbs=%g encoded=%llu raw=%llu\n",
                steps,maxAbs,static_cast<unsigned long long>(stats.compressed_bytes),
                static_cast<unsigned long long>(stats.raw_bytes));
    return 0;
}
