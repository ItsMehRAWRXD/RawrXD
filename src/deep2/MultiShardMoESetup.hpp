#pragma once
/* B03 MiniMax: open MoE loaders on every GGUF shard + attach proxy. ≤99. */
#include "MoEWeightProxy.hpp"
#include "MoEWeightsLoader.hpp"
#include "MoERouter.hpp"
#include "Deep2Engine.h"
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace Deep2 {
namespace multishard_moe {

inline int OpenShardLoaders(
    const std::filesystem::path& firstShard,
    std::vector<std::unique_ptr<MoEWeightsLoader>>& out,
    size_t maxCacheBytes) {
    out.clear();
    namespace fs = std::filesystem;
    const fs::path dir = firstShard.parent_path();
    std::vector<fs::path> shards;
    for (auto& e : fs::directory_iterator(dir)) {
        if (!e.is_regular_file()) continue;
        const auto p = e.path();
        if (p.extension() == ".gguf") shards.push_back(p);
    }
    std::sort(shards.begin(), shards.end());
    if (shards.empty()) shards.push_back(firstShard);
    for (const auto& sp : shards) {
        auto L = std::make_unique<MoEWeightsLoader>();
        L->SetMaxCacheSize(maxCacheBytes / std::max<size_t>(shards.size(), 1));
        if (!L->Open(sp.string().c_str())) {
            std::fprintf(stderr, "B03_MOE_SHARD_OPEN_FAIL %s\n",
                         sp.string().c_str());
            continue;
        }
        std::fprintf(stderr,
                     "B03_MOE_SHARD_OPEN ok=%s experts=%zu layers=%zu\n",
                     sp.filename().string().c_str(), L->GetExpertsPerLayer(),
                     L->GetNumExpertLayers());
        out.push_back(std::move(L));
    }
    return static_cast<int>(out.size());
}

inline void InjectRouterF32(MoERouter& router, const WeightTensor& wr,
                            size_t numExperts, size_t hiddenDim) {
    if (!wr.data || wr.rows == 0 || wr.cols == 0) return;
    if (wr.type != (int)GGMLType::GGML_TYPE_F32) {
        std::fprintf(stderr,
                     "B03_MOE_ROUTER_TYPE_UNSUPPORTED type=%d rows=%zu cols=%zu\n",
                     wr.type, wr.rows, wr.cols);
        return;
    }
    const float* src = (const float*)wr.data;
    /* MoERouter::Route indexes W[d * numExperts + e]. MiniMax GGUF is [E,H]. */
    if (wr.rows == numExperts && wr.cols == hiddenDim && numExperts && hiddenDim) {
        std::vector<float> T(numExperts * hiddenDim);
        for (size_t e = 0; e < numExperts; ++e)
            for (size_t d = 0; d < hiddenDim; ++d)
                T[d * numExperts + e] = src[e * hiddenDim + d];
        router.SetRouterWeights(T.data(), hiddenDim, numExperts);
        std::fprintf(stderr,
                     "B03_MOE_ROUTER_INJECT layout=EH_to_HE E=%zu H=%zu\n",
                     numExperts, hiddenDim);
        return;
    }
    router.SetRouterWeights(src, wr.rows, wr.cols);
    std::fprintf(stderr,
                 "B03_MOE_ROUTER_INJECT layout=raw rows=%zu cols=%zu\n",
                 wr.rows, wr.cols);
}

inline void InjectExpertBiasF32(MoERouter& router, const WeightTensor& wb,
                                size_t numExperts) {
    if (!wb.data || !numExperts) return;
    if (wb.type != (int)GGMLType::GGML_TYPE_F32) {
        std::fprintf(stderr,
                     "B03_MOE_EXPERT_BIAS_TYPE_UNSUPPORTED type=%d\n", wb.type);
        return;
    }
    const size_t n = wb.rows * wb.cols;
    const size_t use = n < numExperts ? n : numExperts;
    router.SetExpertBias((const float*)wb.data, use);
    std::fprintf(stderr, "B03_MOE_EXPERT_BIAS_INJECT n=%zu\n", use);
}

} // namespace multishard_moe
} // namespace Deep2
