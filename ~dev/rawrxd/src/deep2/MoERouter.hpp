#pragma once
// Stub: MoE Router
#include <vector>
#include <cmath>
#include <cstdint>
namespace Deep2 {
struct MoERouter {
    int n_experts = 8;
    std::vector<float> ema;
    std::vector<int> trials;
    MoERouter(int n=8) : n_experts(n), ema(n, 0.5f), trials(n, 0) {}
    std::vector<int> route(const float* hidden, int k) {
        std::vector<int> idx(n_experts);
        for(int i=0;i<n_experts;i++) idx[i]=i;
        return idx;
    }
};
struct MoEConfig { int numExperts=8; int expertsPerToken=2; };
struct MoEWeightHandle { int layer=0; int expert=0; size_t bytes=0; };
class MoELayer {};
class MoEWeightsLoader {};
class MoEWeightProxy {};
} // namespace Deep2
