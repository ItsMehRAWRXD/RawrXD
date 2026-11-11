#pragma once
// BoltExecutor — Nemotron-H MoE/Bolt inference backed by existing Deep2 engine.
// Implements the hybrid SSM/attention/MoE layer loop directly using Deep2Engine
// operators (computeSSM, computeAttention, computeMoEFFN, computeLogits).
//
// Layer flow per block:
//   RMSNorm(attnNorm) → [SSM | Attention] → residual (add pre-norm input)
//   if MoE: RMSNorm(ffnNorm) → computeMoEFFN → residual (add pre-norm input)
// Final: RMSNorm(finalNorm) → computeLogits
//
// Deep2Engine owns all tensors, SSM state, KV cache, and quant kernels.

#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"
#include "Deep2Engine.h"
#include <vector>
#include <string>
#include <stdexcept>
#include <cstdio>
#include <cstring>
#include <span>
#include <algorithm>

namespace Deep2 {

// Layer plan entry: describes each transformer block's operator mix
struct BoltLayerPlan {
    uint32_t index = 0;
    bool hasSSM = false;
    bool hasMoE = false;
    uint32_t routerWidth = 0;
};

// BoltExecutor binds Deep2 operators to a Bolt-style hybrid forward pass
class BoltExecutor {
    Deep2Engine engine_;
    std::vector<BoltLayerPlan> layerPlan_;
    bool initialized_ = false;

public:
    explicit BoltExecutor(const std::string& modelPath) {
        // Load model through Deep2Engine (owns all tensors, state, KV cache, quant kernels)
        if (!engine_.loadModel(modelPath)) {
            throw std::runtime_error("Failed to load model via Deep2Engine: " + modelPath);
        }

        // Build layer plan from bound model weights
        const auto& weights = engine_.getModelWeights();
        layerPlan_.reserve(weights.layers.size());
        for (uint32_t i = 0; i < static_cast<uint32_t>(weights.layers.size()); ++i) {
            const auto& lw = weights.layers[i];
            BoltLayerPlan plan;
            plan.index = i;
            plan.hasSSM = lw.hasSSM;
            plan.hasMoE = (lw.moeRouter.data != nullptr && lw.moeRouter.sizeBytes > 0);
            plan.routerWidth = plan.hasMoE ? static_cast<uint32_t>(lw.moeRouter.rows) : 0;
            layerPlan_.push_back(plan);

            printf("[BoltExecutor] Layer %u: hasSSM=%d hasMoE=%d routerWidth=%u\n",
                   i, plan.hasSSM ? 1 : 0, plan.hasMoE ? 1 : 0, plan.routerWidth);
        }

        initialized_ = true;
        printf("[BoltExecutor] Ready: %zu layers, hidden=%zu, vocab=%zu\n",
               layerPlan_.size(), weights.hiddenDim, weights.vocabSize);
    }

    void Reset() {
        engine_.resetInferenceState();
        initialized_ = true;
    }

    // Forward pass with a single token ID. Returns span into internal logits buffer.
    std::span<const float> Forward(uint32_t tokenId) {
        if (!initialized_) Reset();

        const ModelWeights& mw = engine_.getModelWeights();
        size_t hiddenDim = engine_.getConfig().hiddenDim;
        size_t vocabSize = mw.vocabSize;

        float* hidden = engine_.getLayerTemp();   // working hidden state
        float* tmp = engine_.getFfnOutput();      // temporary buffer

        // 1. Token embedding → hidden
        if (!engine_.embedToken(static_cast<int>(tokenId), hidden)) {
            throw std::runtime_error("Failed to get token embedding");
        }

        // 2. Layer loop
        for (const auto& plan : layerPlan_) {
            const auto& lw = mw.layers[plan.index];

            // Save pre-norm input for residual
            memcpy(tmp, hidden, hiddenDim * sizeof(float));  // tmp = pre-norm input

            // RMSNorm(attnNorm) on input → hidden (in-place)
            engine_.RMSNormW(lw.attnNorm, hidden, hidden, hiddenDim, mw.normEps);

            if (plan.hasSSM) {
                // SSM / Mamba-2 selective scan: input=hidden (norm'd), output=tmp
                engine_.computeSSM(plan.index, hidden, tmp);
                memcpy(hidden, tmp, hiddenDim * sizeof(float));
            } else {
                // Attention (uses KV cache internally): input=hidden, output=tmp
                engine_.computeAttention(plan.index, hidden, tmp, 1);
                memcpy(hidden, tmp, hiddenDim * sizeof(float));
            }

            // Residual: hidden = hidden + pre-norm input (tmp still holds it)
            for (size_t i = 0; i < hiddenDim; ++i) {
                hidden[i] += tmp[i];
            }

            if (plan.hasMoE) {
                // MoE branch: RMSNorm(ffnNorm) → computeMoEFFN → residual
                memcpy(tmp, hidden, hiddenDim * sizeof(float));
                engine_.RMSNormW(lw.ffnNorm, hidden, hidden, hiddenDim, mw.normEps);
                engine_.computeMoEFFN(plan.index, hidden, tmp);
                memcpy(hidden, tmp, hiddenDim * sizeof(float));
                for (size_t i = 0; i < hiddenDim; ++i) {
                    hidden[i] += tmp[i];
                }
            } else {
                // Dense FFN branch: RMSNorm(ffnNorm) → computeFFN → residual
                memcpy(tmp, hidden, hiddenDim * sizeof(float));
                engine_.RMSNormW(lw.ffnNorm, hidden, hidden, hiddenDim, mw.normEps);
                engine_.computeFFN(plan.index, hidden, tmp);
                memcpy(hidden, tmp, hiddenDim * sizeof(float));
                for (size_t i = 0; i < hiddenDim; ++i) {
                    hidden[i] += tmp[i];
                }
            }
        }

        // 3. Output logits: RMSNorm(finalNorm) → tmp, then computeLogits → hidden
        engine_.RMSNormW(mw.finalNorm, hidden, tmp, hiddenDim, mw.normEps);
        engine_.computeLogits(tmp, hidden);  // logits into hidden (layerTemp)

        return std::span<const float>(engine_.getLayerTemp(), vocabSize);
    }

    // Generate next token greedily
    uint32_t Generate(uint32_t tokenId) {
        auto logits = Forward(tokenId);
        return static_cast<uint32_t>(
            std::distance(logits.begin(),
                          std::max_element(logits.begin(), logits.end())));
    }

    uint64_t Position() const { return 0; }  // single-token forward, position managed by KV cache

    size_t HiddenDim() const { return engine_.getConfig().hiddenDim; }
    size_t VocabSize() const { return engine_.getModelWeights().vocabSize; }
    size_t NumLayers() const { return layerPlan_.size(); }
};

} // namespace Deep2
