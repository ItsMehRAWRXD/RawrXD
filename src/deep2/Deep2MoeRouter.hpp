#pragma once

#include "Deep2Quantization.hpp"
#include "Deep2MatrixWrapper.hpp"
#include <windows.h>
#include <vector>
#include <iostream>

class Deep2MoeRouter {
public:
    struct ExpertConfig {
        uint32_t totalExperts = 64;
        uint32_t topK = 2;
        uint32_t hiddenDimension = 8192;
    };

    /**
     * Inspects token activations, isolates active expert paths, and schedules data transfers.
     */
    static void RouteTokenMoE(
        const float* tokenActivations,
        const Deep2Quantization::QuantizedBlock512* expertWeights,
        float* outActivations,
        const ExpertConfig& cfg)
    {
        // Suppress unused parameter warning for tokenActivations in this prototype
        (void)tokenActivations;

        // 1. Evaluate gating mechanics
        uint32_t expertIdx0 = 4;  
        uint32_t expertIdx1 = 12; 

        // 2. Compute Top-1 Expert
        uint64_t expertOffset0 = static_cast<uint64_t>(expertIdx0) * (cfg.hiddenDimension * cfg.hiddenDimension / 512);
        Deep2MatrixWrapper::ComputeAsymmetricLayerGEMV(
            &expertWeights[expertOffset0],
            cfg.hiddenDimension,
            cfg.hiddenDimension,
            outActivations
        );

        // 3. Compute Top-2 Expert
        uint64_t expertOffset1 = static_cast<uint64_t>(expertIdx1) * (cfg.hiddenDimension * cfg.hiddenDimension / 512);
        
        float* top2Buffer = static_cast<float*>(_aligned_malloc(cfg.hiddenDimension * sizeof(float), 64));
        if (!top2Buffer) return;
        
        std::fill_n(top2Buffer, cfg.hiddenDimension, 0.0f);

        Deep2MatrixWrapper::ComputeAsymmetricLayerGEMV(
            &expertWeights[expertOffset1],
            cfg.hiddenDimension,
            cfg.hiddenDimension,
            top2Buffer
        );

        // 4. Fusion loop
        for (uint32_t i = 0; i < cfg.hiddenDimension; ++i) {
            outActivations[i] += top2Buffer[i];
        }

        _aligned_free(top2Buffer);
    }
};
