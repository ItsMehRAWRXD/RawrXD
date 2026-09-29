// Layer compute authority implementation
// RawrXD Layer Compute Authority - Gates all layer execution including attention, FFN, MoE, and SSM

#include "src/compute/LayerComputeAuthority.h"
#include <iostream>
#include <unordered_map>
#include <string>

namespace rawrxd::compute
{
    // Global layer compute authority state
    struct LayerComputeAuthorityState
    {
        bool entered = false;
        int layerIndex = 0;
        long long attentionMs = 0;
        long long ffnMs = 0;
        long long moeMs = 0;
        long long ssmMs = 0;
        long long residualMs = 0;
        long long layerTotalMs = 0;
        std::string verdict = "HOLD";
    };

    // Global state instance
    static LayerComputeAuthorityState g_layerAuthorityState;

    // Begin layer processing
    void beginLayer(int index)
    {
        g_layerAuthorityState.entered = true;
        g_layerAuthorityState.layerIndex = index;
        std::cout << "[LayerComputeAuthority] Beginning layer: " << index << std::endl;
    }

    // Record attention computation
    void recordAttention(long long durationMs)
    {
        g_layerAuthorityState.attentionMs = durationMs;
        g_layerAuthorityState.layerTotalMs += durationMs;
        std::cout << "[LayerComputeAuthority] Recorded attention: " << durationMs << "ms" << std::endl;
    }

    // Record FFN computation
    void recordFFN(long long durationMs)
    {
        g_layerAuthorityState.ffnMs = durationMs;
        g_layerAuthorityState.layerTotalMs += durationMs;
        std::cout << "[LayerComputeAuthority] Recorded FFN: " << durationMs << "ms" << std::endl;
    }

    // Record MoE computation
    void recordMoE(long long durationMs)
    {
        g_layerAuthorityState.moeMs = durationMs;
        g_layerAuthorityState.layerTotalMs += durationMs;
        std::cout << "[LayerComputeAuthority] Recorded MoE: " << durationMs << "ms" << std::endl;
    }

    // Record SSM computation
    void recordSSM(long long durationMs)
    {
        g_layerAuthorityState.ssmMs = durationMs;
        g_layerAuthorityState.layerTotalMs += durationMs;
        std::cout << "[LayerComputeAuthority] Recorded SSM: " << durationMs << "ms" << std::endl;
    }

    // End layer processing
    void endLayer()
    {
        std::cout << "[LayerComputeAuthority] Ending layer " << g_layerAuthorityState.layerIndex 
                  << ": total " << g_layerAuthorityState.layerTotalMs << "ms (attn=" << g_layerAuthorityState.attentionMs
                  << "ms, ffn=" << g_layerAuthorityState.ffnMs << "ms, moe=" << g_layerAuthorityState.moeMs << "ms, ssm=" << g_layerAuthorityState.ssmMs << "ms)" << std::endl;
    }

    // Write layer compute receipt
    void writeLayerComputeReceipt()
    {
        std::cout << "[LayerComputeAuthority] Writing layer compute receipt:" << std::endl;
        std::cout << "  LAYER_INDEX=" << g_layerAuthorityState.layerIndex << std::endl;
        std::cout << "  ATTENTION_MS=" << g_layerAuthorityState.attentionMs << std::endl;
        std::cout << "  FFN_MS=" << g_layerAuthorityState.ffnMs << std::endl;
        std::cout << "  MOE_MS=" << g_layerAuthorityState.moeMs << std::endl;
        std::cout << "  SSM_MS=" << g_layerAuthorityState.ssmMs << std::endl;
        std::cout << "  RESIDUAL_MS=" << g_layerAuthorityState.residualMs << std::endl;
        std::cout << "  LAYER_TOTAL_MS=" << g_layerAuthorityState.layerTotalMs << std::endl;
        std::cout << "  VERDICT=" << g_layerAuthorityState.verdict << std::endl;
    }
}
