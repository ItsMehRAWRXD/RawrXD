// =============================================================================
// Blocker #7: MoE Architecture Validation
// Validates MoE router/expert structure against GGUF metadata
// =============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct MoEConfig {
    int numExperts;        // e.g., 8 for Mixtral
    int numExpertsPerTok;  // e.g., 2 for Mixtral
    int numLayers;
    int hiddenDim;
    int intermediateDim;
    bool hasSharedExpert;  // DeepSeek-style shared expert
    int routerDim;         // usually = hiddenDim
};

struct MoELayerInfo {
    int layerIdx;
    int numExperts;
    bool routerLoaded;
    bool expertsLoaded;
    bool sharedExpertLoaded;
    std::vector<std::string> missingTensors;
};

class MoEValidator {
public:
    // Validate that required MoE tensors exist in GGUF tensor list
    static bool validate(
        const MoEConfig& config,
        const std::vector<std::string>& tensorNames,
        std::vector<MoELayerInfo>& outIssues
    ) {
        bool allValid = true;

        for (int layer = 0; layer < config.numLayers; layer++) {
            MoELayerInfo info;
            info.layerIdx = layer;
            info.numExperts = config.numExperts;
            info.routerLoaded = false;
            info.expertsLoaded = false;
            info.sharedExpertLoaded = false;

            // Expected tensor name patterns (llama.cpp convention):
            // blk.{layer}.ffn_gate_inp.weight  — router
            // blk.{layer}.ffn_gate.{expert}.weight  — gate weights
            // blk.{layer}.ffn_down.{expert}.weight  — down weights
            // blk.{layer}.ffn_up.{expert}.weight    — up weights

            std::string prefix = "blk." + std::to_string(layer) + ".";

            // Check router
            std::string routerName = prefix + "ffn_gate_inp.weight";
            if (hasTensor(tensorNames, routerName)) {
                info.routerLoaded = true;
            } else {
                info.missingTensors.push_back(routerName);
            }

            // Check experts
            int expertsFound = 0;
            for (int e = 0; e < config.numExperts; e++) {
                std::string gate = prefix + "ffn_gate." + std::to_string(e) + ".weight";
                std::string down = prefix + "ffn_down." + std::to_string(e) + ".weight";
                std::string up   = prefix + "ffn_up." + std::to_string(e) + ".weight";

                bool hasGate = hasTensor(tensorNames, gate);
                bool hasDown = hasTensor(tensorNames, down);
                bool hasUp   = hasTensor(tensorNames, up);

                if (hasGate && hasDown && hasUp) {
                    expertsFound++;
                } else {
                    if (!hasGate) info.missingTensors.push_back(gate);
                    if (!hasDown) info.missingTensors.push_back(down);
                    if (!hasUp)   info.missingTensors.push_back(up);
                }
            }

            if (expertsFound == config.numExperts) {
                info.expertsLoaded = true;
            } else if (expertsFound > 0) {
                allValid = false;
            } else {
                // No experts found — might be a dense layer, not MoE
                // Only flag as issue if this layer is supposed to be MoE
            }

            // Check shared expert (DeepSeek-style)
            if (config.hasSharedExpert) {
                std::string sharedGate = prefix + "ffn_gate_shexp.weight";
                std::string sharedDown = prefix + "ffn_down_shexp.weight";
                std::string sharedUp   = prefix + "ffn_up_shexp.weight";

                if (hasTensor(tensorNames, sharedGate)
                    && hasTensor(tensorNames, sharedDown)
                    && hasTensor(tensorNames, sharedUp)) {
                    info.sharedExpertLoaded = true;
                } else {
                    if (!hasTensor(tensorNames, sharedGate))
                        info.missingTensors.push_back(sharedGate);
                    if (!hasTensor(tensorNames, sharedDown))
                        info.missingTensors.push_back(sharedDown);
                    if (!hasTensor(tensorNames, sharedUp))
                        info.missingTensors.push_back(sharedUp);
                }
            }

            if (!info.missingTensors.empty()) {
                allValid = false;
            }

            outIssues.push_back(info);
        }

        return allValid;
    }

    // Extract MoE config from GGUF metadata keys
    static MoEConfig fromMetadata(
        int numLayers,
        int hiddenDim,
        int intermediateDim,
        const std::vector<std::pair<std::string, int>>& intMeta
    ) {
        MoEConfig config;
        config.numLayers = numLayers;
        config.hiddenDim = hiddenDim;
        config.intermediateDim = intermediateDim;
        config.numExperts = 0;
        config.numExpertsPerTok = 0;
        config.hasSharedExpert = false;
        config.routerDim = hiddenDim;

        for (size_t i = 0; i < intMeta.size(); i++) {
            const std::string& key = intMeta[i].first;
            int val = intMeta[i].second;

            if (key == "llm.expert_count" || key == "expert_count") {
                config.numExperts = val;
            }
            if (key == "llm.expert_used_count" || key == "expert_used_count") {
                config.numExpertsPerTok = val;
            }
            if (key == "llm.expert_shared_count" && val > 0) {
                config.hasSharedExpert = true;
            }
        }

        return config;
    }

private:
    static bool hasTensor(const std::vector<std::string>& names, const std::string& target) {
        for (size_t i = 0; i < names.size(); i++) {
            if (names[i] == target) return true;
        }
        return false;
    }
};