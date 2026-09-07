#pragma once
/*
===============================================================================
 Deep2SovereignInferenceGateway — catalog-backed Deep2 load/generate/unload
===============================================================================
 Inference path: ModelCatalog → immutable local path → Deep2Engine.
 No Ollama daemon, HTTP, llama.cpp link, or cloud fallback.
===============================================================================
*/
#include "../deep2/Deep2Engine.h"
#include "../models/ModelCatalog.hpp"

#include <cstddef>
#include <exception>
#include <filesystem>
#include <optional>
#include <string>

namespace fs = std::filesystem;

namespace RawrXD::Agent {

struct Deep2GatewayGenerationConfig {
    std::size_t maxTokens = 64;
    float temperature = 0.0f;
    float topP = 1.0f;
    int topK = 1;
    int seed = 42;
};

struct Deep2GatewayGenerateResult {
    bool success = false;
    std::string text;
    std::string error;
};

class SovereignModelResolver final {
public:
    static bool hasGGUFMagic(const fs::path& path) {
        return rawrxd::models::ModelCatalog::hasGGUFMagic(path);
    }

    static bool isUsableModelFile(const fs::path& path) {
        return rawrxd::models::ModelCatalog::findGGUFOffset(path).has_value();
    }

    static std::optional<fs::path> resolve(const std::string& spec) {
        const auto hit = rawrxd::models::ModelCatalog::resolve(spec);
        if (!hit) return std::nullopt;
        return hit->path.empty() ? hit->absolutePath : hit->path;
    }
};

class Deep2SovereignInferenceGateway final {
public:
    bool loadModel(const std::string& modelPath, std::string* error = nullptr) {
        unload();
        fs::path p(modelPath);
        Deep2::EngineConfig cfg{};
        cfg.useMLA = true;
        cfg.maxSeqLen = 256;
        cfg.useKVCache = true;
        if (!engine_.initialize(cfg)) {
            if (error) *error = "Deep2Engine::initialize failed";
            loaded_ = false;
            return false;
        }
        if (fs::is_directory(p)) {
            if (!engine_.openK2ShardDirectory(modelPath)) {
                if (error) *error = "openK2ShardDirectory failed: " + modelPath;
                loaded_ = false;
                return false;
            }
            if (!engine_.isVulkanInitialized()) engine_.enableVulkan(true);
        } else if (!engine_.loadModel(modelPath)) {
            if (error) *error = "Deep2Engine::loadModel failed for: " + modelPath;
            loaded_ = false;
            return false;
        }
        modelPath_ = modelPath;
        loaded_ = true;
        return true;
    }

    Deep2GatewayGenerateResult generate(
        const std::string& prompt,
        const Deep2GatewayGenerationConfig& cfg)
    {
        Deep2GatewayGenerateResult out;
        if (!loaded_) {
            out.error = "model not loaded";
            return out;
        }
        try {
            Deep2::GenerationOptions opts{};
            opts.maxTokens = static_cast<uint32_t>(cfg.maxTokens);
            opts.temperature = cfg.temperature;
            opts.topP = cfg.topP;
            opts.topK = static_cast<uint32_t>(cfg.topK > 0 ? cfg.topK : 1);
            opts.seed = static_cast<uint64_t>(cfg.seed);
            std::string text;
            auto r = engine_.generateStream(
                prompt, opts,
                [&](int32_t, const std::string& tok) -> bool {
                    text += tok;
                    return true;
                });
            out.text = std::move(text);
            out.success = r.completed && !out.text.empty();
            if (!out.success)
                out.error = r.cancelled ? "cancelled" : "empty generation";
        } catch (const std::exception& ex) {
            out.error = ex.what();
            out.success = false;
        }
        return out;
    }

    void unload() {
        if (loaded_) {
            engine_.unloadModel();
            loaded_ = false;
            modelPath_.clear();
        }
    }

    bool isLoaded() const { return loaded_; }

    ~Deep2SovereignInferenceGateway() {
        unload();
    }

private:
    Deep2::Deep2Engine engine_;
    bool loaded_ = false;
    std::string modelPath_;
};

} // namespace RawrXD::Agent
