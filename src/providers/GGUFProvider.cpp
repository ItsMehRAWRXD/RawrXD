#include "GGUFProvider.hpp"
#include "../runtime/rawrxd_model_api.hpp"
#include <iostream>
#include <chrono>

namespace RawrXD {
    
    // Unique instance of engine per provider allocation
    static std::unique_ptr<RawrXDModelEngine> global_engine_instance = nullptr;

    GGUFProvider::GGUFProvider() {
        if (!global_engine_instance) {
            global_engine_instance = std::make_unique<RawrXDModelEngine>();
        }
    }

    bool GGUFProvider::Load(const std::string& model_path) {
        return global_engine_instance->Initialize(model_path);
    }

    std::string GGUFProvider::Generate(const std::string& prompt, const GenerationConfig& cfg) {
        if (!global_engine_instance) return "Error: Engine uninitialized";
        
        auto start = std::chrono::steady_clock::now();
        
        InternalGenerationConfig internal_cfg{cfg.temperature, cfg.top_p, cfg.max_new_tokens};
        std::string result = global_engine_instance->ExecuteInference(prompt, internal_cfg);
        
        auto end = std::chrono::steady_clock::now();
        last_tps = (double)result.size() / std::chrono::duration_cast<std::chrono::duration<double>>(end - start).count();
        last_memory = 0; // Note: telemetry extraction handled internally
        
        return result;
    }
    
    ModelStats GGUFProvider::Stats() {
        return { last_tps, last_memory };
    }

    std::shared_ptr<IModelProvider> CreateGGUFProvider() {
        return std::make_shared<GGUFProvider>();
    }
}
