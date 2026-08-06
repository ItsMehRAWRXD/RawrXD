#pragma once
#include "../agent_self_healing_orchestrator.hpp"
#include <string>
#include <memory>

namespace RawrXD {
    class GGUFProvider : public IModelProvider {
    public:
        GGUFProvider();
        ~GGUFProvider() override = default;

        bool Load(const std::string& model_path) override;
        std::string Generate(const std::string& prompt, const GenerationConfig& cfg) override;
        ModelStats Stats() override;
        
    private:
        double last_tps = 0.0;
        size_t last_memory = 0;
    };

    std::shared_ptr<IModelProvider> CreateGGUFProvider();
}
