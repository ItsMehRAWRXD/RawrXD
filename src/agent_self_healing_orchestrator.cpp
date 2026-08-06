#include "agent_self_healing_orchestrator.hpp"

namespace RawrXD {

void SovereignMetaRuntime::AddProvider(const std::string& name, std::shared_ptr<IModelProvider> provider) {
    providers[name] = provider;
}

IModelProvider* SovereignMetaRuntime::Select(const Task& task) {
    if(task.requires_privacy && providers.count("GGUF"))
        return providers["GGUF"].get();
    if(task.requires_speed && providers.count("Ollama"))
        return providers["Ollama"].get();
    if(providers.count("Copilot"))
        return providers["Copilot"].get();
        
    // Fallback
    for (auto& [n, p] : providers) {
        return p.get();
    }
    return nullptr;
}

} // namespace RawrXD
