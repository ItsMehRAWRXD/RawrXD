// subsystem_registry.cpp - Implementation of SubsystemRegistry
// Provides subsystem management and invocation

#include <map>
#include <string>
#include <mutex>

// SubsystemId enum definition
enum class SubsystemId {
    LSP_SERVER,
    ASM_ANALYZER,
    HYBRID_ENGINE,
    GPU_SCHEDULER,
    MEMORY_ALLOCATOR,
    COUNT
};

struct SubsystemParams {
    int commandId;
    const void* data;
    size_t dataSize;
};

struct SubsystemResult {
    int status;
    void* output;
    size_t outputSize;
    const char* errorMessage;
};

class SubsystemRegistry {
public:
    SubsystemRegistry() = default;
    ~SubsystemRegistry() = default;
    SubsystemRegistry(const SubsystemRegistry&) = delete;
    SubsystemRegistry& operator=(const SubsystemRegistry&) = delete;

    static SubsystemRegistry& instance() {
        static SubsystemRegistry reg;
        return reg;
    }

    SubsystemResult invoke(const SubsystemParams& params) {
        SubsystemResult result = {};
        result.status = 0;
        return result;
    }

    bool isAvailable(SubsystemId id) const {
        return static_cast<int>(id) < static_cast<int>(SubsystemId::COUNT);
    }

    const char* getSwitchName(SubsystemId id) const {
        switch(id) {
            case SubsystemId::LSP_SERVER: return "lsp";
            case SubsystemId::ASM_ANALYZER: return "asm";
            case SubsystemId::HYBRID_ENGINE: return "hybrid";
            case SubsystemId::GPU_SCHEDULER: return "gpu";
            case SubsystemId::MEMORY_ALLOCATOR: return "memory";
            default: return "unknown";
        }
    }
};

// C-compatible exports
extern "C" {

void* SubsystemRegistry_getInstance() {
    return &SubsystemRegistry::instance();
}

SubsystemResult SubsystemRegistry_invoke(void* registry, const SubsystemParams* params) {
    if (!registry || !params) {
        return {-1, nullptr, 0, "Invalid parameters"};
    }
    return static_cast<SubsystemRegistry*>(registry)->invoke(*params);
}

int SubsystemRegistry_isAvailable(void* registry, int subsystemId) {
    if (!registry) return 0;
    return static_cast<SubsystemRegistry*>(registry)->isAvailable(static_cast<SubsystemId>(subsystemId)) ? 1 : 0;
}

const char* SubsystemRegistry_getSwitchName(void* registry, int subsystemId) {
    if (!registry) return "unknown";
    return static_cast<SubsystemRegistry*>(registry)->getSwitchName(static_cast<SubsystemId>(subsystemId));
}

} // extern "C"
