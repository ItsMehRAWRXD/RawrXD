#include "local_reasoning_integration.hpp"

// Definitions must live in namespace rawrxd::agent to match the declarations
// in local_reasoning_integration.hpp (the TU previously defined them at
// global scope, which produced C2143/C2447 at the function bodies).
namespace rawrxd::agent {

namespace {
LocalReasoningEngine& MutableEngineInstance() {
    static LocalReasoningEngine s_instance;
    return s_instance;
}
bool s_initialized = false;
} // namespace

LocalReasoningEngine& LocalReasoningIntegration::instance() {
    return MutableEngineInstance();
}

void LocalReasoningIntegration::Initialize(const ReasoningConfig& config) {
    MutableEngineInstance().SetConfig(config);
    s_initialized = true;
}

void LocalReasoningIntegration::Shutdown() {
    MutableEngineInstance().ClearHistory();
    s_initialized = false;
}

bool LocalReasoningIntegration::IsInitialized() {
    return s_initialized;
}

} // namespace rawrxd::agent
