// SovereignInferenceClient_stub.cpp
// Minimal stub for TransformerStackOrchestrator linkage when the real
// LlamaNativeBridge-dependent implementation is excluded.

#include "../agentic/SovereignInferenceClient.h"

namespace RawrXD {
namespace Agent {

bool SovereignInferenceClient::IsLoaded() const {
    // Stub: always reports not loaded. The orchestrator allows null client
    // for Phase 3.1 deterministic replay harness.
    return false;
}

} // namespace Agent
} // namespace RawrXD
