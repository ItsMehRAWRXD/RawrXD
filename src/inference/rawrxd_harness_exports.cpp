#include "ultra_fast_inference.h"

#include <windows.h>
#include <cstdint>
#include <new>
#include <string>

namespace {

struct HarnessEngine {
    rawrxd::inference::AutonomousInferenceEngine engine;
    bool initialized = false;

    HarnessEngine()
        : engine(rawrxd::inference::AutonomousInferenceEngine::InferenceConfig{}) {}
};

thread_local std::string g_last_error;

void set_last_error(const std::string& msg) {
    g_last_error = msg;
}

void apply_real_forward_env_gate() {
    char value[16] = {};
    DWORD n = GetEnvironmentVariableA("RAWRXD_ENABLE_REAL_FORWARD", value, static_cast<DWORD>(sizeof(value)));
    if (n == 0) {
        SetEnvironmentVariableA("RAWRXD_ENABLE_REAL_FORWARD", "1");
        return;
    }

    if (n >= sizeof(value)) {
        SetEnvironmentVariableA("RAWRXD_ENABLE_REAL_FORWARD", "1");
        return;
    }

    if (std::string(value) != "1") {
        SetEnvironmentVariableA("RAWRXD_ENABLE_REAL_FORWARD", "1");
    }
}

} // namespace

extern "C" {

__declspec(dllexport) void* rawrxd_harness_create_engine(const char* model_path) {
    g_last_error.clear();

    if (!model_path || model_path[0] == '\0') {
        set_last_error("create_engine: missing model path");
        return nullptr;
    }

    apply_real_forward_env_gate();

    auto* h = new (std::nothrow) HarnessEngine();
    if (!h) {
        set_last_error("create_engine: allocation failed");
        return nullptr;
    }

    h->initialized = h->engine.loadModelAutomatic(model_path);
    if (!h->initialized) {
        set_last_error("create_engine: init failed");
        delete h;
        return nullptr;
    }

    return h;
}

__declspec(dllexport) int rawrxd_harness_run_cycle(void* engine, const char* prompt, uint32_t max_tokens) {
    auto* h = static_cast<HarnessEngine*>(engine);
    if (!h || !h->initialized) {
        set_last_error("run_cycle: engine not initialized");
        return 0;
    }

    if (!prompt || prompt[0] == '\0') {
        set_last_error("run_cycle: missing prompt");
        return 0;
    }

    size_t piece_count = 0;
    auto telem = h->engine.inferText(
        prompt,
        [&](const std::string&) { piece_count++; },
        max_tokens);
    if (piece_count == 0 || telem.generated_tokens == 0) {
        set_last_error("run_cycle: no tokens generated");
        return 0;
    }

    return 1;
}

__declspec(dllexport) void rawrxd_harness_destroy_engine(void* engine) {
    auto* h = static_cast<HarnessEngine*>(engine);
    delete h;
}

__declspec(dllexport) const char* rawrxd_harness_last_error() {
    return g_last_error.c_str();
}

} // extern "C"
