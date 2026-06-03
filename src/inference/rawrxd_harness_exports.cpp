#include "ultra_fast_inference.h"

#include <windows.h>
#include <cstdint>
#include <new>

namespace {

struct HarnessEngine {
    rawrxd::inference::AutonomousInferenceEngine engine;
    bool initialized = false;

    HarnessEngine()
        : engine(rawrxd::inference::AutonomousInferenceEngine::InferenceConfig{}) {}
};

enum HarnessStatus : int {
    HARNESS_OK = 0,
    HARNESS_INVALID_ARG = 1,
    HARNESS_ALLOC_FAIL = 2,
    HARNESS_CTOR_FAIL = 3,
    HARNESS_INIT_FAIL = 4,
    HARNESS_NOT_INITIALIZED = 5,
    HARNESS_RUN_FAIL = 6
};

char g_last_error[256] = {0};

void clear_last_error() {
    g_last_error[0] = '\0';
}

void set_last_error(const char* msg) {
    if (!msg) {
        g_last_error[0] = '\0';
        return;
    }
    lstrcpynA(g_last_error, msg, static_cast<int>(sizeof(g_last_error)));
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

    if (lstrcmpA(value, "1") != 0) {
        SetEnvironmentVariableA("RAWRXD_ENABLE_REAL_FORWARD", "1");
    }
}

} // namespace

extern "C" {

__declspec(dllexport) void* rawrxd_harness_alloc_engine() {
    clear_last_error();

    HANDLE heap = GetProcessHeap();
    if (!heap) {
        set_last_error("alloc_engine: GetProcessHeap failed");
        return nullptr;
    }

    void* mem = HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(HarnessEngine));
    if (!mem) {
        set_last_error("alloc_engine: allocation failed");
        return nullptr;
    }
    return mem;
}

__declspec(dllexport) int rawrxd_harness_ctor_engine(void* mem) {
    clear_last_error();

    if (!mem) {
        set_last_error("ctor_engine: null memory pointer");
        return HARNESS_INVALID_ARG;
    }

    try {
        (void)::new (mem) HarnessEngine();
    } catch (...) {
        set_last_error("ctor_engine: constructor threw");
        return HARNESS_CTOR_FAIL;
    }

    return HARNESS_OK;
}

__declspec(dllexport) int rawrxd_harness_init_model(void* engine, const char* model_path) {
    clear_last_error();

    auto* h = static_cast<HarnessEngine*>(engine);
    if (!h) {
        set_last_error("init_model: null engine");
        return HARNESS_INVALID_ARG;
    }

    if (!model_path || model_path[0] == '\0') {
        set_last_error("init_model: missing model path");
        return HARNESS_INVALID_ARG;
    }

    apply_real_forward_env_gate();

    h->initialized = h->engine.loadModelAutomatic(model_path);
    if (!h->initialized) {
        set_last_error("init_model: loadModelAutomatic failed");
        return HARNESS_INIT_FAIL;
    }

    return HARNESS_OK;
}

__declspec(dllexport) int rawrxd_harness_run_cycle(void* engine, const char* prompt, uint32_t max_tokens) {
    clear_last_error();

    auto* h = static_cast<HarnessEngine*>(engine);
    if (!h || !h->initialized) {
        set_last_error("run_cycle: engine not initialized");
        return HARNESS_NOT_INITIALIZED;
    }

    if (!prompt || prompt[0] == '\0') {
        set_last_error("run_cycle: missing prompt");
        return HARNESS_INVALID_ARG;
    }

    size_t piece_count = 0;
    auto telem = h->engine.inferText(
        prompt,
        [&](const std::string&) { piece_count++; },
        max_tokens);
    if (piece_count == 0 || telem.generated_tokens == 0) {
        set_last_error("run_cycle: no tokens generated");
        return HARNESS_RUN_FAIL;
    }

    return HARNESS_OK;
}

__declspec(dllexport) int rawrxd_harness_dtor_engine(void* engine) {
    clear_last_error();

    auto* h = static_cast<HarnessEngine*>(engine);
    if (!h) {
        set_last_error("dtor_engine: null engine");
        return HARNESS_INVALID_ARG;
    }

    h->~HarnessEngine();
    return HARNESS_OK;
}

__declspec(dllexport) int rawrxd_harness_free_engine(void* mem) {
    clear_last_error();

    if (!mem) {
        set_last_error("free_engine: null memory pointer");
        return HARNESS_INVALID_ARG;
    }

    HANDLE heap = GetProcessHeap();
    if (!heap) {
        set_last_error("free_engine: GetProcessHeap failed");
        return HARNESS_RUN_FAIL;
    }
    if (!HeapFree(heap, 0, mem)) {
        set_last_error("free_engine: HeapFree failed");
        return HARNESS_RUN_FAIL;
    }
    return HARNESS_OK;
}

__declspec(dllexport) const char* rawrxd_harness_last_error() {
    return g_last_error;
}

} // extern "C"
