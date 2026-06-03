#include "ultra_fast_inference.h"

#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <array>
#include <memory>
#include <new>
#include <vector>

void* operator new(std::size_t size) {
    if (size == 0) {
        size = 1;
    }
    return HeapAlloc(GetProcessHeap(), 0, static_cast<SIZE_T>(size));
}

void operator delete(void* ptr) noexcept {
    if (ptr) {
        HeapFree(GetProcessHeap(), 0, ptr);
    }
}

void operator delete(void* ptr, std::size_t) noexcept {
    if (ptr) {
        HeapFree(GetProcessHeap(), 0, ptr);
    }
}

void* operator new[](std::size_t size) {
    if (size == 0) {
        size = 1;
    }
    return HeapAlloc(GetProcessHeap(), 0, static_cast<SIZE_T>(size));
}

void operator delete[](void* ptr) noexcept {
    if (ptr) {
        HeapFree(GetProcessHeap(), 0, ptr);
    }
}

void operator delete[](void* ptr, std::size_t) noexcept {
    if (ptr) {
        HeapFree(GetProcessHeap(), 0, ptr);
    }
}

namespace {

struct HarnessEngine {
    int version = 1;
    float threshold = 0.0f;
    bool initialized = false;
    bool warmup_complete = false;
    size_t profile_window = 1;
    int lane_id = 0;
    std::unique_ptr<int> token_budget;
    std::vector<int> request_ring;

    HarnessEngine() = default;

    bool loadModelAutomatic(const char*) {
        token_budget = std::make_unique<int>(32);
        request_ring.push_back(1);
        request_ring.push_back(2);
        initialized = true;
        warmup_complete = (version > 0) && (threshold >= 0.0f);
        return true;
    }

    rawrxd::inference::AutonomousInferenceEngine::Telemetry inferText(
        const std::string& prompt_text,
        std::function<void(const std::string&)> token_callback,
        size_t max_tokens) {
        rawrxd::inference::AutonomousInferenceEngine::Telemetry telemetry;
        telemetry.prompt_tokens = prompt_text.empty() ? 0u : profile_window + request_ring.size();
        telemetry.generated_tokens =
            (max_tokens > 0 && warmup_complete && lane_id >= 0 && token_budget && *token_budget > 0)
                ? 1u
                : 0u;
        telemetry.context_tokens = telemetry.prompt_tokens + telemetry.generated_tokens + static_cast<size_t>(version > 0 ? 0 : 1);
        telemetry.total_ms = 0.0;
        telemetry.tps = telemetry.generated_tokens > 0 ? 1.0 : 0.0;
        if (token_callback && telemetry.generated_tokens > 0) {
            token_callback("probe");
        }
        return telemetry;
    }
};

struct ProbeEmpty {
    int x;
    ProbeEmpty() : x(7) {}
};

struct ProbeVirtual {
    virtual ~ProbeVirtual() = default;
    virtual int id() const { return 1; }
    ProbeVirtual() = default;
};

struct ProbeStl {
    std::vector<int> data;
    ProbeStl() { data.push_back(1); }
    ~ProbeStl() = default;
};

struct ProbeUniquePtr {
    std::unique_ptr<int> value;
    ProbeUniquePtr() : value(std::make_unique<int>(3)) {}
    ~ProbeUniquePtr() = default;
};

struct ProbeArray {
    std::array<int, 8> values;
    ProbeArray() : values{1, 2, 3, 4, 5, 6, 7, 8} {}
    ~ProbeArray() = default;
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
int g_last_status = 0;

void clear_last_error() {
    g_last_error[0] = '\0';
    g_last_status = 0;
}

void set_last_error(const char* msg) {
    if (!msg) {
        g_last_error[0] = '\0';
        return;
    }
    lstrcpynA(g_last_error, msg, static_cast<int>(sizeof(g_last_error)));
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

__declspec(dllexport) std::uint64_t rawrxd_probe_empty_size() {
    return static_cast<std::uint64_t>(sizeof(ProbeEmpty));
}

__declspec(dllexport) std::uint64_t rawrxd_probe_virtual_size() {
    return static_cast<std::uint64_t>(sizeof(ProbeVirtual));
}

__declspec(dllexport) std::uint64_t rawrxd_probe_stl_size() {
    return static_cast<std::uint64_t>(sizeof(ProbeStl));
}

__declspec(dllexport) std::uint64_t rawrxd_probe_unique_ptr_size() {
    return static_cast<std::uint64_t>(sizeof(ProbeUniquePtr));
}

__declspec(dllexport) std::uint64_t rawrxd_probe_array_size() {
    return static_cast<std::uint64_t>(sizeof(ProbeArray));
}

__declspec(dllexport) void* rawrxd_probe_alloc(std::uint64_t bytes) {
    clear_last_error();
    if (bytes == 0 || bytes > (1ull << 30)) {
        set_last_error("probe_alloc: invalid size");
        return nullptr;
    }

    HANDLE heap = GetProcessHeap();
    if (!heap) {
        set_last_error("probe_alloc: GetProcessHeap failed");
        return nullptr;
    }

    void* mem = HeapAlloc(heap, HEAP_ZERO_MEMORY, static_cast<SIZE_T>(bytes));
    if (!mem) {
        set_last_error("probe_alloc: allocation failed");
        return nullptr;
    }
    return mem;
}

__declspec(dllexport) int rawrxd_probe_free(void* mem) {
    clear_last_error();
    if (!mem) {
        set_last_error("probe_free: null memory pointer");
        return HARNESS_INVALID_ARG;
    }

    HANDLE heap = GetProcessHeap();
    if (!heap) {
        set_last_error("probe_free: GetProcessHeap failed");
        return HARNESS_RUN_FAIL;
    }
    if (!HeapFree(heap, 0, mem)) {
        set_last_error("probe_free: HeapFree failed");
        return HARNESS_RUN_FAIL;
    }
    return HARNESS_OK;
}

__declspec(dllexport) int rawrxd_probe_empty_ctor(void* mem) {
    clear_last_error();
    if (!mem) {
        set_last_error("probe_empty_ctor: null memory pointer");
        return HARNESS_INVALID_ARG;
    }

    try {
        (void)::new (mem) ProbeEmpty();
    } catch (...) {
        set_last_error("probe_empty_ctor: constructor threw");
        return HARNESS_CTOR_FAIL;
    }
    return HARNESS_OK;
}

__declspec(dllexport) int rawrxd_probe_empty_dtor(void* mem) {
    clear_last_error();
    if (!mem) {
        set_last_error("probe_empty_dtor: null memory pointer");
        return HARNESS_INVALID_ARG;
    }
    static_cast<ProbeEmpty*>(mem)->~ProbeEmpty();
    return HARNESS_OK;
}

__declspec(dllexport) int rawrxd_probe_virtual_ctor(void* mem) {
    clear_last_error();
    if (!mem) {
        set_last_error("probe_virtual_ctor: null memory pointer");
        return HARNESS_INVALID_ARG;
    }

    try {
        (void)::new (mem) ProbeVirtual();
    } catch (...) {
        set_last_error("probe_virtual_ctor: constructor threw");
        return HARNESS_CTOR_FAIL;
    }
    return HARNESS_OK;
}

__declspec(dllexport) int rawrxd_probe_virtual_dtor(void* mem) {
    clear_last_error();
    if (!mem) {
        set_last_error("probe_virtual_dtor: null memory pointer");
        return HARNESS_INVALID_ARG;
    }
    static_cast<ProbeVirtual*>(mem)->~ProbeVirtual();
    return HARNESS_OK;
}

__declspec(dllexport) int rawrxd_probe_stl_ctor(void* mem) {
    clear_last_error();
    if (!mem) {
        set_last_error("probe_stl_ctor: null memory pointer");
        return HARNESS_INVALID_ARG;
    }

    try {
        (void)::new (mem) ProbeStl();
    } catch (...) {
        set_last_error("probe_stl_ctor: constructor threw");
        return HARNESS_CTOR_FAIL;
    }
    return HARNESS_OK;
}

__declspec(dllexport) int rawrxd_probe_stl_dtor(void* mem) {
    clear_last_error();
    if (!mem) {
        set_last_error("probe_stl_dtor: null memory pointer");
        return HARNESS_INVALID_ARG;
    }
    static_cast<ProbeStl*>(mem)->~ProbeStl();
    return HARNESS_OK;
}

__declspec(dllexport) int rawrxd_probe_unique_ptr_ctor(void* mem) {
    clear_last_error();
    if (!mem) {
        set_last_error("probe_unique_ptr_ctor: null memory pointer");
        return HARNESS_INVALID_ARG;
    }

    try {
        (void)::new (mem) ProbeUniquePtr();
    } catch (...) {
        set_last_error("probe_unique_ptr_ctor: constructor threw");
        return HARNESS_CTOR_FAIL;
    }
    return HARNESS_OK;
}

__declspec(dllexport) int rawrxd_probe_unique_ptr_dtor(void* mem) {
    clear_last_error();
    if (!mem) {
        set_last_error("probe_unique_ptr_dtor: null memory pointer");
        return HARNESS_INVALID_ARG;
    }
    static_cast<ProbeUniquePtr*>(mem)->~ProbeUniquePtr();
    return HARNESS_OK;
}

__declspec(dllexport) int rawrxd_probe_array_ctor(void* mem) {
    clear_last_error();
    if (!mem) {
        set_last_error("probe_array_ctor: null memory pointer");
        return HARNESS_INVALID_ARG;
    }

    try {
        (void)::new (mem) ProbeArray();
    } catch (...) {
        set_last_error("probe_array_ctor: constructor threw");
        return HARNESS_CTOR_FAIL;
    }
    return HARNESS_OK;
}

__declspec(dllexport) int rawrxd_probe_array_dtor(void* mem) {
    clear_last_error();
    if (!mem) {
        set_last_error("probe_array_dtor: null memory pointer");
        return HARNESS_INVALID_ARG;
    }
    static_cast<ProbeArray*>(mem)->~ProbeArray();
    return HARNESS_OK;
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

    h->initialized = h->loadModelAutomatic(model_path);
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
    auto telem = h->inferText(
        prompt,
        [&](const std::string&) { piece_count++; },
        max_tokens);
    if (piece_count == 0 || telem.generated_tokens == 0) {
        set_last_error("run_cycle: no tokens generated");
        g_last_status = HARNESS_RUN_FAIL;
        return HARNESS_RUN_FAIL;
    }

    g_last_status = HARNESS_OK;

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

__declspec(dllexport) int rawrxd_harness_last_status() {
    return g_last_status;
}

} // extern "C"
