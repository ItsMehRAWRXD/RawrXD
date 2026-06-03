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

static_assert(
    alignof(rawrxd::inference::AutonomousInferenceEngine) <= 16,
    "Engine alignment violation");

struct HarnessEngine {
    rawrxd::inference::AutonomousInferenceEngine engine;
    bool initialized = false;

    HarnessEngine()
        : engine([] {
            rawrxd::inference::AutonomousInferenceEngine::InferenceConfig cfg;
                        cfg.enable_gpu = false;
            cfg.enable_hotpatching = false;
            cfg.enable_async_inference = false;
                        cfg.enable_ollama_blob_support = false;
            return cfg;
          }()) {}

    bool loadModelAutomatic(const std::string& model_path) {
        return engine.loadModelAutomatic(model_path);
    }

    rawrxd::inference::AutonomousInferenceEngine::Telemetry inferText(
        const std::string& prompt_text,
        const std::function<void(const std::string&)>& token_callback,
        size_t max_tokens) {
        return engine.inferText(prompt_text, token_callback, max_tokens);
    }
};

void apply_real_forward_env_gate() {
    char value[16] = {};
    DWORD n = GetEnvironmentVariableA("RAWRXD_ENABLE_REAL_FORWARD", value, static_cast<DWORD>(sizeof(value)));
    if (n == 0 || n >= sizeof(value) || lstrcmpA(value, "1") != 0) {
        SetEnvironmentVariableA("RAWRXD_ENABLE_REAL_FORWARD", "1");
    }
}

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
void* g_veh_handle = nullptr;
std::uint64_t g_last_fault_rip = 0;
std::uint32_t g_last_fault_code = 0;

LONG CALLBACK harness_vectored_exception_handler(EXCEPTION_POINTERS* info) {
    if (!info || !info->ExceptionRecord || !info->ContextRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    g_last_fault_code = info->ExceptionRecord->ExceptionCode;
#if defined(_M_X64)
    g_last_fault_rip = static_cast<std::uint64_t>(info->ContextRecord->Rip);
#else
    g_last_fault_rip = 0;
#endif

    return EXCEPTION_CONTINUE_SEARCH;
}

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

    apply_real_forward_env_gate();

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

__declspec(dllexport) int rawrxd_harness_install_veh() {
    if (!g_veh_handle) {
        g_veh_handle = AddVectoredExceptionHandler(1, harness_vectored_exception_handler);
        if (!g_veh_handle) {
            set_last_error("install_veh: AddVectoredExceptionHandler failed");
            return HARNESS_RUN_FAIL;
        }
    }
    return HARNESS_OK;
}

__declspec(dllexport) std::uint64_t rawrxd_harness_last_fault_rip() {
    return g_last_fault_rip;
}

__declspec(dllexport) std::uint32_t rawrxd_harness_last_fault_code() {
    return g_last_fault_code;
}

} // extern "C"
