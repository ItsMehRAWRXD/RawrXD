// ============================================================================
// RawrXD_SovereignMain.cpp — Minimal C Bridge for Sovereign Hot Lap
// ============================================================================
//
// This is the C++ bridge called by RawrXD_SovereignEntry.asm.
// It initializes the VulkanAccelerator and fires the first tensor.
//
// Design rules:
//   - No I/O streams (no iostream, no printf if possible — use WriteConsoleA)
//   - No dynamic allocation in the hot loop (all pre-allocated)
//   - Uses existing proven VulkanAccelerator (links against C++ runtime libs)
//
// Build: cl /c /O2 /GS- /W3 /EHsc /nologo RawrXD_SovereignMain.cpp
// ============================================================================

#include "RawrXD_VulkanAccelerator.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <vector>

// ============================================================================
// Windows API for console output (no CRT stdout bloat)
// ============================================================================

extern "C" {
    __declspec(dllimport) int __stdcall WriteConsoleA(
        void* hConsoleOutput,
        const void* lpBuffer,
        uint32_t nNumberOfCharsToWrite,
        uint32_t* lpNumberOfCharsWritten,
        void* lpReserved);
    __declspec(dllimport) void* __stdcall GetStdHandle(uint32_t nStdHandle);
}

constexpr uint32_t STD_OUTPUT_HANDLE = 0xFFFFFFF5;

static void raw_print(const char* msg) {
    void* hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!hOut) return;
    uint32_t len = 0;
    while (msg[len]) ++len;
    uint32_t written = 0;
    WriteConsoleA(hOut, msg, len, &written, nullptr);
}

// ============================================================================
// CPU reference RMSNorm (for verification)
// ============================================================================
static void cpu_rmsnorm(const float* x, const float* w, float* y,
                        uint32_t hidden_size, float eps) {
    float sum_sq = 0.0f;
    for (uint32_t i = 0; i < hidden_size; ++i) {
        float v = x[i];
        sum_sq += v * v;
    }
    float rms = std::sqrt(sum_sq / static_cast<float>(hidden_size) + eps);
    float inv_rms = 1.0f / rms;
    for (uint32_t i = 0; i < hidden_size; ++i) {
        y[i] = x[i] * inv_rms * w[i];
    }
}

// ============================================================================
// Sovereign allocator shim — routes CRT malloc/free to kernel32 HeapAlloc/HeapFree
// because /NODEFAULTLIB skips CRT heap initialization.
// ============================================================================

extern "C" {
    __declspec(dllimport) void* __stdcall GetProcessHeap(void);
    __declspec(dllimport) void* __stdcall HeapAlloc(void* hHeap, uint32_t dwFlags, size_t dwBytes);
    __declspec(dllimport) int   __stdcall HeapFree(void* hHeap, uint32_t dwFlags, void* lpMem);
    __declspec(dllimport) void* __stdcall HeapReAlloc(void* hHeap, uint32_t dwFlags, void* lpMem, size_t dwBytes);
    __declspec(dllimport) size_t __stdcall HeapSize(void* hHeap, uint32_t dwFlags, const void* lpMem);
}

extern "C" void* malloc(size_t size) {
    return HeapAlloc(GetProcessHeap(), 0, size);
}

extern "C" void free(void* ptr) {
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

extern "C" void* calloc(size_t num, size_t size) {
    return HeapAlloc(GetProcessHeap(), 0x00000008, num * size); // HEAP_ZERO_MEMORY
}

extern "C" void* realloc(void* ptr, size_t size) {
    if (!ptr) return malloc(size);
    void* h = GetProcessHeap();
    void* new_ptr = HeapAlloc(h, 0, size);
    if (new_ptr) {
        size_t old_size = HeapSize(h, 0, ptr);
        size_t copy_size = (old_size < size) ? old_size : size;
        // Manual memcpy — compiler will inline
        char* dst = static_cast<char*>(new_ptr);
        const char* src = static_cast<const char*>(ptr);
        for (size_t i = 0; i < copy_size; ++i) dst[i] = src[i];
        HeapFree(h, 0, ptr);
    }
    return new_ptr;
}

// Also provide memset/memcpy for any CRT-less paths
#pragma function(memset)
extern "C" void* memset(void* dest, int c, size_t count) {
    unsigned char* p = static_cast<unsigned char*>(dest);
    while (count--) *p++ = static_cast<unsigned char>(c);
    return dest;
}

#pragma function(memcpy)
extern "C" void* memcpy(void* dest, const void* src, size_t count) {
    unsigned char* d = static_cast<unsigned char*>(dest);
    const unsigned char* s = static_cast<const unsigned char*>(src);
    while (count--) *d++ = *s++;
    return dest;
}

#pragma function(memmove)
extern "C" void* memmove(void* dest, const void* src, size_t count) {
    unsigned char* d = static_cast<unsigned char*>(dest);
    const unsigned char* s = static_cast<const unsigned char*>(src);
    if (d < s) {
        while (count--) *d++ = *s++;
    } else if (d > s) {
        d += count; s += count;
        while (count--) *--d = *--s;
    }
    return dest;
}

// ============================================================================
// Debug tracing via OutputDebugStringA (kernel32, no CRT)
// ============================================================================
extern "C" {
    __declspec(dllimport) void __stdcall OutputDebugStringA(const char* lpOutputString);
}

static void dbg(const char* msg) {
    OutputDebugStringA(msg);
    raw_print(msg);
}

// ============================================================================
// Kernel32 file I/O for loading SPIR-V without CRT stdio
// ============================================================================
extern "C" {
    __declspec(dllimport) void* __stdcall CreateFileA(const char* lpFileName, uint32_t dwDesiredAccess, uint32_t dwShareMode, void* lpSecurityAttributes, uint32_t dwCreationDisposition, uint32_t dwFlagsAndAttributes, void* hTemplateFile);
    __declspec(dllimport) int   __stdcall ReadFile(void* hFile, void* lpBuffer, uint32_t nNumberOfBytesToRead, uint32_t* lpNumberOfBytesRead, void* lpOverlapped);
    __declspec(dllimport) uint32_t __stdcall GetFileSize(void* hFile, uint32_t* lpFileSizeHigh);
    __declspec(dllimport) int   __stdcall CloseHandle(void* hObject);
}

constexpr uint32_t GENERIC_READ = 0x80000000;
constexpr uint32_t OPEN_EXISTING  = 3;
constexpr uint32_t FILE_SHARE_READ = 1;
constexpr uint32_t FILE_ATTRIBUTE_NORMAL = 0x80;
#define INVALID_HANDLE_VALUE reinterpret_cast<void*>(static_cast<uintptr_t>(-1))

static void* load_file_kernel32(const char* path, size_t* out_size) {
    void* h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return nullptr;
    uint32_t size_lo = GetFileSize(h, nullptr);
    if (size_lo == 0xFFFFFFFF) { CloseHandle(h); return nullptr; }
    void* buf = malloc(size_lo);
    if (!buf) { CloseHandle(h); return nullptr; }
    uint32_t read = 0;
    if (!ReadFile(h, buf, size_lo, &read, nullptr) || read != size_lo) {
        free(buf); CloseHandle(h); return nullptr;
    }
    CloseHandle(h);
    *out_size = read;
    return buf;
}

// ============================================================================
// Global accelerator pointer — constructed explicitly in Engine_Init
// to avoid reliance on CRT global constructor invocation.
// ============================================================================
static rawrxd::VulkanAccelerator* g_sovereign_accel = nullptr;

// ============================================================================
// Engine_Init — Called once from MASM entry point
// Returns: 0 on success, non-zero on failure
// ============================================================================
extern "C" int Engine_Init(void) {
    dbg("[Sovereign] Engine_Init: VulkanAccelerator warming up...\r\n");

    // Explicit construction via placement new — CRT global ctors are skipped
    void* mem = malloc(sizeof(rawrxd::VulkanAccelerator));
    if (!mem) {
        dbg("[Sovereign] FAIL: malloc for accelerator failed\r\n");
        return 1;
    }
    g_sovereign_accel = new (mem) rawrxd::VulkanAccelerator();

    if (!g_sovereign_accel->Initialize()) {
        dbg("[Sovereign] FAIL: VulkanAccelerator::Initialize() returned false\r\n");
        return 1;
    }
    dbg("[Sovereign] Engine_Init: GPU ready\r\n");
    return 0;
}

// ============================================================================
// ECU_Loop — The sovereign governor loop
// Returns: 0 on success (all tokens processed), non-zero on failure
// ============================================================================
extern "C" int ECU_Loop(void) {
    dbg("[Sovereign] ECU_Loop: entering hot lap\r\n");

    if (!g_sovereign_accel || !g_sovereign_accel->IsReady()) {
        dbg("[Sovereign] FAIL: accelerator not ready\r\n");
        return 1;
    }
    dbg("[Sovereign] Accelerator is ready\r\n");

    // ------------------------------------------------------------------------
    // Load RMSNorm kernel via kernel32 file I/O (no CRT stdio)
    // ------------------------------------------------------------------------
    const char* spv_path = "../../src/inference/kernels/rmsnorm.spv";
    dbg("[Sovereign] Loading SPIR-V file...\r\n");
    size_t spv_size = 0;
    void* spv_data = load_file_kernel32(spv_path, &spv_size);
    if (!spv_data) {
        dbg("[Sovereign] FAIL: could not load SPIR-V file\r\n");
        return 1;
    }
    dbg("[Sovereign] SPIR-V loaded, size=");
    char szbuf[32];
    std::snprintf(szbuf, sizeof(szbuf), "%zu\r\n", spv_size);
    dbg(szbuf);

    dbg("[Sovereign] Calling LoadKernelFromMemory...\r\n");
    uint32_t kernel_id = g_sovereign_accel->LoadKernelFromMemory("rmsnorm", spv_data, spv_size, 3);
    free(spv_data);
    if (kernel_id == 0) {
        dbg("[Sovereign] FAIL: LoadKernelFromMemory returned 0\r\n");
        return 1;
    }
    dbg("[Sovereign] Kernel loaded\r\n");

    // ------------------------------------------------------------------------
    // Prepare synthetic tensors (hidden_size = 256, 1 row)
    // ------------------------------------------------------------------------
    constexpr uint32_t hidden_size = 256;
    constexpr uint32_t num_rows    = 1;
    constexpr float    eps         = 1e-6f;

    // Use stack-allocated arrays to avoid heap in hot loop
    alignas(64) float host_x[hidden_size];
    alignas(64) float host_w[hidden_size];
    alignas(64) float host_y[hidden_size];
    alignas(64) float ref_y[hidden_size];

    for (uint32_t i = 0; i < hidden_size; ++i) {
        host_x[i] = static_cast<float>(i + 1) * 0.01f;
        host_w[i] = 1.0f;
    }

    // ------------------------------------------------------------------------
    // Upload tensors to VRAM
    // ------------------------------------------------------------------------
    rawrxd::TensorDesc desc_x{};
    desc_x.name = "rmsnorm_input";
    desc_x.format = rawrxd::TensorFormat::F32;
    desc_x.rows = num_rows;
    desc_x.cols = hidden_size;
    desc_x.host_ptr = host_x;
    desc_x.size_bytes = hidden_size * sizeof(float);

    rawrxd::TensorDesc desc_w{};
    desc_w.name = "rmsnorm_weight";
    desc_w.format = rawrxd::TensorFormat::F32;
    desc_w.rows = 1;
    desc_w.cols = hidden_size;
    desc_w.host_ptr = host_w;
    desc_w.size_bytes = hidden_size * sizeof(float);

    rawrxd::TensorDesc desc_y{};
    desc_y.name = "rmsnorm_output";
    desc_y.format = rawrxd::TensorFormat::F32;
    desc_y.rows = num_rows;
    desc_y.cols = hidden_size;
    desc_y.host_ptr = nullptr;
    desc_y.size_bytes = hidden_size * sizeof(float);

    rawrxd::GpuTensorHandle h_x = g_sovereign_accel->UploadTensor(desc_x, false);
    rawrxd::GpuTensorHandle h_w = g_sovereign_accel->UploadTensor(desc_w, false);
    rawrxd::GpuTensorHandle h_y = g_sovereign_accel->UploadTensor(desc_y, false);

    if (!h_x.IsValid() || !h_w.IsValid() || !h_y.IsValid()) {
        dbg("[Sovereign] FAIL: tensor upload failed\r\n");
        return 1;
    }
    dbg("[Sovereign] Tensors uploaded\r\n");

    // ------------------------------------------------------------------------
    // The Hot Lap: dispatch RMSNorm 10 times, measuring consistency
    // ------------------------------------------------------------------------
    rawrxd::RMSNormDesc rms_desc{};
    rms_desc.input = h_x;
    rms_desc.output = h_y;
    rms_desc.weight = h_w;
    rms_desc.hidden_size = hidden_size;
    rms_desc.eps = eps;
    rms_desc.num_rows = num_rows;

    bool all_pass = true;
    float max_err_overall = 0.0f;

    for (int lap = 0; lap < 10; ++lap) {
        if (!g_sovereign_accel->DispatchRMSNorm(rms_desc, kernel_id)) {
            dbg("[Sovereign] FAIL: DispatchRMSNorm failed\r\n");
            all_pass = false;
            break;
        }
        if (!g_sovereign_accel->Wait(10'000'000'000ULL)) {
            dbg("[Sovereign] FAIL: Wait timed out\r\n");
            all_pass = false;
            break;
        }

        // Readback and verify
        std::memset(host_y, 0, sizeof(host_y));
        if (!g_sovereign_accel->ReadbackTensor(h_y, host_y)) {
            dbg("[Sovereign] FAIL: ReadbackTensor failed\r\n");
            all_pass = false;
            break;
        }

        cpu_rmsnorm(host_x, host_w, ref_y, hidden_size, eps);

        float max_err = 0.0f;
        for (uint32_t i = 0; i < hidden_size; ++i) {
            float diff = std::fabs(host_y[i] - ref_y[i]);
            if (diff > max_err) max_err = diff;
        }
        if (max_err > max_err_overall) max_err_overall = max_err;
        if (max_err > 1e-4f) {
            all_pass = false;
            dbg("[Sovereign] FAIL: numerical mismatch\r\n");
            break;
        }
    }

    // ------------------------------------------------------------------------
    // Cleanup
    // ------------------------------------------------------------------------
    g_sovereign_accel->Shutdown();

    if (all_pass) {
        dbg("[Sovereign] HOT LAP PASS: 10 cycles, max_err=");
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%.6e\r\n", max_err_overall);
        dbg(buf);
        dbg("[Sovereign] Engine shutdown clean. Sovereign binary verified.\r\n");
        return 0;
    }

    dbg("[Sovereign] HOT LAP FAIL\r\n");
    return 1;
}
