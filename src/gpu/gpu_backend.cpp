#include "gpu_backend.h"
<<<<<<< HEAD
#include <cstdio>
#include <cstdint>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
=======
#include "../gpu_masm/gpu_masm_bridge.h"
#include "../ggml_masm/ggml_masm_bridge.h"
#include "../../include/vulkan_compute.h"
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <system_error>
#include <limits>
#include <vector>
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

// Static member initialization
GpuBackend::Backend GpuBackend::s_currentBackend = GpuBackend::CPU;
bool GpuBackend::s_initialized = false;

bool GpuBackend::initialize(Backend backend)
{
    if (s_initialized && s_currentBackend == backend) {
<<<<<<< HEAD
        fprintf(stderr, "[GpuBackend] Already initialized: %s\n", backendName(backend));
        return true;
    }

    switch (backend) {
    case Vulkan:
        if (initializeVulkan()) {
            s_currentBackend = Vulkan;
            s_initialized = true;
            return true;
        }
        fprintf(stderr, "[GpuBackend] WARNING: Failed to initialize Vulkan, falling back to CPU\n");
        return initializeCpu();

    case CUDA:
        if (initializeCuda()) {
            s_currentBackend = CUDA;
            s_initialized = true;
            return true;
        }
        fprintf(stderr, "[GpuBackend] WARNING: Failed to initialize CUDA, falling back to CPU\n");
        return initializeCpu();

    case CPU:
        return initializeCpu();
    }

    return false;
=======
        return true;
    }

    // Initialize GPU detection system first
    if (GPU_Initialize() != 0) {
        return initializeCpu();
    }

    // Detect available GPUs
    int32_t gpuCount = GPU_Detect();

    // Map our backend enum to MASM backend codes (0=CPU, 1=Vulkan, 2=CUDA, 3=ROCm)
    int64_t masmBackend = 0;
    switch (backend) {
    case Vulkan:
        masmBackend = 1;
        break;
    case CUDA:
        masmBackend = 2;
        break;
    case CPU:
        masmBackend = 0;
        break;
    }

    // Call MASM backend initialization
    int64_t result = InitializeGPUBackend(masmBackend);
    
    if (result == 0) {
        // Success - update state
        s_currentBackend = backend;
        s_initialized = true;
        return true;
    } else {
        // Failed - try CPU fallback
        result = InitializeGPUBackend(0); // Force CPU mode
        if (result == 0) {
            s_currentBackend = CPU;
            s_initialized = true;
            return true;
        }
        return false;
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

GpuBackend::Backend GpuBackend::currentBackend()
{
    return s_currentBackend;
}

bool GpuBackend::isBackendAvailable(Backend backend)
{
<<<<<<< HEAD
    switch (backend) {
    case Vulkan: {
        fprintf(stderr, "[GpuBackend] Probing Vulkan runtime...\n");
#ifdef _WIN32
        HMODULE hLib = LoadLibraryA("vulkan-1.dll");
        if (hLib) {
            // Verify we can resolve vkCreateInstance
            auto pfn = GetProcAddress(hLib, "vkCreateInstance");
            FreeLibrary(hLib);
            bool avail = (pfn != nullptr);
            fprintf(stderr, "[GpuBackend] Vulkan %s\n", avail ? "AVAILABLE" : "NOT AVAILABLE (missing vkCreateInstance)");
            return avail;
        }
        fprintf(stderr, "[GpuBackend] Vulkan NOT AVAILABLE (vulkan-1.dll not found)\n");
        return false;
#else
        void* lib = dlopen("libvulkan.so.1", RTLD_LAZY);
        if (lib) {
            void* pfn = dlsym(lib, "vkCreateInstance");
            dlclose(lib);
            bool avail = (pfn != nullptr);
            fprintf(stderr, "[GpuBackend] Vulkan %s\n", avail ? "AVAILABLE" : "NOT AVAILABLE");
            return avail;
        }
        fprintf(stderr, "[GpuBackend] Vulkan NOT AVAILABLE (libvulkan.so.1 not found)\n");
        return false;
#endif
    }
    case CUDA: {
        fprintf(stderr, "[GpuBackend] Probing CUDA runtime...\n");
#ifdef _WIN32
        HMODULE hLib = LoadLibraryA("nvcuda.dll");
        if (hLib) {
            auto pfn = GetProcAddress(hLib, "cuInit");
            FreeLibrary(hLib);
            bool avail = (pfn != nullptr);
            fprintf(stderr, "[GpuBackend] CUDA %s\n", avail ? "AVAILABLE" : "NOT AVAILABLE (missing cuInit)");
            return avail;
        }
        fprintf(stderr, "[GpuBackend] CUDA NOT AVAILABLE (nvcuda.dll not found)\n");
        return false;
#else
        void* lib = dlopen("libcuda.so", RTLD_LAZY);
        if (lib) {
            void* pfn = dlsym(lib, "cuInit");
            dlclose(lib);
            bool avail = (pfn != nullptr);
            fprintf(stderr, "[GpuBackend] CUDA %s\n", avail ? "AVAILABLE" : "NOT AVAILABLE");
            return avail;
        }
        fprintf(stderr, "[GpuBackend] CUDA NOT AVAILABLE (libcuda.so not found)\n");
        return false;
#endif
    }
=======
    // Initialize GPU detection if not already done
    static bool detectionInitialized = false;
    if (!detectionInitialized) {
        GPU_Initialize();
        GPU_Detect();
        detectionInitialized = true;
    }

    int32_t gpuCount = GPU_GetDeviceCount();
    
    switch (backend) {
    case Vulkan:
        // Check if any GPU is available (Vulkan supports NVIDIA, AMD, Intel)
        return gpuCount > 0;
        
    case CUDA:
        // Check for NVIDIA GPU specifically
        for (int32_t i = 0; i < gpuCount; i++) {
            GpuDeviceInfo devInfo;
            if (GPU_GetDevice(i, &devInfo) == 0) {
                // NVIDIA vendor ID is 0x10DE
                if (devInfo.vendorId == 0x10DE) {
                    return true;
                }
            }
        }
        return false;
        
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    case CPU:
        return true;  // CPU always available
    }
    return false;
}

<<<<<<< HEAD
const char* GpuBackend::backendName(Backend backend)
=======
std::string GpuBackend::backendName(Backend backend)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
{
    switch (backend) {
    case CPU:
        return "CPU";
    case Vulkan:
        return "Vulkan";
    case CUDA:
        return "CUDA";
    }
    return "Unknown";
}

bool GpuBackend::initializeWithFallback()
{
<<<<<<< HEAD
    // Try Vulkan first
    if (isBackendAvailable(Vulkan) && initializeVulkan()) {
        s_currentBackend = Vulkan;
        s_initialized = true;
        fprintf(stderr, "[GpuBackend] OK: GPU Backend initialized with Vulkan\n");
        return true;
    }

    // Fall back to CUDA
    if (isBackendAvailable(CUDA) && initializeCuda()) {
        s_currentBackend = CUDA;
        s_initialized = true;
        fprintf(stderr, "[GpuBackend] OK: GPU Backend initialized with CUDA\n");
        return true;
    }

    // Final fallback to CPU
    fprintf(stderr, "[GpuBackend] WARNING: No GPU backends available, falling back to CPU (slower performance)\n");
    return initializeCpu();
=======
    // Try Vulkan first (most compatible)
    if (isBackendAvailable(Vulkan)) {
        if (initialize(Vulkan)) {
            return true;
        }
    }

    // Fall back to CUDA (NVIDIA only)
    if (isBackendAvailable(CUDA)) {
        if (initialize(CUDA)) {
            return true;
        }
    }

    // Final fallback to CPU
    return initialize(CPU);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

bool GpuBackend::initializeVulkan()
{
<<<<<<< HEAD
    fprintf(stderr, "[GpuBackend] Attempting to initialize Vulkan...\n");

#ifdef _WIN32
    HMODULE hVulkan = LoadLibraryA("vulkan-1.dll");
    if (!hVulkan) {
        fprintf(stderr, "[GpuBackend] FAILED: vulkan-1.dll not found (error %lu)\n", GetLastError());
        return false;
    }

    // Resolve vkCreateInstance
    typedef int (*PFN_vkCreateInstance)(const void*, const void*, void**);
    auto pfnCreateInstance = (PFN_vkCreateInstance)GetProcAddress(hVulkan, "vkCreateInstance");
    if (!pfnCreateInstance) {
        fprintf(stderr, "[GpuBackend] FAILED: vkCreateInstance not found in vulkan-1.dll\n");
        FreeLibrary(hVulkan);
        return false;
    }

    // Attempt minimal Vulkan instance creation to validate driver
    struct VkApplicationInfo {
        int sType; const void* pNext; const char* pAppName; uint32_t appVer;
        const char* pEngineName; uint32_t engineVer; uint32_t apiVer;
    };
    struct VkInstanceCreateInfo {
        int sType; const void* pNext; uint32_t flags;
        const VkApplicationInfo* pAppInfo;
        uint32_t layerCount; const char* const* ppLayers;
        uint32_t extCount; const char* const* ppExts;
    };

    VkApplicationInfo appInfo = {};
    appInfo.sType = 0; // VK_STRUCTURE_TYPE_APPLICATION_INFO
    appInfo.pAppName = "RawrXD";
    appInfo.apiVer = (1 << 22) | (0 << 12); // VK 1.0

    VkInstanceCreateInfo createInfo = {};
    createInfo.sType = 1; // VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO
    createInfo.pAppInfo = &appInfo;

    void* instance = nullptr;
    int vkResult = pfnCreateInstance(&createInfo, nullptr, &instance);

    if (vkResult != 0 || !instance) {
        fprintf(stderr, "[GpuBackend] FAILED: vkCreateInstance returned %d\n", vkResult);
        FreeLibrary(hVulkan);
        return false;
    }

    // Clean up the test instance
    typedef void (*PFN_vkDestroyInstance)(void*, const void*);
    auto pfnDestroy = (PFN_vkDestroyInstance)GetProcAddress(hVulkan, "vkDestroyInstance");
    if (pfnDestroy && instance) {
        pfnDestroy(instance, nullptr);
    }

    // Keep vulkan-1.dll loaded for future use
    fprintf(stderr, "[GpuBackend] OK: Vulkan initialized successfully (driver validated)\n");
    return true;
#else
    // POSIX: dlopen libvulkan
    void* lib = dlopen("libvulkan.so.1", RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "[GpuBackend] FAILED: libvulkan.so.1 not found\n");
        return false;
    }
    fprintf(stderr, "[GpuBackend] OK: Vulkan library loaded\n");
    return true;
#endif
=======
    
    // Create Vulkan instance through MASM
    int64_t result = VK_CreateInstance();
    if (result != 0) {
        return false;
    }

    // Enumerate physical devices
    int32_t deviceCount = VK_EnumeratePhysicalDevices();
    if (deviceCount == 0) {
        VK_DestroyInstance();
        return false;
    }

    return true;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

bool GpuBackend::initializeCuda()
{
<<<<<<< HEAD
    fprintf(stderr, "[GpuBackend] Attempting to initialize CUDA...\n");

#ifdef _WIN32
    HMODULE hCuda = LoadLibraryA("nvcuda.dll");
    if (!hCuda) {
        fprintf(stderr, "[GpuBackend] WARNING: CUDA not available (nvcuda.dll not found, error %lu)\n", GetLastError());
        return false;
    }

    typedef int (*PFN_cuInit)(unsigned int);
    auto pfnCuInit = (PFN_cuInit)GetProcAddress(hCuda, "cuInit");
    if (!pfnCuInit) {
        fprintf(stderr, "[GpuBackend] WARNING: cuInit not found in nvcuda.dll\n");
        FreeLibrary(hCuda);
        return false;
    }

    int cuResult = pfnCuInit(0);
    if (cuResult != 0) {
        fprintf(stderr, "[GpuBackend] WARNING: cuInit failed with error %d\n", cuResult);
        FreeLibrary(hCuda);
        return false;
    }

    fprintf(stderr, "[GpuBackend] OK: CUDA initialized successfully\n");
    return true;
#else
    void* lib = dlopen("libcuda.so", RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "[GpuBackend] WARNING: CUDA not available (libcuda.so not found)\n");
        return false;
    }
    fprintf(stderr, "[GpuBackend] OK: CUDA library loaded\n");
    return true;
#endif
=======
    
    // Initialize CUDA runtime through MASM
    int64_t result = CUDA_Initialize();
    if (result != 0) {
        return false;
    }

    // Get CUDA device count
    int32_t deviceCount = CUDA_GetDeviceCount();
    if (deviceCount == 0) {
        return false;
    }

    // Set device 0 as active
    result = CUDA_SetDevice(0);
    if (result != 0) {
        return false;
    }

    return true;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

bool GpuBackend::initializeCpu()
{
<<<<<<< HEAD
    fprintf(stderr, "[GpuBackend] Initializing CPU backend...\n");
    s_currentBackend = CPU;
    s_initialized = true;
    fprintf(stderr, "[GpuBackend] OK: CPU backend ready (models will run on CPU - slower performance)\n");
    return true;
}
=======
    
    // Still call MASM backend with CPU mode for consistency
    int64_t result = InitializeGPUBackend(0); // 0 = CPU mode
    
    s_currentBackend = CPU;
    s_initialized = true;
    return true;
}

namespace {
    using Clock = std::chrono::steady_clock;
    namespace fs = std::filesystem;

    std::unique_ptr<VulkanCompute> g_vulkanCompute;
    std::once_flag g_vulkanInitFlag;
    std::atomic<bool> g_vulkanReady{false};
    std::atomic<uint64_t> g_gpuMatmulCount{0};
    std::atomic<uint64_t> g_cpuMatmulCount{0};
    std::atomic<uint64_t> g_lastMatmulLatencyUs{0};

    fs::path resolveRepoRoot()
    {
        fs::path here(__FILE__);
        return here.parent_path().parent_path();
    }

    std::optional<std::string> resolveMatmulSpvPath()
    {
        std::vector<fs::path> candidates;
        const char* envPath = std::getenv("RAWRXD_MATMUL_SPV");
        if (envPath && *envPath) {
            fs::path envCandidate(envPath);
            if (fs::is_directory(envCandidate)) {
                candidates.emplace_back(envCandidate / "mul_mm.spv");
                candidates.emplace_back(envCandidate / "matmul_f16.spv");
                candidates.emplace_back(envCandidate / "matmul.spv");
            } else {
                candidates.emplace_back(envCandidate);
            }
        }

        const fs::path root = resolveRepoRoot();
        candidates.emplace_back(root / "3rdparty/ggml/src/ggml-vulkan/vulkan-shaders.spv/mul_mm.spv");
        candidates.emplace_back(root / "3rdparty/ggml/src/ggml-vulkan/vulkan-shaders.spv/matmul_f16.spv");
        candidates.emplace_back(root / "3rdparty/ggml/src/ggml-vulkan/vulkan-shaders.spv/matmul.spv");

        for (const auto& candidate : candidates) {
            std::error_code ec;
            if (fs::exists(candidate, ec) && fs::is_regular_file(candidate, ec)) {
                return candidate.string();
            }
        }

        return std::nullopt;
    }
}

extern "C" int64_t HybridGPU_Init()
{
    std::call_once(g_vulkanInitFlag, [] {
        g_vulkanCompute = std::make_unique<VulkanCompute>();
        if (!g_vulkanCompute->Initialize()) {
            g_vulkanCompute.reset();
            return;
        }
        g_vulkanReady.store(true, std::memory_order_release);
    });

    return g_vulkanReady.load(std::memory_order_acquire) ? 1 : 0;
}

extern "C" int64_t HybridCPU_MatMul(const float* A, const float* B, float* C,
                                     int64_t M, int64_t N, int64_t K)
{
    if (!A || !B || !C || M <= 0 || N <= 0 || K <= 0) {
        return -1;
    }

    ggml_masm_gemm_f32(A, B, C, M, N, K, 1.0f, 0.0f);
    g_cpuMatmulCount.fetch_add(1, std::memory_order_relaxed);
    return 0;
}

extern "C" int64_t HybridGPU_MatMul(const float* A, const float* B, float* C,
                                     int64_t M, int64_t N, int64_t K)
{
    if (!A || !B || !C || M <= 0 || N <= 0 || K <= 0) {
        return -1;
    }

    const auto start = Clock::now();
    bool usedGpu = false;
    const bool dimsFit = M > 0 && N > 0 && K > 0 &&
        M <= static_cast<int64_t>(std::numeric_limits<uint32_t>::max()) &&
        N <= static_cast<int64_t>(std::numeric_limits<uint32_t>::max()) &&
        K <= static_cast<int64_t>(std::numeric_limits<uint32_t>::max());

    if (HybridGPU_Init() != 0 && g_vulkanCompute && dimsFit) {
        const auto spvPath = resolveMatmulSpvPath();
        if (spvPath) {
            const bool dispatched = g_vulkanCompute->DispatchMatMulHost(
                A, B, C,
                static_cast<uint32_t>(M),
                static_cast<uint32_t>(K),
                static_cast<uint32_t>(N),
                *spvPath);

            if (dispatched) {
                usedGpu = true;
                g_gpuMatmulCount.fetch_add(1, std::memory_order_relaxed);
                        << "shader:" << std::string::fromStdString(*spvPath);
            } else {
            }
        } else {
        }
    } else if (!dimsFit) {
    }

    if (!usedGpu) {
        ggml_masm_gemm_f32(A, B, C, M, N, K, 1.0f, 0.0f);
        g_cpuMatmulCount.fetch_add(1, std::memory_order_relaxed);
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
    g_lastMatmulLatencyUs.store(static_cast<uint64_t>(elapsed.count()), std::memory_order_relaxed);
    return 0;
}

extern "C" int64_t HybridGPU_Synchronize()
{
    if (g_vulkanReady.load(std::memory_order_acquire) && g_vulkanCompute) {
        return g_vulkanCompute->FlushAsyncCommands() ? 0 : -1;
    }
    return 0;
}

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
