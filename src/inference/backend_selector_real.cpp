// ============================================================================
// Backend Selector - Real Implementation
// ============================================================================
// Probes hardware and selects optimal backend
// ============================================================================

#include "backend_selector_real.hpp"
#include <iostream>

// Windows: Use DXGI for GPU detection (always available)
// Linux/Mac: Would use Vulkan
#ifdef _WIN32
    #include <windows.h>
    #include <dxgi.h>
    #pragma comment(lib, "dxgi.lib")
#endif

namespace RawrXD {
namespace Inference {

// ============================================================================
// Probe System Capabilities
// ============================================================================
BackendCapabilities ProbeSystemCapabilities() {
    BackendCapabilities caps = {};
    
#ifdef _WIN32
    // Windows: Check for GPU via DXGI
    HMODULE dxgi = LoadLibraryA("dxgi.dll");
    if (dxgi) {
        typedef HRESULT (WINAPI *CreateDXGIFactory1_t)(REFIID, void**);
        CreateDXGIFactory1_t CreateDXGIFactory1 = 
            (CreateDXGIFactory1_t)GetProcAddress(dxgi, "CreateDXGIFactory1");
        
        if (CreateDXGIFactory1) {
            // We have DXGI - GPU likely present
            caps.vulkan_available = true;  // Assume Vulkan available if DXGI is
            
            // Try to get adapter info
            IDXGIFactory1* factory = nullptr;
            if (SUCCEEDED(CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void**)&factory))) {
                IDXGIAdapter1* adapter = nullptr;
                for (UINT i = 0; factory->EnumAdapters1(i, &adapter) != DXGI_ERROR_NOT_FOUND; ++i) {
                    DXGI_ADAPTER_DESC1 desc;
                    if (SUCCEEDED(adapter->GetDesc1(&desc))) {
                        // Skip software adapters
                        if (!(desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE)) {
                            size_t vram_mb = desc.DedicatedVideoMemory / (1024 * 1024);
                            
                            // Convert wide string to narrow
                            char name[128] = {};
                            WideCharToMultiByte(CP_UTF8, 0, desc.Description, -1, name, 128, nullptr, nullptr);
                            
                            // Prefer discrete GPU with most VRAM
                            if (vram_mb > caps.vram_mb) {
                                caps.vram_mb = vram_mb;
                                caps.gpu_name = name;
                                caps.supports_fp16 = true;  // Modern GPUs support FP16
                                caps.supports_int8 = true;
                                caps.has_matrix_cores = (desc.VendorId == 0x1002); // AMD
                            }
                        }
                        adapter->Release();
                    }
                }
                factory->Release();
            }
        }
        FreeLibrary(dxgi);
    }
#else
    // Linux/Mac: Try Vulkan
    // TODO: Implement Vulkan probing on non-Windows platforms
    caps.vulkan_available = false;
#endif
    
    // Check Medusa availability (requires sufficient VRAM)
    caps.medusa_available = caps.vulkan_available && caps.vram_mb >= 12000;
    
    std::cout << "[BackendProbe] Vulkan: " << (caps.vulkan_available ? "YES" : "NO")
              << ", VRAM: " << caps.vram_mb << " MB"
              << ", GPU: " << caps.gpu_name
              << ", Medusa: " << (caps.medusa_available ? "YES" : "NO") << "\n";
    
    return caps;
}

// ============================================================================
// Select Optimal Backend
// ============================================================================
BackendType SelectOptimalBackend(const BackendConfig& config, 
                                  const BackendCapabilities& caps) {
    // Force CPU if requested
    if (config.force_cpu) {
        std::cout << "[BackendSelector] CPU forced by config\n";
        return BackendType::CPU;
    }
    
    // Check if specific type requested
    if (config.type != BackendType::AUTO) {
        // Validate requested backend is available
        if (config.type == BackendType::MEDUSA_GPU && !caps.medusa_available) {
            std::cerr << "[BackendSelector] Medusa GPU requested but not available, falling back\n";
        } else if (config.type == BackendType::VULKAN && !caps.vulkan_available) {
            std::cerr << "[BackendSelector] Vulkan requested but not available, falling back\n";
        } else {
            return config.type;
        }
    }
    
    // Auto-select best backend
    if (caps.medusa_available && config.enable_medusa) {
        std::cout << "[BackendSelector] Selected: MEDUSA_GPU (" << caps.vram_mb << "MB VRAM)\n";
        return BackendType::MEDUSA_GPU;
    }
    
    if (caps.vulkan_available) {
        std::cout << "[BackendSelector] Selected: VULKAN\n";
        return BackendType::VULKAN;
    }
    
    std::cout << "[BackendSelector] Selected: CPU\n";
    return BackendType::CPU;
}

// ============================================================================
// Backend Implementations
// ============================================================================
class CPUBackend : public IInferenceBackend {
public:
    bool Initialize(const BackendConfig& config) override {
        // CPU backend always available
        initialized_ = true;
        return true;
    }
    
    void Shutdown() override {
        initialized_ = false;
    }
    
    bool IsInitialized() const override { return initialized_; }
    std::string GetName() const override { return "CPU"; }
    BackendType GetType() const override { return BackendType::CPU; }
    
    float GetTokensPerSecond() const override { return 0.0f; } // Not tracked here
    float GetAverageLatencyMs() const override { return 0.0f; }
    size_t GetVRAMUsedMB() const override { return 0; }
    
private:
    bool initialized_ = false;
};

class VulkanBackend : public IInferenceBackend {
public:
    bool Initialize(const BackendConfig& config) override {
        // Would initialize Vulkan GGML backend here
        std::cout << "[VulkanBackend] Initializing...\n";
        initialized_ = true;
        return true;
    }
    
    void Shutdown() override {
        initialized_ = false;
    }
    
    bool IsInitialized() const override { return initialized_; }
    std::string GetName() const override { return "Vulkan"; }
    BackendType GetType() const override { return BackendType::VULKAN; }
    
    float GetTokensPerSecond() const override { return 0.0f; }
    float GetAverageLatencyMs() const override { return 0.0f; }
    size_t GetVRAMUsedMB() const override { return 0; }
    
private:
    bool initialized_ = false;
};

class MedusaGPUBackend : public IInferenceBackend {
public:
    bool Initialize(const BackendConfig& config) override {
        std::cout << "[MedusaGPUBackend] Initializing with " << config.medusa_heads << " heads...\n";
        
        // TODO: Create real Medusa engine when available
        // For now, just mark as initialized for testing
        initialized_ = true;
        std::cout << "[MedusaGPUBackend] Ready for 32K context (stub)\n";
        return true;
    }
    
    void Shutdown() override {
        initialized_ = false;
    }
    
    bool IsInitialized() const override { return initialized_; }
    std::string GetName() const override { return "MedusaGPU"; }
    BackendType GetType() const override { return BackendType::MEDUSA_GPU; }
    
    float GetTokensPerSecond() const override { return 0.0f; } // TODO: Real metrics
    float GetAverageLatencyMs() const override { return 0.0f; }
    size_t GetVRAMUsedMB() const override { return 0; }
    
private:
    bool initialized_ = false;
};

// ============================================================================
// Create Backend
// ============================================================================
std::unique_ptr<IInferenceBackend> CreateBackend(BackendType type) {
    switch (type) {
        case BackendType::CPU:
            return std::make_unique<CPUBackend>();
        case BackendType::VULKAN:
            return std::make_unique<VulkanBackend>();
        case BackendType::MEDUSA_GPU:
            return std::make_unique<MedusaGPUBackend>();
        default:
            return nullptr;
    }
}

// ============================================================================
// Initialize GGML Backend (Bridge to existing code)
// ============================================================================
ggml_rxd_backend* InitializeGGMLBackend(BackendType type, 
                                       ggml_rxd_context* ctx,
                                       const BackendConfig& config) {
    // This bridges to the existing GGML backend system
    // Returns the appropriate backend pointer for GGML to use
    
    switch (type) {
        case BackendType::CPU:
            // Call existing CPU init
            // return ggml_rxd_backend_cpu_init();
            return nullptr; // Placeholder
            
        case BackendType::VULKAN:
            // Would call Vulkan backend init
            std::cout << "[GGMLBridge] Initializing Vulkan backend\n";
            return nullptr; // Placeholder - needs real Vulkan backend
            
        case BackendType::MEDUSA_GPU:
            // Medusa doesn't use standard GGML backend
            // It has its own execution path
            std::cout << "[GGMLBridge] Medusa uses custom execution path\n";
            return nullptr;
            
        default:
            return nullptr;
    }
}

} // namespace Inference
} // namespace RawrXD
