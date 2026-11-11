// ============================================================================
// Backend Selector - Real Implementation
// ============================================================================
// Selects between CPU, Vulkan, and Medusa GPU backends based on capability
// ============================================================================

#pragma once
#include <string>
#include <memory>
#include <cstdint>

namespace RawrXD {
namespace Inference {

// Forward declarations
struct ggml_rxd_backend;
struct ggml_rxd_context;

// Backend types
enum class BackendType {
    CPU,           // Standard CPU backend
    VULKAN,        // Vulkan GPU backend (GGML)
    MEDUSA_GPU,    // Medusa speculative decoding on GPU
    AUTO           // Select best available
};

// Backend capabilities
struct BackendCapabilities {
    bool vulkan_available = false;
    bool medusa_available = false;
    size_t vram_mb = 0;
    size_t vram_free_mb = 0;
    std::string gpu_name;
    bool supports_fp16 = false;
    bool supports_int8 = false;
    bool has_matrix_cores = false;  // RDNA3 WMMA
};

// Backend configuration
struct BackendConfig {
    BackendType type = BackendType::AUTO;
    bool force_cpu = false;
    bool enable_medusa = true;
    uint32_t medusa_heads = 8;
    uint32_t max_context = 32768;
    size_t vram_budget_mb = 14000;  // Leave 2GB headroom
    std::string model_path;
    int ngl = 999;  // Number of GPU layers
};

// Backend interface
class IInferenceBackend {
public:
    virtual ~IInferenceBackend() = default;
    virtual bool Initialize(const BackendConfig& config) = 0;
    virtual void Shutdown() = 0;
    virtual bool IsInitialized() const = 0;
    virtual std::string GetName() const = 0;
    virtual BackendType GetType() const = 0;
    
    // Performance metrics
    virtual float GetTokensPerSecond() const = 0;
    virtual float GetAverageLatencyMs() const = 0;
    virtual size_t GetVRAMUsedMB() const = 0;
};

// Probe system for available backends
BackendCapabilities ProbeSystemCapabilities();

// Select best backend for configuration
BackendType SelectOptimalBackend(const BackendConfig& config, 
                                const BackendCapabilities& caps);

// Create backend instance
std::unique_ptr<IInferenceBackend> CreateBackend(BackendType type);

// Initialize GGML backend (bridges to existing GGML code)
ggml_rxd_backend* InitializeGGMLBackend(BackendType type, 
                                       ggml_rxd_context* ctx,
                                       const BackendConfig& config);

} // namespace Inference
} // namespace RawrXD
