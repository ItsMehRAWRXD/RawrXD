// ============================================================================
// dynamic_model_loader.h
// Hot-swappable model loader with memory-aware backend selection
// Supports: CPU fallback, GPU spillover, Medusa speculative decoding
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <functional>
#include <atomic>
#include <cstdint>

namespace RawrXD {

// Forward declaration
class InferenceEngine;

// Model capability descriptor
struct ModelCapability {
    std::string name;
    std::string path;
    size_t size_bytes = 0;
    int context_length = 4096;
    int quant_bits = 8;
    bool supports_gpu = true;
    bool supports_medusa = false;
    bool supports_speculative = false;
    float estimated_vram_mb = 0.f;
    float estimated_ram_mb = 0.f;
};

// Backend preference for loading
enum class LoadBackend {
    Auto,       // Choose based on memory pressure
    CPU,        // Force CPU
    GPU,        // Force GPU (if available)
    Spillover   // GPU + CPU spill for large models
};

// Load result
struct LoadResult {
    bool success = false;
    std::string error;
    std::string backend_used;
    float load_time_ms = 0.f;
    size_t vram_used_mb = 0;
    size_t ram_used_mb = 0;
};

class DynamicModelLoader {
public:
    static DynamicModelLoader& instance();

    // --- Configuration ---
    void setTinyModelPath(const std::string& path) { m_tiny_model = path; }
    void setDefaultModelPath(const std::string& path) { m_default_model = path; }
    void setMaxVRAMMB(size_t mb) { m_max_vram_mb = mb; }
    void setMaxRAMMB(size_t mb) { m_max_ram_mb = mb; }

    // --- Model Discovery ---
    std::vector<ModelCapability> scanModelDirectory(const std::string& dir);
    ModelCapability probeModel(const std::string& path);

    // --- Loading ---
    LoadResult loadModel(const std::string& path, LoadBackend backend = LoadBackend::Auto);
    LoadResult loadTinyModel();  // Auto-loads Phi-3-mini or similar
    bool unloadModel();
    bool isModelLoaded() const;
    std::string currentModelPath() const;

    // --- Hot Swap ---
    LoadResult swapToModel(const std::string& path, LoadBackend backend = LoadBackend::Auto);

    // --- Memory Query ---
    size_t getAvailableVRAMMB() const;
    size_t getAvailableRAMMB() const;
    bool canFitModel(const ModelCapability& model) const;

    // --- Callbacks ---
    using LoadCallback = std::function<void(const LoadResult&)>;
    void setOnLoadComplete(LoadCallback cb) { m_on_load = std::move(cb); }
    void setOnUnloadComplete(std::function<void()> cb) { m_on_unload = std::move(cb); }

    // --- Inference Engine Bridge ---
    void setInferenceEngine(InferenceEngine* engine) { m_engine = engine; }
    InferenceEngine* getInferenceEngine() const { return m_engine; }

    // --- Medusa / Speculative Decoding ---
    bool enableMedusa(const std::string& draft_model_path);
    bool enableSpeculativeDecoding(int draft_tokens = 4);
    void disableSpeculativeDecoding();
    bool isSpeculativeEnabled() const;

private:
    DynamicModelLoader() = default;
    ~DynamicModelLoader() = default;

    std::string m_current_model;
    std::string m_tiny_model;
    std::string m_default_model;
    std::atomic<bool> m_loaded{false};
    std::atomic<bool> m_speculative_enabled{false};
    std::mutex m_mutex;

    InferenceEngine* m_engine = nullptr;

    size_t m_max_vram_mb = 16000;  // 16GB default
    size_t m_max_ram_mb = 64000;   // 64GB default

    LoadCallback m_on_load;
    std::function<void()> m_on_unload;

    LoadResult tryLoadGPU(const std::string& path);
    LoadResult tryLoadCPU(const std::string& path);
    LoadResult tryLoadSpillover(const std::string& path);
};

} // namespace RawrXD
