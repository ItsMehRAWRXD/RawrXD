#pragma once
#include <string>
#include <unordered_map>
#include <memory>
#include <filesystem>
#include <vector>
#include <mutex>
#include <optional>

namespace RawrXD {

// LoRA weight matrices: W = W_0 + BA
// A: (rank x in_features) - down-projection
// B: (out_features x rank) - up-projection
struct AdapterWeights {
    std::vector<float> A;  // Shape: [rank, in_features]
    std::vector<float> B;  // Shape: [out_features, rank]
    uint32_t rank = 0;
    uint32_t in_features = 0;
    uint32_t out_features = 0;
    
    // Validate dimensions are consistent
    bool is_valid() const {
        if (rank == 0 || in_features == 0 || out_features == 0) return false;
        if (A.size() != rank * in_features) return false;
        if (B.size() != out_features * rank) return false;
        return true;
    }
    
    // Compute output = B * A * input (LoRA path)
    // input: [in_features], output: [out_features]
    void apply_lora(const float* input, float* output) const;
};

// Metadata for adapter versioning and compatibility
struct AdapterManifest {
    std::string name;
    std::string version;           // Semantic versioning
    std::string base_model;        // e.g., "codebert-base"
    std::string base_model_version;
    std::string description;
    uint32_t rank = 8;             // LoRA rank (typically 4-64)
    std::vector<std::string> tags; // e.g., ["python", "data-science"]
    uint64_t trained_samples = 0;  // Number of training samples
    float training_loss = 0.0f;    // Final training loss
    uint64_t created_timestamp = 0;
    uint64_t modified_timestamp = 0;
    
    // Serialize to/from JSON
    std::string to_json() const;
    static std::optional<AdapterManifest> from_json(const std::string& json);
};

// Forward declaration
class LoRAEmbeddingHook;

// Singleton registry for managing LoRA adapters
class AdapterRegistry {
public:
    static AdapterRegistry& instance();
    
    // Load an adapter from .cache/adapters/{name}.lora
    // Returns true on success, false on failure (logs error)
    bool load_adapter(const std::string& name);
    
    // Unload an adapter from memory
    void unload_adapter(const std::string& name);
    
    // Activate adapter for current session
    // Automatically unloads previous active adapter if different
    bool activate_adapter(const std::string& name);
    
    // Deactivate current adapter (revert to base model)
    void deactivate_adapter();
    
    // Return weights for the current forward pass
    // Returns nullptr if no active adapter
    const AdapterWeights* get_active_weights() const;
    
    // Get active adapter manifest
    const AdapterManifest* get_active_manifest() const;
    
    // Check if adapter is loaded
    bool is_loaded(const std::string& name) const;
    
    // List all loaded adapters
    std::vector<std::string> list_loaded() const;
    
    // Get adapter cache directory
    std::filesystem::path get_adapter_cache_dir() const;
    
    // Set custom cache directory
    void set_adapter_cache_dir(const std::filesystem::path& path);
    
    // Get the embedding hook for integration
    LoRAEmbeddingHook* get_embedding_hook();

private:
    AdapterRegistry();
    ~AdapterRegistry() = default;
    
    AdapterRegistry(const AdapterRegistry&) = delete;
    AdapterRegistry& operator=(const AdapterRegistry&) = delete;
    
    // Parse .lora file format (custom binary format)
    std::optional<AdapterWeights> parse_lora_file(const std::filesystem::path& path);
    std::optional<AdapterManifest> parse_manifest(const std::filesystem::path& path);
    
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, AdapterWeights> m_registry;
    std::unordered_map<std::string, AdapterManifest> m_manifests;
    std::string m_active_adapter_id;
    std::filesystem::path m_cache_dir;
    std::unique_ptr<LoRAEmbeddingHook> m_embedding_hook;
};

// Hook for integrating LoRA into embedding pipeline
// Performs: output = W_0 * x + B * A * x
class LoRAEmbeddingHook {
public:
    LoRAEmbeddingHook();
    ~LoRAEmbeddingHook();
    
    // Set the active weights (called by AdapterRegistry)
    void set_weights(const AdapterWeights* weights);
    
    // Apply LoRA to embedding output
    // base_output: W_0 * x (from base model)
    // input: x (original input embeddings)
    // result: base_output + B * A * input
    void apply(
        const float* base_output,
        const float* input,
        float* result,
        size_t batch_size,
        size_t seq_length,
        size_t hidden_dim
    );
    
    // Check if LoRA is currently active
    bool is_active() const { return m_weights != nullptr; }
    
    // Get current rank (0 if inactive)
    uint32_t get_rank() const;

private:
    const AdapterWeights* m_weights = nullptr;
    
    // Temporary buffer for A * x computation
    std::vector<float> m_temp_buffer;
    mutable std::mutex m_mutex;
};

} // namespace RawrXD
