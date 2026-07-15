#pragma once

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <filesystem>
#include <optional>

namespace RawrXD {

/**
 * @brief LoRA hyperparameters configuration
 * 
 * Phase 18C: Low-Rank Adaptation for personalized embeddings
 */
struct LoRAConfig {
    int rank = 8;                    // r: Low-rank dimension (typically 4-16)
    float alpha = 16.0f;             // Scaling factor (usually 2× rank)
    float dropout = 0.05f;           // Regularization during training
    float learning_rate = 0.0001f;   // SGD step size for adapter training
    std::string base_model_id;       // Reference to frozen base model
    int target_dim = 384;            // Embedding dimension (MiniLM-L6)
    
    // Serialization helpers
    std::string to_json() const;
    static LoRAConfig from_json(const std::string& json);
};

/**
 * @brief Adapter weight matrices and metadata
 * 
 * Stores the trainable A and B matrices for LoRA adaptation.
 * Matrix A: (target_dim × rank) - down-projection
 * Matrix B: (rank × target_dim) - up-projection
 */
struct AdapterState {
    std::string id;                           // Unique adapter identifier
    std::string name;                         // Human-readable name
    LoRAConfig config;                        // Hyperparameters
    std::vector<float> matrix_A;             // Decomposed matrix A (d × r)
    std::vector<float> matrix_B;             // Decomposed matrix B (r × d)
    uint32_t version = 1;                     // Format version for migrations
    int64_t training_samples = 0;             // Number of samples trained on
    double avg_loss = 0.0;                    // Last known training loss
    std::string created_at;                   // ISO timestamp
    std::string last_trained_at;              // ISO timestamp
    
    // Memory footprint: ~2 × d × r × 4 bytes
    // For d=384, r=8: ~24KB per adapter
    size_t memory_bytes() const {
        return (matrix_A.size() + matrix_B.size()) * sizeof(float);
    }
    
    // Validate dimensions match config
    bool validate_dimensions() const;
};

/**
 * @brief Thread-safe manager for LoRA adapter lifecycle
 * 
 * Phase 18C.1: Registry for loading, activating, and persisting
 * user-specific LoRA adapters. Supports hot-swapping adapters
 * without blocking inference.
 */
class LoRAAdapterManager {
public:
    /**
     * @brief Get singleton instance
     */
    static LoRAAdapterManager& instance();
    
    /**
     * @brief Initialize manager and load default adapter
     * @return true if initialization successful
     */
    bool initialize();
    
    /**
     * @brief Load adapter from disk
     * @param id Adapter identifier (filename without .lora extension)
     * @return true if loaded successfully
     * 
     * Loads from %LOCALAPPDATA%/RawrXD/adapters/{id}.lora
     */
    bool load_adapter(const std::string& id);
    
    /**
     * @brief Create new adapter with random initialization
     * @param id Unique identifier
     * @param config LoRA hyperparameters
     * @return true if created successfully
     * 
     * Initializes A with Kaiming initialization, B with zeros
     * (standard LoRA practice for stable training)
     */
    bool create_adapter(const std::string& id, const LoRAConfig& config);
    
    /**
     * @brief Activate adapter for inference
     * @param id Adapter identifier
     * 
     * Thread-safe: swaps active adapter pointer atomically
     */
    void activate_adapter(const std::string& id);
    
    /**
     * @brief Get currently active adapter
     * @return Shared pointer to active adapter (may be null)
     * 
     * Returns immutable reference safe for concurrent inference.
     * Old references remain valid until last user releases them.
     */
    std::shared_ptr<const AdapterState> get_active_adapter() const;
    
    /**
     * @brief Get adapter by ID (not necessarily active)
     * @param id Adapter identifier
     * @return Shared pointer or nullptr if not found
     */
    std::shared_ptr<const AdapterState> get_adapter(const std::string& id) const;
    
    /**
     * @brief Check if adapter exists in registry
     */
    bool has_adapter(const std::string& id) const;
    
    /**
     * @brief List all loaded adapter IDs
     */
    std::vector<std::string> list_adapters() const;
    
    /**
     * @brief Save adapter to disk
     * @param id Adapter identifier
     * @return true if saved successfully
     */
    bool save_adapter(const std::string& id) const;
    
    /**
     * @brief Save all adapters
     */
    void save_all() const;
    
    /**
     * @brief Unload adapter from memory
     * @param id Adapter identifier
     * 
     * Cannot unload active adapter (deactivate first)
     */
    bool unload_adapter(const std::string& id);
    
    /**
     * @brief Delete adapter from disk and memory
     * @param id Adapter identifier
     */
    bool delete_adapter(const std::string& id);
    
    /**
     * @brief Get active adapter ID
     * @return Current active adapter ID or empty string
     */
    std::string get_active_adapter_id() const;
    
    /**
     * @brief Shutdown manager and save all adapters
     */
    void shutdown();
    
    // Disable copy/move
    LoRAAdapterManager(const LoRAAdapterManager&) = delete;
    LoRAAdapterManager& operator=(const LoRAAdapterManager&) = delete;
    LoRAAdapterManager(LoRAAdapterManager&&) = delete;
    LoRAAdapterManager& operator=(LoRAAdapterManager&&) = delete;

private:
    LoRAAdapterManager() = default;
    ~LoRAAdapterManager();
    
    std::filesystem::path get_adapter_path(const std::string& id) const;
    std::filesystem::path get_adapters_dir() const;
    void ensure_adapters_dir() const;
    
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, std::shared_ptr<AdapterState>> m_registry;
    std::shared_ptr<AdapterState> m_active_adapter;
    std::string m_active_id;
    bool m_initialized = false;
};

} // namespace RawrXD
