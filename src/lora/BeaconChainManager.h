#pragma once
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <filesystem>
#include <mutex>
#include <atomic>

// Forward declarations for C interface
extern "C" {
typedef struct LoRABeaconState LoRABeaconState;
typedef struct LoRABeaconChain LoRABeaconChain;
}

namespace RawrXD {

// Forward declarations
class BeaconAdapterManager;
struct AdapterData;

// ============================================================================
// Chain Execution Mode
// ============================================================================
enum class ChainMode {
    SEQUENTIAL = 0,      // Apply each adapter in order: W = W_0 + sum(B_i*A_i)
    WEIGHTED_BLEND = 1,  // Blend matrices first: W = W_0 + B_blended*A_blended
    CONDITIONAL = 2,     // Context-aware selection
    PARALLEL = 3         // Parallel application (requires thread pool)
};

const char* chain_mode_to_string(ChainMode mode);
ChainMode chain_mode_from_string(const std::string& str);

// ============================================================================
// Chain Entry
// ============================================================================
struct ChainEntry {
    std::string adapter_name;
    float weight = 1.0f;           // Composition weight
    bool enabled = true;           // Can be toggled at runtime
    
    // Runtime data (populated when chain is activated)
    const AdapterData* adapter_data = nullptr;
    LoRABeaconState* beacon_state = nullptr;
    
    // Validation
    bool is_valid() const {
        return !adapter_name.empty() && enabled && weight >= 0.0f;
    }
};

// ============================================================================
// Chain Configuration
// ============================================================================
struct ChainConfig {
    std::string name;
    ChainMode mode = ChainMode::SEQUENTIAL;
    std::vector<ChainEntry> entries;
    
    // Conditional mode settings
    std::string condition_expression;  // e.g., "file_extension == '.py'"
    
    // Performance settings
    bool precompute_blend = false;     // For WEIGHTED_BLEND mode
    bool cache_intermediates = false;  // Cache partial results
    
    // Metadata
    std::string description;
    std::vector<std::string> tags;
    uint64_t created_timestamp = 0;
    uint64_t modified_timestamp = 0;
    
    // Serialization
    std::string to_json() const;
    static std::optional<ChainConfig> from_json(const std::string& json);
    static std::optional<ChainConfig> from_file(const std::filesystem::path& path);
    bool save_to_file(const std::filesystem::path& path) const;
};

// ============================================================================
// Chain Statistics
// ============================================================================
struct ChainStats {
    std::string chain_name;
    size_t entry_count = 0;
    size_t active_entry_count = 0;
    ChainMode mode;
    
    // Runtime metrics
    uint64_t inference_count = 0;
    uint64_t total_latency_us = 0;
    float average_latency_us = 0.0f;
    
    // Cache metrics
    size_t cache_hits = 0;
    size_t cache_misses = 0;
    float cache_hit_rate = 0.0f;
};

// ============================================================================
// Beacon Chain Manager
// ============================================================================
class BeaconChainManager {
public:
    static BeaconChainManager& instance();
    
    // Initialization
    void initialize(const std::filesystem::path& chains_directory);
    
    // Chain lifecycle
    bool create_chain(const ChainConfig& config);
    bool update_chain(const std::string& name, const ChainConfig& config);
    bool delete_chain(const std::string& name);
    bool load_chain(const std::string& name);
    void unload_chain(const std::string& name);
    
    // Chain activation (for inference)
    bool activate_chain(const std::string& name);
    void deactivate_chain();
    
    // Chain queries
    bool is_chain_active(const std::string& name) const;
    bool is_chain_loaded(const std::string& name) const;
    std::string get_active_chain_name() const;
    std::vector<std::string> list_chains() const;
    std::optional<ChainConfig> get_chain_config(const std::string& name) const;
    
    // Entry management (runtime modifications)
    bool add_entry(const std::string& chain_name, const ChainEntry& entry);
    bool remove_entry(const std::string& chain_name, const std::string& adapter_name);
    bool update_entry_weight(const std::string& chain_name, 
                            const std::string& adapter_name, 
                            float new_weight);
    bool toggle_entry(const std::string& chain_name, 
                     const std::string& adapter_name, 
                     bool enabled);
    
    // Reorder entries
    bool move_entry_up(const std::string& chain_name, const std::string& adapter_name);
    bool move_entry_down(const std::string& chain_name, const std::string& adapter_name);
    
    // Statistics
    ChainStats get_stats(const std::string& chain_name) const;
    std::vector<ChainStats> get_all_stats() const;
    void reset_stats(const std::string& chain_name);
    
    // Factory presets
    static ChainConfig create_python_chain();
    static ChainConfig create_cpp_chain();
    static ChainConfig create_web_chain();
    static ChainConfig create_ml_chain();
    static ChainConfig create_security_chain();
    
    // Validation
    bool validate_chain(const ChainConfig& config) const;
    std::vector<std::string> get_validation_errors(const ChainConfig& config) const;
    
    // Import/Export
    bool export_chain(const std::string& chain_name, const std::filesystem::path& export_path);
    bool import_chain(const std::filesystem::path& import_path, 
                     const std::string& new_name = "");
    
    // C interface for MASM integration
    LoRABeaconChain* get_beacon_chain_c() const;
    
    // Event callbacks
    using ChainEventCallback = std::function<void(const std::string& chain_name, 
                                                     const std::string& event_type)>;
    void set_event_callback(ChainEventCallback callback);

private:
    BeaconChainManager() = default;
    ~BeaconChainManager();
    
    BeaconChainManager(const BeaconChainManager&) = delete;
    BeaconChainManager& operator=(const BeaconChainManager&) = delete;
    
    // Internal helpers
    bool build_beacon_chain(const ChainConfig& config);
    void destroy_beacon_chain();
    bool update_beacon_chain_state();
    
    std::filesystem::path get_chain_path(const std::string& name) const;
    void notify_event(const std::string& chain_name, const std::string& event_type);
    
    // Data
    std::unordered_map<std::string, ChainConfig> m_chains;
    std::unordered_map<std::string, ChainStats> m_stats;
    std::string m_active_chain;
    std::string m_loaded_chain;
    
    std::filesystem::path m_chains_dir;
    mutable std::mutex m_mutex;
    
    // C-compatible beacon chain (for MASM)
    LoRABeaconChain* m_beacon_chain = nullptr;
    std::vector<LoRABeaconState*> m_beacon_states;
    
    // Callback
    ChainEventCallback m_event_callback;
    
    // Precomputed blended weights (for WEIGHTED_BLEND mode)
    std::vector<float> m_blended_A;
    std::vector<float> m_blended_B;
};

// ============================================================================
// Chain Context (for conditional evaluation)
// ============================================================================
struct ChainContext {
    std::string file_path;
    std::string file_extension;
    std::string language;
    std::vector<std::string> imports;
    std::vector<std::string> symbols;
    bool is_test_file = false;
    bool has_security_keywords = false;
    uint64_t timestamp = 0;
    
    // Evaluation
    bool evaluate_condition(const std::string& expression) const;
};

// ============================================================================
// Utility Functions
// ============================================================================

// Quick chain operations
bool quick_activate_chain(const std::string& name);
void quick_deactivate_chain();
bool quick_create_sequential_chain(const std::string& name, 
                                   const std::vector<std::string>& adapter_names);

// Chain templates
ChainConfig make_composite_chain(const std::string& name,
                                 const std::vector<std::pair<std::string, float>>& adapters);

// Validation
bool validate_chain_name(const std::string& name);
std::string sanitize_chain_name(const std::string& name);

} // namespace RawrXD
