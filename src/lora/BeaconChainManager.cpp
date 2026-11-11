#include "BeaconChainManager.h"
#include "AdapterSerializer.h"
#include "LoRABeaconInterface.h"
#include <json/json.h>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>

namespace RawrXD {

// ============================================================================
// Chain Mode Utilities
// ============================================================================

const char* chain_mode_to_string(ChainMode mode) {
    switch (mode) {
        case ChainMode::SEQUENTIAL: return "sequential";
        case ChainMode::WEIGHTED_BLEND: return "weighted_blend";
        case ChainMode::CONDITIONAL: return "conditional";
        case ChainMode::PARALLEL: return "parallel";
        default: return "unknown";
    }
}

ChainMode chain_mode_from_string(const std::string& str) {
    if (str == "sequential") return ChainMode::SEQUENTIAL;
    if (str == "weighted_blend") return ChainMode::WEIGHTED_BLEND;
    if (str == "conditional") return ChainMode::CONDITIONAL;
    if (str == "parallel") return ChainMode::PARALLEL;
    return ChainMode::SEQUENTIAL;
}

// ============================================================================
// ChainConfig Serialization
// ============================================================================

std::string ChainConfig::to_json() const {
    Json::Value root;
    root["name"] = name;
    root["mode"] = chain_mode_to_string(mode);
    root["description"] = description;
    root["condition_expression"] = condition_expression;
    root["precompute_blend"] = precompute_blend;
    root["cache_intermediates"] = cache_intermediates;
    root["created_timestamp"] = static_cast<Json::UInt64>(created_timestamp);
    root["modified_timestamp"] = static_cast<Json::UInt64>(modified_timestamp);
    
    Json::Value tags_json(Json::Value::arrayValue);
    for (const auto& tag : tags) {
        tags_json.append(tag);
    }
    root["tags"] = tags_json;
    
    Json::Value entries_json(Json::Value::arrayValue);
    for (const auto& entry : entries) {
        Json::Value entry_json;
        entry_json["adapter_name"] = entry.adapter_name;
        entry_json["weight"] = entry.weight;
        entry_json["enabled"] = entry.enabled;
        entries_json.append(entry_json);
    }
    root["entries"] = entries_json;
    
    Json::StreamWriterBuilder builder;
    return Json::writeString(builder, root);
}

std::optional<ChainConfig> ChainConfig::from_json(const std::string& json_str) {
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errors;
    
    std::istringstream json_stream(json_str);
    if (!Json::parseFromStream(builder, json_stream, &root, &errors)) {
        return std::nullopt;
    }
    
    ChainConfig config;
    config.name = root.get("name", "").asString();
    config.mode = chain_mode_from_string(root.get("mode", "sequential").asString());
    config.description = root.get("description", "").asString();
    config.condition_expression = root.get("condition_expression", "").asString();
    config.precompute_blend = root.get("precompute_blend", false).asBool();
    config.cache_intermediates = root.get("cache_intermediates", false).asBool();
    config.created_timestamp = root.get("created_timestamp", 0).asUInt64();
    config.modified_timestamp = root.get("modified_timestamp", 0).asUInt64();
    
    const Json::Value tags = root["tags"];
    if (tags.isArray()) {
        for (const auto& tag : tags) {
            config.tags.push_back(tag.asString());
        }
    }
    
    const Json::Value entries = root["entries"];
    if (entries.isArray()) {
        for (const auto& entry_json : entries) {
            ChainEntry entry;
            entry.adapter_name = entry_json.get("adapter_name", "").asString();
            entry.weight = entry_json.get("weight", 1.0f).asFloat();
            entry.enabled = entry_json.get("enabled", true).asBool();
            config.entries.push_back(entry);
        }
    }
    
    return config;
}

std::optional<ChainConfig> ChainConfig::from_file(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file) {
        return std::nullopt;
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    return from_json(content);
}

bool ChainConfig::save_to_file(const std::filesystem::path& path) const {
    std::filesystem::create_directories(path.parent_path());
    
    std::ofstream file(path);
    if (!file) {
        return false;
    }
    
    file << to_json();
    return file.good();
}

// ============================================================================
// BeaconChainManager Implementation
// ============================================================================

BeaconChainManager& BeaconChainManager::instance() {
    static BeaconChainManager instance;
    return instance;
}

BeaconChainManager::~BeaconChainManager() {
    deactivate_chain();
    destroy_beacon_chain();
}

void BeaconChainManager::initialize(const std::filesystem::path& chains_directory) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_chains_dir = chains_directory;
    std::filesystem::create_directories(m_chains_dir);
    
    // Load all existing chains
    for (const auto& entry : std::filesystem::directory_iterator(m_chains_dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".json") {
            auto config = ChainConfig::from_file(entry.path());
            if (config) {
                m_chains[config->name] = *config;
            }
        }
    }
}

bool BeaconChainManager::create_chain(const ChainConfig& config) {
    if (!validate_chain(config)) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_chains.find(config.name) != m_chains.end()) {
        return false; // Already exists
    }
    
    ChainConfig new_config = config;
    new_config.created_timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    new_config.modified_timestamp = new_config.created_timestamp;
    
    // Save to disk
    auto path = get_chain_path(config.name);
    if (!new_config.save_to_file(path)) {
        return false;
    }
    
    m_chains[config.name] = new_config;
    m_stats[config.name] = ChainStats{};
    m_stats[config.name].chain_name = config.name;
    
    notify_event(config.name, "created");
    return true;
}

bool BeaconChainManager::update_chain(const std::string& name, const ChainConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_chains.find(name);
    if (it == m_chains.end()) {
        return false;
    }
    
    ChainConfig updated = config;
    updated.name = name;
    updated.modified_timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    
    auto path = get_chain_path(name);
    if (!updated.save_to_file(path)) {
        return false;
    }
    
    it->second = updated;
    
    // Rebuild beacon chain if this is the active chain
    if (m_active_chain == name) {
        update_beacon_chain_state();
    }
    
    notify_event(name, "updated");
    return true;
}

bool BeaconChainManager::delete_chain(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Deactivate if active
    if (m_active_chain == name) {
        deactivate_chain();
    }
    
    // Remove from memory
    m_chains.erase(name);
    m_stats.erase(name);
    
    // Remove from disk
    auto path = get_chain_path(name);
    std::filesystem::remove(path);
    
    notify_event(name, "deleted");
    return true;
}

bool BeaconChainManager::load_chain(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_chains.find(name);
    if (it == m_chains.end()) {
        // Try loading from disk
        auto path = get_chain_path(name);
        auto config = ChainConfig::from_file(path);
        if (!config) {
            return false;
        }
        m_chains[name] = *config;
        m_stats[name] = ChainStats{};
        m_stats[name].chain_name = name;
    }
    
    m_loaded_chain = name;
    return true;
}

void BeaconChainManager::unload_chain(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_active_chain == name) {
        deactivate_chain();
    }
    
    if (m_loaded_chain == name) {
        m_loaded_chain.clear();
    }
}

bool BeaconChainManager::activate_chain(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Ensure chain exists
    auto it = m_chains.find(name);
    if (it == m_chains.end()) {
        if (!load_chain(name)) {
            return false;
        }
        it = m_chains.find(name);
    }
    
    // Deactivate current chain
    if (!m_active_chain.empty()) {
        deactivate_chain();
    }
    
    // Build beacon chain
    if (!build_beacon_chain(it->second)) {
        return false;
    }
    
    m_active_chain = name;
    notify_event(name, "activated");
    return true;
}

void BeaconChainManager::deactivate_chain() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_active_chain.empty()) {
        notify_event(m_active_chain, "deactivated");
        m_active_chain.clear();
    }
    
    // Clear beacon state
    auto* beacon = lora_get_beacon();
    if (beacon) {
        lora_clear_beacon();
    }
    
    destroy_beacon_chain();
}

bool BeaconChainManager::is_chain_active(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_active_chain == name;
}

bool BeaconChainManager::is_chain_loaded(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_chains.find(name) != m_chains.end();
}

std::string BeaconChainManager::get_active_chain_name() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_active_chain;
}

std::vector<std::string> BeaconChainManager::list_chains() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<std::string> result;
    for (const auto& [name, _] : m_chains) {
        result.push_back(name);
    }
    return result;
}

std::optional<ChainConfig> BeaconChainManager::get_chain_config(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_chains.find(name);
    if (it != m_chains.end()) {
        return it->second;
    }
    return std::nullopt;
}

// ============================================================================
// Entry Management
// ============================================================================

bool BeaconChainManager::add_entry(const std::string& chain_name, const ChainEntry& entry) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_chains.find(chain_name);
    if (it == m_chains.end()) {
        return false;
    }
    
    it->second.entries.push_back(entry);
    it->second.modified_timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    
    // Save updated chain
    auto path = get_chain_path(chain_name);
    it->second.save_to_file(path);
    
    // Update beacon chain if active
    if (m_active_chain == chain_name) {
        update_beacon_chain_state();
    }
    
    return true;
}

bool BeaconChainManager::remove_entry(const std::string& chain_name, const std::string& adapter_name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_chains.find(chain_name);
    if (it == m_chains.end()) {
        return false;
    }
    
    auto& entries = it->second.entries;
    entries.erase(
        std::remove_if(entries.begin(), entries.end(),
            [&adapter_name](const ChainEntry& e) { return e.adapter_name == adapter_name; }),
        entries.end()
    );
    
    it->second.modified_timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    
    auto path = get_chain_path(chain_name);
    it->second.save_to_file(path);
    
    if (m_active_chain == chain_name) {
        update_beacon_chain_state();
    }
    
    return true;
}

bool BeaconChainManager::update_entry_weight(const std::string& chain_name,
                                            const std::string& adapter_name,
                                            float new_weight) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_chains.find(chain_name);
    if (it == m_chains.end()) {
        return false;
    }
    
    for (auto& entry : it->second.entries) {
        if (entry.adapter_name == adapter_name) {
            entry.weight = new_weight;
            break;
        }
    }
    
    it->second.modified_timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    
    auto path = get_chain_path(chain_name);
    it->second.save_to_file(path);
    
    if (m_active_chain == chain_name) {
        update_beacon_chain_state();
    }
    
    return true;
}

bool BeaconChainManager::toggle_entry(const std::string& chain_name,
                                     const std::string& adapter_name,
                                     bool enabled) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_chains.find(chain_name);
    if (it == m_chains.end()) {
        return false;
    }
    
    for (auto& entry : it->second.entries) {
        if (entry.adapter_name == adapter_name) {
            entry.enabled = enabled;
            break;
        }
    }
    
    it->second.modified_timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    
    auto path = get_chain_path(chain_name);
    it->second.save_to_file(path);
    
    if (m_active_chain == chain_name) {
        update_beacon_chain_state();
    }
    
    return true;
}

// ============================================================================
// Beacon Chain Building
// ============================================================================

bool BeaconChainManager::build_beacon_chain(const ChainConfig& config) {
    // Clean up existing
    destroy_beacon_chain();
    
    // Allocate beacon chain
    m_beacon_chain = static_cast<LoRABeaconChain*>(
        lora_aligned_alloc(sizeof(LoRABeaconChain), 64)
    );
    if (!m_beacon_chain) {
        return false;
    }
    
    std::memset(m_beacon_chain, 0, sizeof(LoRABeaconChain));
    
    // Build linked list of beacon states
    LoRABeaconState* prev_beacon = nullptr;
    
    for (const auto& entry : config.entries) {
        if (!entry.enabled) continue;
        
        // Load adapter data
        auto adapter_data = AdapterCacheManager::instance().load(entry.adapter_name);
        if (!adapter_data) {
            continue; // Skip missing adapters
        }
        
        // Allocate beacon state
        LoRABeaconState* beacon = static_cast<LoRABeaconState*>(
            lora_aligned_alloc(sizeof(LoRABeaconState), 64)
        );
        if (!beacon) {
            destroy_beacon_chain();
            return false;
        }
        
        std::memset(beacon, 0, sizeof(LoRABeaconState));
        
        // Allocate aligned buffers for A and B
        size_t a_size = adapter_data->matrix_a.size() * sizeof(float);
        size_t b_size = adapter_data->matrix_b.size() * sizeof(float);
        
        float* A_buffer = static_cast<float*>(lora_aligned_alloc(a_size, 32));
        float* B_buffer = static_cast<float*>(lora_aligned_alloc(b_size, 32));
        
        if (!A_buffer || !B_buffer) {
            lora_aligned_free(A_buffer);
            lora_aligned_free(B_buffer);
            lora_aligned_free(beacon);
            destroy_beacon_chain();
            return false;
        }
        
        // Copy data
        std::memcpy(A_buffer, adapter_data->matrix_a.data(), a_size);
        std::memcpy(B_buffer, adapter_data->matrix_b.data(), b_size);
        
        // Initialize beacon state
        beacon->version = 1;
        beacon->status = LORA_BEACON_ACTIVE;
        beacon->rank = adapter_data->rank;
        beacon->hidden_dim = adapter_data->in_features;  // Map in_features to hidden_dim
        beacon->ptr_A = A_buffer;
        beacon->ptr_B = B_buffer;
        beacon->scale_factor = entry.weight;
        beacon->next_adapter = nullptr;
        beacon->composite_weight = entry.weight;
        
        // Link to chain
        if (prev_beacon) {
            prev_beacon->next_adapter = beacon;
        } else {
            m_beacon_chain->head = beacon;
        }
        
        prev_beacon = beacon;
        m_beacon_states.push_back(beacon);
    }
    
    m_beacon_chain->tail = prev_beacon;
    m_beacon_chain->adapter_count = static_cast<uint32_t>(m_beacon_states.size());
    m_beacon_chain->active_count = m_beacon_chain->adapter_count;
    
    // Set mode-specific flags
    switch (config.mode) {
        case ChainMode::SEQUENTIAL:
            m_beacon_chain->flags = 0;
            break;
        case ChainMode::WEIGHTED_BLEND:
            m_beacon_chain->flags = 1; // Flag for blend mode
            // Precompute blended weights if requested
            if (config.precompute_blend) {
                // TODO: Implement weight blending
            }
            break;
        default:
            m_beacon_chain->flags = 0;
            break;
    }
    
    return true;
}

void BeaconChainManager::destroy_beacon_chain() {
    if (!m_beacon_chain) {
        return;
    }
    
    // Free all beacon states and their buffers
    for (auto* beacon : m_beacon_states) {
        if (beacon) {
            lora_aligned_free(beacon->ptr_A);
            lora_aligned_free(beacon->ptr_B);
            lora_aligned_free(beacon);
        }
    }
    m_beacon_states.clear();
    
    // Free chain
    lora_aligned_free(m_beacon_chain);
    m_beacon_chain = nullptr;
}

bool BeaconChainManager::update_beacon_chain_state() {
    if (!m_active_chain.empty()) {
        auto it = m_chains.find(m_active_chain);
        if (it != m_chains.end()) {
            return build_beacon_chain(it->second);
        }
    }
    return false;
}

// ============================================================================
// Factory Methods
// ============================================================================

ChainConfig BeaconChainManager::create_python_chain() {
    ChainConfig config;
    config.name = "python-default";
    config.mode = ChainMode::SEQUENTIAL;
    config.description = "Default Python coding assistant";
    config.tags = {"python", "general"};
    
    ChainEntry entry;
    entry.adapter_name = "python-base";
    entry.weight = 1.0f;
    entry.enabled = true;
    config.entries.push_back(entry);
    
    return config;
}

ChainConfig BeaconChainManager::create_cpp_chain() {
    ChainConfig config;
    config.name = "cpp-default";
    config.mode = ChainMode::SEQUENTIAL;
    config.description = "C++ coding assistant with STL support";
    config.tags = {"cpp", "c++", "stl"};
    
    ChainEntry entry;
    entry.adapter_name = "cpp-base";
    entry.weight = 1.0f;
    entry.enabled = true;
    config.entries.push_back(entry);
    
    return config;
}

ChainConfig BeaconChainManager::create_web_chain() {
    ChainConfig config;
    config.name = "web-fullstack";
    config.mode = ChainMode::SEQUENTIAL;
    config.description = "Full-stack web development (JS/TS/React/Node)";
    config.tags = {"javascript", "typescript", "react", "node"};
    
    ChainEntry js_entry;
    js_entry.adapter_name = "javascript-base";
    js_entry.weight = 0.6f;
    js_entry.enabled = true;
    config.entries.push_back(js_entry);
    
    ChainEntry react_entry;
    react_entry.adapter_name = "react-patterns";
    react_entry.weight = 0.4f;
    react_entry.enabled = true;
    config.entries.push_back(react_entry);
    
    return config;
}

ChainConfig BeaconChainManager::create_ml_chain() {
    ChainConfig config;
    config.name = "ml-python";
    config.mode = ChainMode::SEQUENTIAL;
    config.description = "Machine Learning with PyTorch/NumPy";
    config.tags = {"python", "ml", "pytorch", "numpy"};
    
    ChainEntry py_entry;
    py_entry.adapter_name = "python-base";
    py_entry.weight = 0.5f;
    py_entry.enabled = true;
    config.entries.push_back(py_entry);
    
    ChainEntry ml_entry;
    ml_entry.adapter_name = "pytorch-patterns";
    ml_entry.weight = 0.5f;
    ml_entry.enabled = true;
    config.entries.push_back(ml_entry);
    
    return config;
}

ChainConfig BeaconChainManager::create_security_chain() {
    ChainConfig config;
    config.name = "security-focused";
    config.mode = ChainMode::CONDITIONAL;
    config.description = "Security-focused coding patterns";
    config.condition_expression = "has_security_keywords == true";
    config.tags = {"security", "hardening"};
    
    ChainEntry entry;
    entry.adapter_name = "security-best-practices";
    entry.weight = 1.0f;
    entry.enabled = true;
    config.entries.push_back(entry);
    
    return config;
}

// ============================================================================
// Validation
// ============================================================================

bool BeaconChainManager::validate_chain(const ChainConfig& config) const {
    return get_validation_errors(config).empty();
}

std::vector<std::string> BeaconChainManager::get_validation_errors(const ChainConfig& config) const {
    std::vector<std::string> errors;
    
    if (config.name.empty()) {
        errors.push_back("Chain name cannot be empty");
    }
    
    if (config.entries.empty()) {
        errors.push_back("Chain must have at least one entry");
    }
    
    for (const auto& entry : config.entries) {
        if (entry.adapter_name.empty()) {
            errors.push_back("Entry adapter name cannot be empty");
        }
        if (entry.weight < 0.0f) {
            errors.push_back("Entry weight cannot be negative");
        }
    }
    
    return errors;
}

// ============================================================================
// Import/Export
// ============================================================================

bool BeaconChainManager::export_chain(const std::string& chain_name, const std::filesystem::path& export_path) {
    auto config = get_chain_config(chain_name);
    if (!config) {
        return false;
    }
    
    return config->save_to_file(export_path);
}

bool BeaconChainManager::import_chain(const std::filesystem::path& import_path, const std::string& new_name) {
    auto config = ChainConfig::from_file(import_path);
    if (!config) {
        return false;
    }
    
    if (!new_name.empty()) {
        config->name = new_name;
    }
    
    return create_chain(*config);
}

// ============================================================================
// C Interface
// ============================================================================

LoRABeaconChain* BeaconChainManager::get_beacon_chain_c() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_beacon_chain;
}

// ============================================================================
// Event Callbacks
// ============================================================================

void BeaconChainManager::set_event_callback(ChainEventCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_event_callback = callback;
}

void BeaconChainManager::notify_event(const std::string& chain_name, const std::string& event_type) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_event_callback) {
        m_event_callback(chain_name, event_type);
    }
}

// ============================================================================
// Statistics
// ============================================================================

ChainStats BeaconChainManager::get_stats(const std::string& chain_name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_stats.find(chain_name);
    if (it != m_stats.end()) {
        return it->second;
    }
    return ChainStats{};
}

std::vector<ChainStats> BeaconChainManager::get_all_stats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<ChainStats> result;
    for (const auto& [name, stats] : m_stats) {
        result.push_back(stats);
    }
    return result;
}

void BeaconChainManager::reset_stats(const std::string& chain_name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_stats.find(chain_name);
    if (it != m_stats.end()) {
        it->second = ChainStats{};
        it->second.chain_name = chain_name;
    }
}

// ============================================================================
// Path Helpers
// ============================================================================

std::filesystem::path BeaconChainManager::get_chain_path(const std::string& name) const {
    return m_chains_dir / (name + ".json");
}

// ============================================================================
// Utility Functions
// ============================================================================

bool quick_activate_chain(const std::string& name) {
    return BeaconChainManager::instance().activate_chain(name);
}

void quick_deactivate_chain() {
    BeaconChainManager::instance().deactivate_chain();
}

bool quick_create_sequential_chain(const std::string& name, const std::vector<std::string>& adapter_names) {
    ChainConfig config;
    config.name = name;
    config.mode = ChainMode::SEQUENTIAL;
    
    for (const auto& adapter_name : adapter_names) {
        ChainEntry entry;
        entry.adapter_name = adapter_name;
        entry.weight = 1.0f;
        entry.enabled = true;
        config.entries.push_back(entry);
    }
    
    return BeaconChainManager::instance().create_chain(config);
}

ChainConfig make_composite_chain(const std::string& name,
                                 const std::vector<std::pair<std::string, float>>& adapters) {
    ChainConfig config;
    config.name = name;
    config.mode = ChainMode::WEIGHTED_BLEND;
    
    for (const auto& [adapter_name, weight] : adapters) {
        ChainEntry entry;
        entry.adapter_name = adapter_name;
        entry.weight = weight;
        entry.enabled = true;
        config.entries.push_back(entry);
    }
    
    return config;
}

bool validate_chain_name(const std::string& name) {
    if (name.empty() || name.length() > 128) {
        return false;
    }
    
    for (char c : name) {
        if (!std::isalnum(c) && c != '-' && c != '_' && c != '.') {
            return false;
        }
    }
    
    return true;
}

std::string sanitize_chain_name(const std::string& name) {
    std::string result;
    result.reserve(name.length());
    
    for (char c : name) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.') {
            result += c;
        } else {
            result += '_';
        }
    }
    
    // Trim to max length
    if (result.length() > 128) {
        result = result.substr(0, 128);
    }
    
    return result;
}

} // namespace RawrXD
