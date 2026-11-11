#include "AdapterRegistry.h"
#include <fstream>
#include <json/json.h>
#include <cstring>
#include <algorithm>

namespace RawrXD {

// ============================================================================
// AdapterWeights Implementation
// ============================================================================

void AdapterWeights::apply_lora(const float* input, float* output) const {
    if (!is_valid()) return;
    
    // Compute: output = B * A * input
    // Step 1: temp = A * input (rank x 1 vector)
    std::vector<float> temp(rank, 0.0f);
    for (uint32_t r = 0; r < rank; ++r) {
        float sum = 0.0f;
        for (uint32_t i = 0; i < in_features; ++i) {
            sum += A[r * in_features + i] * input[i];
        }
        temp[r] = sum;
    }
    
    // Step 2: output = B * temp
    for (uint32_t o = 0; o < out_features; ++o) {
        float sum = 0.0f;
        for (uint32_t r = 0; r < rank; ++r) {
            sum += B[o * rank + r] * temp[r];
        }
        output[o] = sum;
    }
}

// ============================================================================
// AdapterManifest Implementation
// ============================================================================

std::string AdapterManifest::to_json() const {
    Json::Value root;
    root["name"] = name;
    root["version"] = version;
    root["base_model"] = base_model;
    root["base_model_version"] = base_model_version;
    root["description"] = description;
    root["rank"] = rank;
    
    Json::Value tags_json(Json::Value::arrayValue);
    for (const auto& tag : tags) {
        tags_json.append(tag);
    }
    root["tags"] = tags_json;
    
    root["trained_samples"] = static_cast<Json::UInt64>(trained_samples);
    root["training_loss"] = training_loss;
    root["created_timestamp"] = static_cast<Json::UInt64>(created_timestamp);
    root["modified_timestamp"] = static_cast<Json::UInt64>(modified_timestamp);
    
    Json::StreamWriterBuilder builder;
    return Json::writeString(builder, root);
}

std::optional<AdapterManifest> AdapterManifest::from_json(const std::string& json_str) {
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errors;
    
    std::istringstream json_stream(json_str);
    if (!Json::parseFromStream(builder, json_stream, &root, &errors)) {
        return std::nullopt;
    }
    
    AdapterManifest manifest;
    manifest.name = root.get("name", "").asString();
    manifest.version = root.get("version", "1.0.0").asString();
    manifest.base_model = root.get("base_model", "").asString();
    manifest.base_model_version = root.get("base_model_version", "").asString();
    manifest.description = root.get("description", "").asString();
    manifest.rank = root.get("rank", 8).asUInt();
    
    const Json::Value tags = root["tags"];
    if (tags.isArray()) {
        for (const auto& tag : tags) {
            manifest.tags.push_back(tag.asString());
        }
    }
    
    manifest.trained_samples = root.get("trained_samples", 0).asUInt64();
    manifest.training_loss = root.get("training_loss", 0.0).asDouble();
    manifest.created_timestamp = root.get("created_timestamp", 0).asUInt64();
    manifest.modified_timestamp = root.get("modified_timestamp", 0).asUInt64();
    
    return manifest;
}

// ============================================================================
// AdapterRegistry Implementation
// ============================================================================

AdapterRegistry& AdapterRegistry::instance() {
    static AdapterRegistry instance;
    return instance;
}

AdapterRegistry::AdapterRegistry() {
    // Default cache directory: %USERPROFILE%\.rawrxd\adapters
    const char* user_profile = std::getenv("USERPROFILE");
    if (user_profile) {
        m_cache_dir = std::filesystem::path(user_profile) / ".rawrxd" / "adapters";
    } else {
        m_cache_dir = std::filesystem::temp_directory_path() / "rawrxd_adapters";
    }
    
    // Ensure directory exists
    std::filesystem::create_directories(m_cache_dir);
    
    // Initialize embedding hook
    m_embedding_hook = std::make_unique<LoRAEmbeddingHook>();
}

bool AdapterRegistry::load_adapter(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Already loaded
    if (m_registry.find(name) != m_registry.end()) {
        return true;
    }
    
    std::filesystem::path lora_path = m_cache_dir / (name + ".lora");
    std::filesystem::path manifest_path = m_cache_dir / (name + ".json");
    
    // Parse weights
    auto weights = parse_lora_file(lora_path);
    if (!weights) {
        return false;
    }
    
    // Parse manifest if exists
    auto manifest = parse_manifest(manifest_path);
    if (manifest) {
        m_manifests[name] = *manifest;
    }
    
    m_registry[name] = std::move(*weights);
    return true;
}

void AdapterRegistry::unload_adapter(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Deactivate if currently active
    if (m_active_adapter_id == name) {
        deactivate_adapter();
    }
    
    m_registry.erase(name);
    m_manifests.erase(name);
}

bool AdapterRegistry::activate_adapter(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Ensure loaded
    if (m_registry.find(name) == m_registry.end()) {
        if (!load_adapter(name)) {
            return false;
        }
    }
    
    // Update active
    m_active_adapter_id = name;
    if (m_embedding_hook) {
        m_embedding_hook->set_weights(&m_registry[name]);
    }
    
    return true;
}

void AdapterRegistry::deactivate_adapter() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_active_adapter_id.clear();
    if (m_embedding_hook) {
        m_embedding_hook->set_weights(nullptr);
    }
}

const AdapterWeights* AdapterRegistry::get_active_weights() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_active_adapter_id.empty()) {
        return nullptr;
    }
    
    auto it = m_registry.find(m_active_adapter_id);
    if (it != m_registry.end()) {
        return &it->second;
    }
    return nullptr;
}

const AdapterManifest* AdapterRegistry::get_active_manifest() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_active_adapter_id.empty()) {
        return nullptr;
    }
    
    auto it = m_manifests.find(m_active_adapter_id);
    if (it != m_manifests.end()) {
        return &it->second;
    }
    return nullptr;
}

bool AdapterRegistry::is_loaded(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_registry.find(name) != m_registry.end();
}

std::vector<std::string> AdapterRegistry::list_loaded() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<std::string> result;
    for (const auto& [name, _] : m_registry) {
        result.push_back(name);
    }
    return result;
}

std::filesystem::path AdapterRegistry::get_adapter_cache_dir() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_cache_dir;
}

void AdapterRegistry::set_adapter_cache_dir(const std::filesystem::path& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_cache_dir = path;
    std::filesystem::create_directories(m_cache_dir);
}

LoRAEmbeddingHook* AdapterRegistry::get_embedding_hook() {
    return m_embedding_hook.get();
}

// Binary format for .lora files:
// Header: "RAWRLORA" (8 bytes)
// Version: uint32_t (4 bytes)
// Rank: uint32_t
// InFeatures: uint32_t
// OutFeatures: uint32_t
// A weights: float[rank * in_features]
// B weights: float[out_features * rank]
std::optional<AdapterWeights> AdapterRegistry::parse_lora_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }
    
    // Read header
    char header[8];
    file.read(header, 8);
    if (std::memcmp(header, "RAWRLORA", 8) != 0) {
        return std::nullopt;
    }
    
    // Read version
    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (version != 1) {
        return std::nullopt; // Unsupported version
    }
    
    AdapterWeights weights;
    file.read(reinterpret_cast<char*>(&weights.rank), sizeof(weights.rank));
    file.read(reinterpret_cast<char*>(&weights.in_features), sizeof(weights.in_features));
    file.read(reinterpret_cast<char*>(&weights.out_features), sizeof(weights.out_features));
    
    // Read A matrix
    size_t a_size = weights.rank * weights.in_features;
    weights.A.resize(a_size);
    file.read(reinterpret_cast<char*>(weights.A.data()), a_size * sizeof(float));
    
    // Read B matrix
    size_t b_size = weights.out_features * weights.rank;
    weights.B.resize(b_size);
    file.read(reinterpret_cast<char*>(weights.B.data()), b_size * sizeof(float));
    
    if (!file || !weights.is_valid()) {
        return std::nullopt;
    }
    
    return weights;
}

std::optional<AdapterManifest> AdapterRegistry::parse_manifest(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file) {
        return std::nullopt;
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    
    return AdapterManifest::from_json(content);
}

// ============================================================================
// LoRAEmbeddingHook Implementation
// ============================================================================

LoRAEmbeddingHook::LoRAEmbeddingHook() = default;
LoRAEmbeddingHook::~LoRAEmbeddingHook() = default;

void LoRAEmbeddingHook::set_weights(const AdapterWeights* weights) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_weights = weights;
}

void LoRAEmbeddingHook::apply(
    const float* base_output,
    const float* input,
    float* result,
    size_t batch_size,
    size_t seq_length,
    size_t hidden_dim
) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_weights || !m_weights->is_valid()) {
        // No LoRA active, just copy base output
        std::memcpy(result, base_output, batch_size * seq_length * hidden_dim * sizeof(float));
        return;
    }
    
    const size_t total_tokens = batch_size * seq_length;
    
    // Ensure temp buffer is large enough
    if (m_temp_buffer.size() < m_weights->rank) {
        m_temp_buffer.resize(m_weights->rank);
    }
    
    // For each token: result = base_output + B * A * input
    for (size_t token = 0; token < total_tokens; ++token) {
        const float* token_input = input + token * hidden_dim;
        const float* token_base = base_output + token * hidden_dim;
        float* token_result = result + token * hidden_dim;
        
        // Start with base output
        std::memcpy(token_result, token_base, hidden_dim * sizeof(float));
        
        // Compute LoRA delta: B * A * input
        // Step 1: temp = A * input
        for (uint32_t r = 0; r < m_weights->rank; ++r) {
            float sum = 0.0f;
            for (uint32_t i = 0; i < m_weights->in_features && i < hidden_dim; ++i) {
                sum += m_weights->A[r * m_weights->in_features + i] * token_input[i];
            }
            m_temp_buffer[r] = sum;
        }
        
        // Step 2: Add B * temp to result
        for (uint32_t o = 0; o < m_weights->out_features && o < hidden_dim; ++o) {
            float lora_contrib = 0.0f;
            for (uint32_t r = 0; r < m_weights->rank; ++r) {
                lora_contrib += m_weights->B[o * m_weights->rank + r] * m_temp_buffer[r];
            }
            token_result[o] += lora_contrib;
        }
    }
}

uint32_t LoRAEmbeddingHook::get_rank() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_weights) {
        return m_weights->rank;
    }
    return 0;
}

} // namespace RawrXD
