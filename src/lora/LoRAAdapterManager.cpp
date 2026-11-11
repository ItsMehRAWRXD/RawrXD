#include "LoRAAdapterManager.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#endif

namespace RawrXD {

// LoRAConfig serialization
std::string LoRAConfig::to_json() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"rank\": " << rank << ",\n";
    oss << "  \"alpha\": " << alpha << ",\n";
    oss << "  \"dropout\": " << dropout << ",\n";
    oss << "  \"learning_rate\": " << learning_rate << ",\n";
    oss << "  \"base_model_id\": \"" << base_model_id << "\",\n";
    oss << "  \"target_dim\": " << target_dim << "\n";
    oss << "}";
    return oss.str();
}

LoRAConfig LoRAConfig::from_json(const std::string& json) {
    LoRAConfig config;
    // Simple parsing - production would use proper JSON library
    size_t pos = json.find("\"rank\":");
    if (pos != std::string::npos) {
        config.rank = std::stoi(json.substr(pos + 7));
    }
    pos = json.find("\"alpha\":");
    if (pos != std::string::npos) {
        config.alpha = std::stof(json.substr(pos + 8));
    }
    pos = json.find("\"dropout\":");
    if (pos != std::string::npos) {
        config.dropout = std::stof(json.substr(pos + 10));
    }
    pos = json.find("\"target_dim\":");
    if (pos != std::string::npos) {
        config.target_dim = std::stoi(json.substr(pos + 13));
    }
    return config;
}

// AdapterState validation
bool AdapterState::validate_dimensions() const {
    size_t expected_A = config.target_dim * config.rank;
    size_t expected_B = config.rank * config.target_dim;
    return matrix_A.size() == expected_A && matrix_B.size() == expected_B;
}

// Singleton implementation
LoRAAdapterManager& LoRAAdapterManager::instance() {
    static LoRAAdapterManager inst;
    return inst;
}

LoRAAdapterManager::~LoRAAdapterManager() {
    if (m_initialized) {
        shutdown();
    }
}

bool LoRAAdapterManager::initialize() {
    if (m_initialized) {
        return true;
    }
    
    ensure_adapters_dir();
    
    // Try to load default adapter
    if (!load_adapter("default")) {
        // Create default adapter if it doesn't exist
        LoRAConfig default_config;
        create_adapter("default", default_config);
        activate_adapter("default");
    }
    
    m_initialized = true;
    return true;
}

bool LoRAAdapterManager::load_adapter(const std::string& id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto path = get_adapter_path(id);
    if (!std::filesystem::exists(path)) {
        return false;
    }
    
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        return false;
    }
    
    auto state = std::make_shared<AdapterState>();
    
    // Read header
    uint32_t version;
    ifs.read(reinterpret_cast<char*>(&version), sizeof(version));
    state->version = version;
    
    // Read ID length and ID
    uint32_t id_len;
    ifs.read(reinterpret_cast<char*>(&id_len), sizeof(id_len));
    state->id.resize(id_len);
    ifs.read(state->id.data(), id_len);
    
    // Read config (as JSON for flexibility)
    uint32_t config_len;
    ifs.read(reinterpret_cast<char*>(&config_len), sizeof(config_len));
    std::string config_json(config_len, '\0');
    ifs.read(config_json.data(), config_len);
    state->config = LoRAConfig::from_json(config_json);
    
    // Read matrix dimensions
    uint32_t A_size, B_size;
    ifs.read(reinterpret_cast<char*>(&A_size), sizeof(A_size));
    ifs.read(reinterpret_cast<char*>(&B_size), sizeof(B_size));
    
    // Read matrices
    state->matrix_A.resize(A_size);
    state->matrix_B.resize(B_size);
    ifs.read(reinterpret_cast<char*>(state->matrix_A.data()), A_size * sizeof(float));
    ifs.read(reinterpret_cast<char*>(state->matrix_B.data()), B_size * sizeof(float));
    
    // Read metadata
    ifs.read(reinterpret_cast<char*>(&state->training_samples), sizeof(state->training_samples));
    ifs.read(reinterpret_cast<char*>(&state->avg_loss), sizeof(state->avg_loss));
    
    if (!ifs.good()) {
        return false;
    }
    
    m_registry[id] = state;
    return true;
}

bool LoRAAdapterManager::create_adapter(const std::string& id, const LoRAConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto state = std::make_shared<AdapterState>();
    state->id = id;
    state->name = id;
    state->config = config;
    
    // Initialize matrices
    size_t A_size = config.target_dim * config.rank;
    size_t B_size = config.rank * config.target_dim;
    state->matrix_A.resize(A_size);
    state->matrix_B.resize(B_size);
    
    // Kaiming initialization for A (He initialization)
    std::random_device rd;
    std::mt19937 gen(rd());
    float std_dev = std::sqrt(2.0f / config.target_dim);
    std::normal_distribution<float> dist(0.0f, std_dev);
    
    for (auto& val : state->matrix_A) {
        val = dist(gen);
    }
    
    // Zero initialization for B (standard LoRA practice)
    std::fill(state->matrix_B.begin(), state->matrix_B.end(), 0.0f);
    
    // Timestamps
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%dT%H:%M:%S");
    state->created_at = ss.str();
    state->last_trained_at = ss.str();
    
    m_registry[id] = state;
    return true;
}

void LoRAAdapterManager::activate_adapter(const std::string& id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_registry.find(id);
    if (it != m_registry.end()) {
        m_active_adapter = it->second;
        m_active_id = id;
    }
}

std::shared_ptr<const AdapterState> LoRAAdapterManager::get_active_adapter() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_active_adapter;
}

std::shared_ptr<const AdapterState> LoRAAdapterManager::get_adapter(const std::string& id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_registry.find(id);
    if (it != m_registry.end()) {
        return it->second;
    }
    return nullptr;
}

bool LoRAAdapterManager::has_adapter(const std::string& id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_registry.find(id) != m_registry.end();
}

std::vector<std::string> LoRAAdapterManager::list_adapters() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> ids;
    for (const auto& [id, _] : m_registry) {
        ids.push_back(id);
    }
    return ids;
}

bool LoRAAdapterManager::save_adapter(const std::string& id) const {
    std::shared_ptr<AdapterState> state;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_registry.find(id);
        if (it == m_registry.end()) {
            return false;
        }
        state = it->second;
    }
    
    ensure_adapters_dir();
    auto path = get_adapter_path(id);
    
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) {
        return false;
    }
    
    // Write header
    uint32_t version = state->version;
    ofs.write(reinterpret_cast<const char*>(&version), sizeof(version));
    
    // Write ID
    uint32_t id_len = state->id.size();
    ofs.write(reinterpret_cast<const char*>(&id_len), sizeof(id_len));
    ofs.write(state->id.data(), id_len);
    
    // Write config as JSON
    std::string config_json = state->config.to_json();
    uint32_t config_len = config_json.size();
    ofs.write(reinterpret_cast<const char*>(&config_len), sizeof(config_len));
    ofs.write(config_json.data(), config_len);
    
    // Write matrix dimensions
    uint32_t A_size = state->matrix_A.size();
    uint32_t B_size = state->matrix_B.size();
    ofs.write(reinterpret_cast<const char*>(&A_size), sizeof(A_size));
    ofs.write(reinterpret_cast<const char*>(&B_size), sizeof(B_size));
    
    // Write matrices
    ofs.write(reinterpret_cast<const char*>(state->matrix_A.data()), A_size * sizeof(float));
    ofs.write(reinterpret_cast<const char*>(state->matrix_B.data()), B_size * sizeof(float));
    
    // Write metadata
    ofs.write(reinterpret_cast<const char*>(&state->training_samples), sizeof(state->training_samples));
    ofs.write(reinterpret_cast<const char*>(&state->avg_loss), sizeof(state->avg_loss));
    
    return ofs.good();
}

void LoRAAdapterManager::save_all() const {
    std::vector<std::string> ids;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& [id, _] : m_registry) {
            ids.push_back(id);
        }
    }
    
    for (const auto& id : ids) {
        save_adapter(id);
    }
}

bool LoRAAdapterManager::unload_adapter(const std::string& id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Cannot unload active adapter
    if (m_active_id == id) {
        return false;
    }
    
    auto it = m_registry.find(id);
    if (it == m_registry.end()) {
        return false;
    }
    
    m_registry.erase(it);
    return true;
}

bool LoRAAdapterManager::delete_adapter(const std::string& id) {
    // First unload from memory
    if (!unload_adapter(id)) {
        return false;
    }
    
    // Then delete from disk
    auto path = get_adapter_path(id);
    if (std::filesystem::exists(path)) {
        return std::filesystem::remove(path);
    }
    
    return true;
}

std::string LoRAAdapterManager::get_active_adapter_id() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_active_id;
}

void LoRAAdapterManager::shutdown() {
    save_all();
    m_initialized = false;
}

std::filesystem::path LoRAAdapterManager::get_adapter_path(const std::string& id) const {
    return get_adapters_dir() / (id + ".lora");
}

std::filesystem::path LoRAAdapterManager::get_adapters_dir() const {
#ifdef _WIN32
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, path))) {
        return std::filesystem::path(path) / "RawrXD" / "adapters";
    }
    return std::filesystem::path("C:/RawrXD/adapters");
#else
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (home) {
        return std::filesystem::path(home) / ".config" / "rawrxd" / "adapters";
    }
    return std::filesystem::path("/tmp/rawrxd_adapters");
#endif
}

void LoRAAdapterManager::ensure_adapters_dir() const {
    auto dir = get_adapters_dir();
    if (!std::filesystem::exists(dir)) {
        std::filesystem::create_directories(dir);
    }
}

} // namespace RawrXD
