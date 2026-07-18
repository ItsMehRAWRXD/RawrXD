// secure_config.cpp
// Batch 13: Secure Configuration Management
//
// Manages sensitive configuration securely
// Features: Encryption, secrets management, secure defaults

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <fstream>
#include <sstream>
#include <mutex>
#include <optional>

namespace Benchmark {
namespace Security {

// Secure string that clears memory on destruction
class SecureString {
public:
    SecureString() = default;
    explicit SecureString(const std::string& str) : data_(str) {}
    
    ~SecureString() {
        Clear();
    }
    
    // Disable copy
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;
    
    // Enable move
    SecureString(SecureString&& other) noexcept : data_(std::move(other.data_)) {
        other.data_.clear();
    }
    
    SecureString& operator=(SecureString&& other) noexcept {
        if (this != &other) {
            Clear();
            data_ = std::move(other.data_);
            other.data_.clear();
        }
        return *this;
    }
    
    const char* c_str() const { return data_.c_str(); }
    const std::string& str() const { return data_; }
    size_t length() const { return data_.length(); }
    bool empty() const { return data_.empty(); }
    
    void Clear() {
        // Overwrite memory
        for (auto& c : data_) {
            c = 0;
        }
        data_.clear();
    }

private:
    std::string data_;
};

// Configuration value with metadata
struct ConfigValue {
    std::string key;
    std::string value;
    bool encrypted;
    bool sensitive;
    std::string source;  // file, env, vault
    int64_t modified_at;
};

// Secure configuration manager
class SecureConfigManager {
public:
    struct Config {
        std::string config_file = "config.json";
        std::string secrets_file = "secrets.enc";
        bool encrypt_secrets = true;
        bool allow_env_override = true;
        std::vector<std::string> sensitive_keys = {
            "api_key", "password", "secret", "token", "private_key"
        };
    };
    
    explicit SecureConfigManager(const Config& config = Config()) 
        : config_(config) {}
    
    // Load configuration
    bool Load() {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        // Load main config
        if (!LoadFromFile(config_.config_file)) {
            return false;
        }
        
        // Load secrets if exists
        if (FileExists(config_.secrets_file)) {
            LoadSecrets(config_.secrets_file);
        }
        
        // Apply environment variable overrides
        if (config_.allow_env_override) {
            ApplyEnvironmentOverrides();
        }
        
        // Validate configuration
        return ValidateConfiguration();
    }
    
    // Save configuration
    bool Save() {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        // Separate sensitive values
        std::map<std::string, ConfigValue> regular_config;
        std::map<std::string, ConfigValue> secrets;
        
        for (const auto& [key, value] : values_) {
            if (value.sensitive) {
                secrets[key] = value;
            } else {
                regular_config[key] = value;
            }
        }
        
        // Save regular config
        if (!SaveToFile(config_.config_file, regular_config)) {
            return false;
        }
        
        // Save secrets
        if (!secrets.empty()) {
            if (!SaveSecrets(config_.secrets_file, secrets)) {
                return false;
            }
        }
        
        return true;
    }
    
    // Get configuration value
    std::optional<std::string> Get(const std::string& key) const {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        auto it = values_.find(key);
        if (it != values_.end()) {
            return it->second.value;
        }
        
        return std::nullopt;
    }
    
    // Get with default
    std::string GetOrDefault(const std::string& key, 
                             const std::string& default_value) const {
        auto value = Get(key);
        return value.value_or(default_value);
    }
    
    // Get secure string (for passwords/keys)
    SecureString GetSecure(const std::string& key) const {
        auto value = Get(key);
        if (value.has_value()) {
            return SecureString(value.value());
        }
        return SecureString();
    }
    
    // Set configuration value
    void Set(const std::string& key, const std::string& value,
             bool sensitive = false) {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        ConfigValue config_value;
        config_value.key = key;
        config_value.value = value;
        config_value.sensitive = sensitive || IsSensitiveKey(key);
        config_value.encrypted = false;
        config_value.source = "runtime";
        config_value.modified_at = GetTimestamp();
        
        values_[key] = config_value;
    }
    
    // Set encrypted value
    void SetEncrypted(const std::string& key, const std::string& encrypted_value) {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        ConfigValue config_value;
        config_value.key = key;
        config_value.value = Decrypt(encrypted_value);
        config_value.sensitive = true;
        config_value.encrypted = true;
        config_value.source = "encrypted";
        config_value.modified_at = GetTimestamp();
        
        values_[key] = config_value;
    }
    
    // Check if key exists
    bool Has(const std::string& key) const {
        std::lock_guard<std::mutex> lock(config_mutex_);
        return values_.find(key) != values_.end();
    }
    
    // Remove key
    bool Remove(const std::string& key) {
        std::lock_guard<std::mutex> lock(config_mutex_);
        return values_.erase(key) > 0;
    }
    
    // Get all keys
    std::vector<std::string> GetKeys() const {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        std::vector<std::string> keys;
        for (const auto& [key, _] : values_) {
            keys.push_back(key);
        }
        
        return keys;
    }
    
    // Get all non-sensitive values (for display)
    std::map<std::string, std::string> GetPublicConfig() const {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        std::map<std::string, std::string> public_config;
        for (const auto& [key, value] : values_) {
            if (!value.sensitive) {
                public_config[key] = value.value;
            } else {
                public_config[key] = "***REDACTED***";
            }
        }
        
        return public_config;
    }
    
    // Validate configuration
    bool ValidateConfiguration() const {
        // Check required values
        std::vector<std::string> required = {
            "benchmark.default_iterations",
            "benchmark.timeout_seconds"
        };
        
        for (const auto& key : required) {
            if (!Has(key)) {
                return false;
            }
        }
        
        // Validate ranges
        auto iterations = Get("benchmark.default_iterations");
        if (iterations.has_value()) {
            int val = std::stoi(iterations.value());
            if (val < 1 || val > 10000) {
                return false;
            }
        }
        
        return true;
    }
    
    // Export configuration (excluding secrets)
    std::string ExportToJSON() const {
        std::stringstream json;
        json << "{";
        
        bool first = true;
        for (const auto& [key, value] : values_) {
            if (value.sensitive) continue;
            
            if (!first) json << ",";
            json << "\"" << key << "\":";
            
            // Try to parse as number
            bool is_number = true;
            for (char c : value.value) {
                if (!std::isdigit(c) && c != '.' && c != '-') {
                    is_number = false;
                    break;
                }
            }
            
            if (is_number) {
                json << value.value;
            } else {
                json << "\"" << value.value << "\"";
            }
            
            first = false;
        }
        
        json << "}";
        return json.str();
    }

private:
    Config config_;
    mutable std::mutex config_mutex_;
    std::map<std::string, ConfigValue> values_;
    
    bool LoadFromFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            return false;
        }
        
        // Simplified JSON parsing
        // In production: Use proper JSON library
        std::string line;
        while (std::getline(file, line)) {
            // Parse key-value pairs
            size_t colon = line.find(':');
            if (colon != std::string::npos) {
                std::string key = line.substr(0, colon);
                std::string value = line.substr(colon + 1);
                
                // Trim whitespace and quotes
                key = Trim(key);
                value = Trim(value, " \"\t\n\r");
                
                Set(key, value, IsSensitiveKey(key));
            }
        }
        
        return true;
    }
    
    bool SaveToFile(const std::string& filename,
                    const std::map<std::string, ConfigValue>& config) {
        std::ofstream file(filename);
        if (!file.is_open()) {
            return false;
        }
        
        file << "{" << std::endl;
        bool first = true;
        for (const auto& [key, value] : config) {
            if (!first) file << "," << std::endl;
            file << "  \"" << key << "\": ";
            
            // Check if numeric
            bool is_number = true;
            for (char c : value.value) {
                if (!std::isdigit(c) && c != '.' && c != '-') {
                    is_number = false;
                    break;
                }
            }
            
            if (is_number) {
                file << value.value;
            } else {
                file << "\"" << value.value << "\"";
            }
            
            first = false;
        }
        file << std::endl << "}" << std::endl;
        
        return true;
    }
    
    bool LoadSecrets(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            return false;
        }
        
        // Read encrypted secrets
        std::string encrypted_data((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());
        
        // Decrypt and parse
        std::string decrypted = Decrypt(encrypted_data);
        // Parse decrypted secrets
        
        return true;
    }
    
    bool SaveSecrets(const std::string& filename,
                     const std::map<std::string, ConfigValue>& secrets) {
        std::stringstream data;
        for (const auto& [key, value] : secrets) {
            data << key << "=" << value.value << std::endl;
        }
        
        std::string encrypted = Encrypt(data.str());
        
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }
        
        file.write(encrypted.c_str(), encrypted.length());
        return true;
    }
    
    void ApplyEnvironmentOverrides() {
        // Check for BENCHMARK_* environment variables
        // In production: Use getenv or platform-specific APIs
    }
    
    bool IsSensitiveKey(const std::string& key) const {
        std::string lower = key;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        
        for (const auto& sensitive : config_.sensitive_keys) {
            if (lower.find(sensitive) != std::string::npos) {
                return true;
            }
        }
        
        return false;
    }
    
    bool FileExists(const std::string& filename) const {
        std::ifstream file(filename);
        return file.good();
    }
    
    std::string Encrypt(const std::string& data) {
        // Placeholder - in production: Use AES-256-GCM
        return data;
    }
    
    std::string Decrypt(const std::string& data) {
        // Placeholder - in production: Use AES-256-GCM
        return data;
    }
    
    std::string Trim(const std::string& str, const std::string& chars = " \t\n\r") {
        size_t first = str.find_first_not_of(chars);
        if (first == std::string::npos) return "";
        
        size_t last = str.find_last_not_of(chars);
        return str.substr(first, last - first + 1);
    }
    
    int64_t GetTimestamp() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

// Default secure configuration
struct DefaultSecureConfig {
    static std::map<std::string, std::string> Get() {
        return {
            // Security settings
            {"security.enable_auth", "true"},
            {"security.enable_rate_limiting", "true"},
            {"security.enable_audit_logging", "true"},
            {"security.session_timeout_minutes", "60"},
            {"security.api_key_rotation_days", "90"},
            
            // Rate limiting
            {"rate_limit.global_requests_per_minute", "1000"},
            {"rate_limit.ip_requests_per_minute", "60"},
            {"rate_limit.user_requests_per_minute", "120"},
            
            // Audit logging
            {"audit.log_directory", "./logs/audit"},
            {"audit.max_file_size_mb", "100"},
            {"audit.retention_days", "90"},
            
            // Input validation
            {"validation.max_request_size_mb", "10"},
            {"validation.max_prompt_length", "10000"},
            {"validation.max_tokens", "8192"},
            
            // Benchmark defaults
            {"benchmark.default_iterations", "30"},
            {"benchmark.timeout_seconds", "300"},
            {"benchmark.warmup_iterations", "5"},
            {"benchmark.confidence_level", "0.95"}
        };
    }
};

} // namespace Security
} // namespace Benchmark
