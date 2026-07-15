/**
 * @file Config.h
 * @brief Configuration management for agentic system
 * 
 * Part of Production Framework - Phase 5
 * Provides centralized configuration with type safety and validation.
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include <string>
#include <unordered_map>
#include <variant>
#include <optional>
#include <mutex>
#include <vector>

namespace RawrXD {
namespace Agentic {

/**
 * @brief Configuration value types
 */
using ConfigValue = std::variant<
    bool,
    int,
    float,
    std::string
>;

/**
 * @brief Configuration manager with thread-safe access
 * 
 * Provides centralized configuration storage with:
 * - Type-safe value storage
 * - Default value support
 * - Thread-safe read/write
 * - Validation hooks
 */
class Config {
public:
    /**
     * @brief Get singleton instance
     */
    static Config& Instance();
    
    /**
     * @brief Load configuration from file
     * @param path Configuration file path
     * @return true if loaded successfully
     */
    bool LoadFromFile(const std::string& path);
    
    /**
     * @brief Save configuration to file
     * @param path Configuration file path
     * @return true if saved successfully
     */
    bool SaveToFile(const std::string& path) const;
    
    /**
     * @brief Get configuration value
     * @param key Configuration key
     * @param defaultValue Default value if not found
     * @return Configuration value or default
     */
    template<typename T>
    T Get(const std::string& key, const T& defaultValue = T{}) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_values.find(key);
        if (it != m_values.end()) {
            if (std::holds_alternative<T>(it->second)) {
                return std::get<T>(it->second);
            }
        }
        return defaultValue;
    }
    
    /**
     * @brief Set configuration value
     * @param key Configuration key
     * @param value Value to set
     */
    template<typename T>
    void Set(const std::string& key, const T& value) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_values[key] = value;
    }
    
    /**
     * @brief Check if key exists
     * @param key Configuration key
     * @return true if key exists
     */
    bool Has(const std::string& key) const;
    
    /**
     * @brief Remove configuration key
     * @param key Configuration key
     */
    void Remove(const std::string& key);
    
    /**
     * @brief Clear all configuration
     */
    void Clear();
    
    /**
     * @brief Get all configuration keys
     * @return Vector of keys
     */
    std::vector<std::string> GetKeys() const;

private:
    Config() = default;
    ~Config() = default;
    
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;
    
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, ConfigValue> m_values;
};

} // namespace Agentic
} // namespace RawrXD
