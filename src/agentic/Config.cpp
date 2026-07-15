/**
 * @file Config.cpp
 * @brief Configuration management implementation
 * 
 * @copyright RawrXD 2026
 */

#include "Config.h"
#include <fstream>
#include <sstream>
#include <vector>

namespace RawrXD {
namespace Agentic {

Config& Config::Instance() {
    static Config instance;
    return instance;
}

bool Config::LoadFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::string line;
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        size_t pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }
        
        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);
        
        // Trim whitespace
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);
        
        // Try to parse as different types
        if (value == "true" || value == "True" || value == "TRUE") {
            m_values[key] = true;
        } else if (value == "false" || value == "False" || value == "FALSE") {
            m_values[key] = false;
        } else {
            // Try int
            char* end;
            long intVal = std::strtol(value.c_str(), &end, 10);
            if (*end == '\0') {
                m_values[key] = static_cast<int>(intVal);
            } else {
                // Try float
                char* endf;
                float floatVal = std::strtof(value.c_str(), &endf);
                if (*endf == '\0') {
                    m_values[key] = floatVal;
                } else {
                    // Store as string
                    m_values[key] = value;
                }
            }
        }
    }
    
    return true;
}

bool Config::SaveToFile(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    file << "# RawrXD Configuration File\n";
    file << "# Auto-generated\n\n";
    
    for (const auto& [key, value] : m_values) {
        file << key << "=";
        
        std::visit([&file](const auto& v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, bool>) {
                file << (v ? "true" : "false");
            } else if constexpr (std::is_same_v<T, int>) {
                file << v;
            } else if constexpr (std::is_same_v<T, float>) {
                file << v;
            } else if constexpr (std::is_same_v<T, std::string>) {
                file << v;
            }
        }, value);
        
        file << "\n";
    }
    
    return true;
}

bool Config::Has(const std::string& key) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_values.find(key) != m_values.end();
}

void Config::Remove(const std::string& key) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_values.erase(key);
}

void Config::Clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_values.clear();
}

std::vector<std::string> Config::GetKeys() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> keys;
    keys.reserve(m_values.size());
    
    for (const auto& [key, _] : m_values) {
        keys.push_back(key);
    }
    
    return keys;
}

} // namespace Agentic
} // namespace RawrXD
