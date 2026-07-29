#include "FeatureFlags.hpp"
#include <fstream>
#include <sstream>

namespace RawrXD::Agentic::Wiring {

FeatureFlags& FeatureFlags::instance() {
    static FeatureFlags inst;
    return inst;
}

void FeatureFlags::set(const std::string& name, bool value) {
<<<<<<< HEAD
    bool oldValue = false;
    bool changed = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        oldValue = m_boolFlags[name].load();
        m_boolFlags[name].store(value);
        changed = (oldValue != value);
    }

    if (changed) {
        notifyCallbacks(name, oldValue, value);
    }
=======
    std::lock_guard<std::mutex> lock(m_mutex);
    bool oldValue = m_boolFlags[name].load();
    m_boolFlags[name].store(value);
    notifyCallbacks(name, oldValue, value);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

bool FeatureFlags::get(const std::string& name, bool defaultValue) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_boolFlags.find(name);
    return (it != m_boolFlags.end()) ? it->second.load() : defaultValue;
}

std::string FeatureFlags::getString(const std::string& name, const std::string& defaultValue) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_stringFlags.find(name);
    return (it != m_stringFlags.end()) ? it->second : defaultValue;
}

void FeatureFlags::setString(const std::string& name, const std::string& value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_stringFlags[name] = value;
}

int FeatureFlags::getInt(const std::string& name, int defaultValue) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_intFlags.find(name);
    return (it != m_intFlags.end()) ? it->second.load() : defaultValue;
}

void FeatureFlags::setInt(const std::string& name, int value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_intFlags[name].store(value);
}

float FeatureFlags::getFloat(const std::string& name, float defaultValue) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_floatFlags.find(name);
    return (it != m_floatFlags.end()) ? it->second.load() : defaultValue;
}

void FeatureFlags::setFloat(const std::string& name, float value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_floatFlags[name].store(value);
}

void FeatureFlags::onFlagChanged(const std::string& name, FlagCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_callbacks[name].push_back(callback);
}

<<<<<<< HEAD
bool FeatureFlags::loadFromFile(const std::string& filePath) {
    std::ifstream ifs(filePath);
    if (!ifs.is_open()) {
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(ifs)),
                        std::istreambuf_iterator<char>());

    std::lock_guard<std::mutex> lock(m_mutex);

    // Parse simple JSON format: {"key": value, ...}
    // Supports bool (true/false), int, float, and string values
    size_t pos = 0;
    while ((pos = content.find('"', pos)) != std::string::npos) {
        size_t keyStart = pos + 1;
        size_t keyEnd = content.find('"', keyStart);
        if (keyEnd == std::string::npos) break;

        std::string key = content.substr(keyStart, keyEnd - keyStart);
        pos = content.find(':', keyEnd);
        if (pos == std::string::npos) break;
        pos++;

        // Skip whitespace
        while (pos < content.size() && (content[pos] == ' ' || content[pos] == '\t')) pos++;

        if (pos >= content.size()) break;

        if (content[pos] == '"') {
            // String value
            size_t valStart = pos + 1;
            size_t valEnd = content.find('"', valStart);
            if (valEnd == std::string::npos) break;
            m_stringFlags[key] = content.substr(valStart, valEnd - valStart);
            pos = valEnd + 1;
        } else if (content.substr(pos, 4) == "true") {
            m_boolFlags[key].store(true);
            pos += 4;
        } else if (content.substr(pos, 5) == "false") {
            m_boolFlags[key].store(false);
            pos += 5;
        } else {
            // Numeric value — extract until delimiter
            size_t numStart = pos;
            while (pos < content.size() && content[pos] != ',' &&
                   content[pos] != '}' && content[pos] != '\n') {
                pos++;
            }
            std::string numStr = content.substr(numStart, pos - numStart);
            // Trim whitespace
            while (!numStr.empty() && (numStr.back() == ' ' || numStr.back() == '\r')) {
                numStr.pop_back();
            }
            try {
                if (numStr.find('.') != std::string::npos) {
                    m_floatFlags[key].store(std::stof(numStr));
                } else {
                    m_intFlags[key].store(std::stoi(numStr));
                }
            } catch (...) {
                // Ignore malformed numeric field and continue parsing.
            }
        }
    }

    return true;
}

bool FeatureFlags::saveToFile(const std::string& filePath) const {
    std::ofstream ofs(filePath, std::ios::trunc);
    if (!ofs.is_open()) {
        return false;
    }

    ofs << toJson();
    return ofs.good();
=======
#include <nlohmann/json.hpp>

// ...existing code...


bool FeatureFlags::loadFromFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) return false;
    
    try {
        nlohmann::json j;
        file >> j;
        
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Parse simple key-value pairs
        if (j.contains("bools")) {
             for (auto& element : j["bools"].items()) {
                 m_boolFlags[element.key()].store(element.value().get<bool>());
             }
        }
        if (j.contains("strings")) {
             for (auto& element : j["strings"].items()) {
                 m_stringFlags[element.key()] = element.value().get<std::string>();
             }
        }
        return true;
    } catch (...) {
        return false;
    }
}

bool FeatureFlags::saveToFile(const std::string& filePath) const {
    try {
        nlohmann::json j;
        j["bools"] = nlohmann::json::object();
        j["strings"] = nlohmann::json::object();

        {
             std::lock_guard<std::mutex> lock(m_mutex);
             for (const auto& pair : m_boolFlags) {
                 j["bools"][pair.first] = pair.second.load();
             }
             for (const auto& pair : m_stringFlags) {
                 j["strings"][pair.first] = pair.second;
             }
        }
        
        std::ofstream file(filePath);
        if (!file.is_open()) return false;
        
        file << j.dump(4);
        return true;
    } catch (...) {
        return false;
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

std::string FeatureFlags::toJson() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ostringstream json;
    json << "{\n";
<<<<<<< HEAD

    bool first = true;

    // Serialize bool flags
    for (const auto& [name, value] : m_boolFlags) {
        if (!first) json << ",\n";
        first = false;
        json << "  \"" << name << "\": " << (value.load() ? "true" : "false");
    }

    // Serialize int flags
    for (const auto& [name, value] : m_intFlags) {
        if (!first) json << ",\n";
        first = false;
        json << "  \"" << name << "\": " << value.load();
    }

    // Serialize float flags
    for (const auto& [name, value] : m_floatFlags) {
        if (!first) json << ",\n";
        first = false;
        json << "  \"" << name << "\": " << value.load();
    }

    // Serialize string flags
    for (const auto& [name, value] : m_stringFlags) {
        if (!first) json << ",\n";
        first = false;
        json << "  \"" << name << "\": \"" << value << "\"";
    }

    json << "\n}\n";
=======
    json << "  \"boolFlags\": {\n";
    bool first = true;
    for (const auto& [key, val] : m_boolFlags) {
        if (!first) json << ",\n";
        json << "    \"" << key << "\": " << (val ? "true" : "false");
        first = false;
    }
    json << "\n  },\n";
    
    json << "  \"intFlags\": {\n";
    first = true;
    for (const auto& [key, val] : m_intFlags) {
        if (!first) json << ",\n";
        json << "    \"" << key << "\": " << val;
        first = false;
    }
    json << "\n  },\n";
    
    json << "  \"floatFlags\": {\n";
    first = true;
    for (const auto& [key, val] : m_floatFlags) {
        if (!first) json << ",\n";
        json << "    \"" << key << "\": " << val;
        first = false;
    }
    json << "\n  },\n";
    
    json << "  \"stringFlags\": {\n";
    first = true;
    for (const auto& [key, val] : m_stringFlags) {
        if (!first) json << ",\n";
        json << "    \"" << key << "\": \"" << val << "\"";
        first = false;
    }
    json << "\n  }\n";
    
    json << "}\n";
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return json.str();
}

void FeatureFlags::clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_boolFlags.clear();
    m_intFlags.clear();
    m_floatFlags.clear();
    m_stringFlags.clear();
    m_callbacks.clear();
}

std::vector<std::string> FeatureFlags::listFlags() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> flags;
<<<<<<< HEAD
    flags.reserve(m_boolFlags.size() + m_intFlags.size() + m_floatFlags.size() + m_stringFlags.size());
    for (const auto& [name, _] : m_boolFlags) {
        flags.push_back(name);
    }
    for (const auto& [name, _] : m_intFlags) {
        flags.push_back(name);
    }
    for (const auto& [name, _] : m_floatFlags) {
        flags.push_back(name);
    }
    for (const auto& [name, _] : m_stringFlags) {
        flags.push_back(name);
    }
    std::sort(flags.begin(), flags.end());
    flags.erase(std::unique(flags.begin(), flags.end()), flags.end());
=======
    for (const auto& [name, _] : m_boolFlags) {
        flags.push_back(name);
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return flags;
}

void FeatureFlags::notifyCallbacks(const std::string& name, bool oldValue, bool newValue) {
<<<<<<< HEAD
    std::vector<FlagCallback> callbacks;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_callbacks.find(name);
        if (it != m_callbacks.end()) {
            callbacks = it->second;
        }
    }

    for (const auto& callback : callbacks) {
        callback(name, oldValue, newValue);
    }
=======
    auto it = m_callbacks.find(name);
    if (it != m_callbacks.end()) {
        for (const auto& callback : it->second) {
            callback(name, oldValue, newValue);
        }
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

} // namespace RawrXD::Agentic::Wiring
