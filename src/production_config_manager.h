#pragma once

#include <string>
#include <map>
#include <mutex>

namespace RawrXD {

class ProductionConfigManager {
public:
    static ProductionConfigManager& instance() {
        static ProductionConfigManager manager;
        return manager;
    }

    bool loadConfig() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_loaded = true;
        return true;
    }

    const std::string& getEnvironment() const {
        return m_environment;
    }

    bool isFeatureEnabled(const std::string& feature) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_features.find(feature);
        return it != m_features.end() && it->second;
    }

private:
    ProductionConfigManager() : m_loaded(false), m_environment("development") {}

    bool m_loaded;
    std::string m_environment;
    std::map<std::string, bool> m_features;
    mutable std::mutex m_mutex;
};

} // namespace RawrXD