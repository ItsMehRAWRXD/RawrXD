// RawrXD Example Backend Plugin
// Phase AI: Plugin System - Example Implementation

#include "../../src/plugin/plugin_manager.hpp"
#include <iostream>
#include <chrono>

namespace rawrxd {
namespace plugin {

// Example backend plugin that adds custom inference capabilities
class ExampleBackendPlugin : public IPlugin {
public:
    ExampleBackendPlugin() : state_(PluginState::UNLOADED) {}
    
    ~ExampleBackendPlugin() override = default;
    
    bool initialize(const std::unordered_map<std::string, std::string>& config) override {
        std::cout << "ExampleBackendPlugin: Initializing..." << std::endl;
        
        // Read configuration
        auto it = config.find("backend_type");
        if (it != config.end()) {
            backend_type_ = it->second;
        }
        
        it = config.find("device_id");
        if (it != config.end()) {
            device_id_ = std::stoi(it->second);
        }
        
        state_ = PluginState::INITIALIZED;
        return true;
    }
    
    void shutdown() override {
        std::cout << "ExampleBackendPlugin: Shutting down..." << std::endl;
        state_ = PluginState::UNLOADED;
    }
    
    PluginInfo getInfo() const override {
        PluginInfo info;
        info.id = "example_backend";
        info.name = "Example Backend Plugin";
        info.version = "1.0.0";
        info.description = "Example custom inference backend plugin";
        info.author = "RawrXD Team";
        info.license = "MIT";
        info.type = PluginType::BACKEND;
        info.api_version = PLUGIN_API_VERSION;
        info.dependencies = {};  // No dependencies
        return info;
    }
    
    PluginState getState() const override {
        return state_;
    }
    
    void setState(PluginState state) override {
        state_ = state;
    }
    
    bool isHealthy() const override {
        return state_ == PluginState::RUNNING || state_ == PluginState::INITIALIZED;
    }
    
    void onConfigChanged(const std::string& key, const std::string& value) override {
        std::cout << "ExampleBackendPlugin: Config changed - " << key << " = " << value << std::endl;
        
        if (key == "device_id") {
            device_id_ = std::stoi(value);
        } else if (key == "backend_type") {
            backend_type_ = value;
        }
    }
    
    // Custom backend methods
    bool isAvailable() const {
        return state_ == PluginState::RUNNING;
    }
    
    std::string getBackendType() const {
        return backend_type_;
    }
    
    int getDeviceId() const {
        return device_id_;
    }
    
private:
    PluginState state_;
    std::string backend_type_ = "cpu";
    int device_id_ = 0;
};

// Export plugin functions
RAWRXD_REGISTER_PLUGIN(ExampleBackendPlugin);

} // namespace plugin
} // namespace rawrxd
