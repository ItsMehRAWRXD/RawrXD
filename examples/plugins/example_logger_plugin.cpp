// RawrXD Example Logger Plugin
// Phase AI: Plugin System - Example Implementation

#include "../../src/plugin/plugin_manager.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>

namespace rawrxd {
namespace plugin {

// Example logger plugin that writes logs to a custom file
class ExampleLoggerPlugin : public IPlugin {
public:
    ExampleLoggerPlugin() : state_(PluginState::UNLOADED) {}
    
    ~ExampleLoggerPlugin() override {
        if (log_file_.is_open()) {
            log_file_.close();
        }
    }
    
    bool initialize(const std::unordered_map<std::string, std::string>& config) override {
        std::cout << "ExampleLoggerPlugin: Initializing..." << std::endl;
        
        // Get log file path from config
        auto it = config.find("log_file");
        if (it != config.end()) {
            log_file_path_ = it->second;
        } else {
            log_file_path_ = "logs/plugin_example.log";
        }
        
        // Get log level from config
        it = config.find("log_level");
        if (it != config.end()) {
            log_level_ = it->second;
        }
        
        // Open log file
        log_file_.open(log_file_path_, std::ios::app);
        if (!log_file_.is_open()) {
            std::cerr << "ExampleLoggerPlugin: Failed to open log file: " << log_file_path_ << std::endl;
            return false;
        }
        
        log("INFO", "Logger plugin initialized");
        state_ = PluginState::INITIALIZED;
        return true;
    }
    
    void shutdown() override {
        log("INFO", "Logger plugin shutting down");
        
        if (log_file_.is_open()) {
            log_file_.close();
        }
        
        state_ = PluginState::UNLOADED;
    }
    
    PluginInfo getInfo() const override {
        PluginInfo info;
        info.id = "example_logger";
        info.name = "Example Logger Plugin";
        info.version = "1.0.0";
        info.description = "Example custom logger plugin";
        info.author = "RawrXD Team";
        info.license = "MIT";
        info.type = PluginType::LOGGER;
        info.api_version = PLUGIN_API_VERSION;
        info.dependencies = {};
        return info;
    }
    
    PluginState getState() const override {
        return state_;
    }
    
    void setState(PluginState state) override {
        state_ = state;
    }
    
    bool isHealthy() const override {
        return log_file_.is_open();
    }
    
    void onConfigChanged(const std::string& key, const std::string& value) override {
        if (key == "log_level") {
            log_level_ = value;
            log("INFO", "Log level changed to: " + value);
        }
    }
    
    // Custom logger methods
    void log(const std::string& level, const std::string& message) {
        if (!log_file_.is_open()) return;
        
        // Check if we should log this level
        if (!shouldLog(level)) return;
        
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        log_file_ << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "] ";
        log_file_ << "[" << level << "] " << message << std::endl;
        log_file_.flush();
    }
    
    void logInference(const std::string& model, int tokens_in, int tokens_out, double latency_ms) {
        std::stringstream ss;
        ss << "Inference: model=" << model;
        ss << ", tokens_in=" << tokens_in;
        ss << ", tokens_out=" << tokens_out;
        ss << ", latency_ms=" << latency_ms;
        log("INFO", ss.str());
    }
    
private:
    PluginState state_;
    std::string log_file_path_;
    std::string log_level_ = "INFO";
    std::ofstream log_file_;
    
    bool shouldLog(const std::string& level) const {
        static const std::unordered_map<std::string, int> levels = {
            {"DEBUG", 0},
            {"INFO", 1},
            {"WARNING", 2},
            {"ERROR", 3},
            {"FATAL", 4}
        };
        
        auto it_level = levels.find(level);
        auto it_config = levels.find(log_level_);
        
        if (it_level == levels.end() || it_config == levels.end()) {
            return true;
        }
        
        return it_level->second >= it_config->second;
    }
};

// Export plugin functions
RAWRXD_REGISTER_PLUGIN(ExampleLoggerPlugin);

} // namespace plugin
} // namespace rawrxd
