#include "VAL064_TelemetryAdapter.hpp"
#include <fstream>
#include <sstream>
#include <chrono>
#include <iostream>

namespace val064 {

// Simple JSON value parser helper
class SimpleJsonParser {
public:
    static double parseDouble(const std::string& json, const std::string& key) {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0.0;
        pos = json.find(":", pos);
        if (pos == std::string::npos) return 0.0;
        pos++;
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r')) pos++;
        return std::stod(json.substr(pos));
    }
    
    static int parseInt(const std::string& json, const std::string& key) {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0;
        pos = json.find(":", pos);
        if (pos == std::string::npos) return 0;
        pos++;
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r')) pos++;
        return std::stoi(json.substr(pos));
    }
};

// FileTelemetryProvider implementation
FileTelemetryProvider::FileTelemetryProvider(const std::string& telemetry_file)
    : telemetry_file_(telemetry_file) {}

LiveMetrics FileTelemetryProvider::CollectMetrics() {
    // Check if we need to re-read (cache for 100ms)
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    if (cached_metrics_ && (now - last_read_time_) < 100'000'000) {
        return *cached_metrics_;
    }
    
    LiveMetrics metrics;
    metrics.timestamp_ns = static_cast<uint64_t>(now);
    
    std::ifstream file(telemetry_file_);
    if (!file.is_open()) {
        metrics.valid = false;
        metrics.error_message = "Cannot open telemetry file: " + telemetry_file_;
        return metrics;
    }
    
    try {
        std::string json_str((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
        
        // Extract metrics from JSON using simple parser
        metrics.prefill_tps = SimpleJsonParser::parseDouble(json_str, "prefill_tps");
        metrics.decode_tps = SimpleJsonParser::parseDouble(json_str, "decode_tps");
        metrics.first_token_ms = SimpleJsonParser::parseDouble(json_str, "first_token_ms");
        metrics.peak_vram_mb = SimpleJsonParser::parseDouble(json_str, "peak_vram_mb");
        metrics.peak_ram_mb = SimpleJsonParser::parseDouble(json_str, "peak_ram_mb");
        metrics.prompt_tokens = SimpleJsonParser::parseInt(json_str, "prompt_tokens");
        metrics.generated_tokens = SimpleJsonParser::parseInt(json_str, "generated_tokens");
        
        metrics.valid = true;
        cached_metrics_ = metrics;
        last_read_time_ = now;
    } catch (const std::exception& e) {
        metrics.valid = false;
        metrics.error_message = std::string("JSON parse error: ") + e.what();
    }
    
    return metrics;
}

bool FileTelemetryProvider::IsAvailable() const {
    std::ifstream file(telemetry_file_);
    return file.good();
}

// SharedMemoryTelemetryProvider implementation
// Note: Windows-specific code disabled for portability
// To enable, define VAL064_ENABLE_SHM before including this file

SharedMemoryTelemetryProvider::SharedMemoryTelemetryProvider(const std::string& shm_name)
    : shm_name_(shm_name), initialized_(false), shm_handle_(nullptr) {
    // Shared memory disabled in this build
}

LiveMetrics SharedMemoryTelemetryProvider::CollectMetrics() {
    LiveMetrics m;
    m.valid = false;
    m.error_message = "Shared memory not supported in this build";
    return m;
}

bool SharedMemoryTelemetryProvider::IsAvailable() const { 
    return false; 
}

// MockTelemetryProvider implementation
LiveMetrics MockTelemetryProvider::CollectMetrics() {
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    auto metrics = mock_metrics_;
    metrics.timestamp_ns = static_cast<uint64_t>(now);
    metrics.valid = true;
    return metrics;
}

// Factory implementation
std::unique_ptr<ITelemetryProvider> TelemetryProviderFactory::CreateProvider(const std::string& backend) {
    if (backend == "file") {
        return std::make_unique<FileTelemetryProvider>("evidence/performance/telemetry_live.json");
    } else if (backend == "shared_memory" || backend == "shm") {
        return std::make_unique<SharedMemoryTelemetryProvider>("RawrXD_Telemetry");
    } else if (backend == "mock") {
        return std::make_unique<MockTelemetryProvider>();
    }
    return nullptr;
}

std::unique_ptr<ITelemetryProvider> TelemetryProviderFactory::AutoDetect() {
    // Try shared memory first (fastest, most real-time)
    auto shm = std::make_unique<SharedMemoryTelemetryProvider>("RawrXD_Telemetry");
    if (shm->IsAvailable()) {
        std::cout << "[VAL-064] Auto-detected shared memory telemetry provider" << std::endl;
        return shm;
    }
    
    // Fall back to file-based
    auto file = std::make_unique<FileTelemetryProvider>("evidence/performance/telemetry_live.json");
    if (file->IsAvailable()) {
        std::cout << "[VAL-064] Auto-detected file telemetry provider" << std::endl;
        return file;
    }
    
    // Use mock as last resort
    std::cout << "[VAL-064] Using mock telemetry provider (no live data available)" << std::endl;
    return std::make_unique<MockTelemetryProvider>();
}

std::vector<std::string> TelemetryProviderFactory::ListAvailableProviders() {
    std::vector<std::string> providers;
    
    // Check shared memory
    auto shm = std::make_unique<SharedMemoryTelemetryProvider>("RawrXD_Telemetry");
    if (shm->IsAvailable()) {
        providers.push_back("shared_memory");
    }
    
    // Check file
    auto file = std::make_unique<FileTelemetryProvider>("evidence/performance/telemetry_live.json");
    if (file->IsAvailable()) {
        providers.push_back("file");
    }
    
    // Mock is always available
    providers.push_back("mock");
    
    return providers;
}

} // namespace val064
