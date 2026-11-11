// =============================================================================
// sovereign_config.cpp
// Configuration management implementation
// =============================================================================

#include "sovereign_config.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>
#include <fstream>
#include <sstream>

namespace Sovereign {

// =============================================================================
// JSON Helper (minimal implementation)
// =============================================================================
class JsonHelper {
public:
    static std::string GetString(const std::string& json, const std::string& key, const std::string& default_val) {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return default_val;
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return default_val;
        
        pos = json.find_first_of("\"0123456789-.tf", pos + 1);
        if (pos == std::string::npos) return default_val;
        
        if (json[pos] == '"') {
            size_t end = json.find("\"", pos + 1);
            if (end == std::string::npos) return default_val;
            return json.substr(pos + 1, end - pos - 1);
        }
        
        size_t end = json.find_first_of(",}\n", pos);
        return json.substr(pos, end - pos);
    }
    
    static int GetInt(const std::string& json, const std::string& key, int default_val) {
        std::string val = GetString(json, key, "");
        if (val.empty()) return default_val;
        return std::atoi(val.c_str());
    }
    
    static float GetFloat(const std::string& json, const std::string& key, float default_val) {
        std::string val = GetString(json, key, "");
        if (val.empty()) return default_val;
        return std::atof(val.c_str());
    }
    
    static bool GetBool(const std::string& json, const std::string& key, bool default_val) {
        std::string val = GetString(json, key, "");
        if (val == "true") return true;
        if (val == "false") return false;
        return default_val;
    }
};

// =============================================================================
// SovereignConfig Implementation
// =============================================================================
SovereignConfig SovereignConfig::FromFile(const std::string& path) {
    SovereignConfig config;
    
    std::ifstream file(path);
    if (!file.is_open()) {
        printf("[Config] Warning: Could not open %s, using defaults\n", path.c_str());
        return config;
    }
    
    std::string json((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
    file.close();
    
    return FromJson(json);
}

SovereignConfig SovereignConfig::FromJson(const std::string& json) {
    SovereignConfig config;
    
    config.model_path = JsonHelper::GetString(json, "model_path", config.model_path);
    config.model_format = JsonHelper::GetString(json, "model_format", config.model_format);
    
    config.max_tokens = JsonHelper::GetInt(json, "max_tokens", config.max_tokens);
    config.temperature = JsonHelper::GetFloat(json, "temperature", config.temperature);
    config.top_p = JsonHelper::GetFloat(json, "top_p", config.top_p);
    config.top_k = JsonHelper::GetInt(json, "top_k", config.top_k);
    config.seed = JsonHelper::GetInt(json, "seed", config.seed);
    
    config.num_threads = JsonHelper::GetInt(json, "num_threads", config.num_threads);
    config.batch_size = JsonHelper::GetInt(json, "batch_size", config.batch_size);
    config.use_mmap = JsonHelper::GetBool(json, "use_mmap", config.use_mmap);
    config.lock_memory = JsonHelper::GetBool(json, "lock_memory", config.lock_memory);
    
    config.arena_size_mb = JsonHelper::GetInt(json, "arena_size_mb", config.arena_size_mb);
    config.kv_cache_size_mb = JsonHelper::GetInt(json, "kv_cache_size_mb", config.kv_cache_size_mb);
    
    config.use_avx512 = JsonHelper::GetBool(json, "use_avx512", config.use_avx512);
    config.use_avx2 = JsonHelper::GetBool(json, "use_avx2", config.use_avx2);
    config.use_gpu = JsonHelper::GetBool(json, "use_gpu", config.use_gpu);
    
    config.log_level = JsonHelper::GetString(json, "log_level", config.log_level);
    config.log_file = JsonHelper::GetString(json, "log_file", config.log_file);
    config.log_colors = JsonHelper::GetBool(json, "log_colors", config.log_colors);
    
    config.server_port = JsonHelper::GetInt(json, "server_port", config.server_port);
    config.server_host = JsonHelper::GetString(json, "server_host", config.server_host);
    
    return config;
}

bool SovereignConfig::SaveToFile(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return false;
    
    file << "{\n";
    file << "  \"model_path\": \"" << model_path << "\",\n";
    file << "  \"model_format\": \"" << model_format << "\",\n";
    file << "  \"max_tokens\": " << max_tokens << ",\n";
    file << "  \"temperature\": " << temperature << ",\n";
    file << "  \"top_p\": " << top_p << ",\n";
    file << "  \"top_k\": " << top_k << ",\n";
    file << "  \"seed\": " << seed << ",\n";
    file << "  \"num_threads\": " << num_threads << ",\n";
    file << "  \"batch_size\": " << batch_size << ",\n";
    file << "  \"use_mmap\": " << (use_mmap ? "true" : "false") << ",\n";
    file << "  \"lock_memory\": " << (lock_memory ? "true" : "false") << ",\n";
    file << "  \"arena_size_mb\": " << arena_size_mb << ",\n";
    file << "  \"kv_cache_size_mb\": " << kv_cache_size_mb << ",\n";
    file << "  \"use_avx512\": " << (use_avx512 ? "true" : "false") << ",\n";
    file << "  \"use_avx2\": " << (use_avx2 ? "true" : "false") << ",\n";
    file << "  \"use_gpu\": " << (use_gpu ? "true" : "false") << ",\n";
    file << "  \"log_level\": \"" << log_level << "\",\n";
    file << "  \"log_file\": \"" << log_file << "\",\n";
    file << "  \"log_colors\": " << (log_colors ? "true" : "false") << ",\n";
    file << "  \"server_port\": " << server_port << ",\n";
    file << "  \"server_host\": \"" << server_host << "\"\n";
    file << "}\n";
    
    file.close();
    return true;
}

bool SovereignConfig::Validate(std::string& error) const {
    if (model_path.empty()) {
        error = "model_path is required";
        return false;
    }
    
    if (max_tokens == 0 || max_tokens > 32768) {
        error = "max_tokens must be between 1 and 32768";
        return false;
    }
    
    if (temperature < 0.0f || temperature > 2.0f) {
        error = "temperature must be between 0.0 and 2.0";
        return false;
    }
    
    if (arena_size_mb < 256) {
        error = "arena_size_mb must be at least 256";
        return false;
    }
    
    return true;
}

void SovereignConfig::Print() const {
    printf("=================================================================\n");
    printf("Sovereign Engine Configuration\n");
    printf("=================================================================\n");
    printf("Model:\n");
    printf("  Path: %s\n", model_path.c_str());
    printf("  Format: %s\n", model_format.c_str());
    printf("\nInference:\n");
    printf("  Max Tokens: %u\n", max_tokens);
    printf("  Temperature: %.2f\n", temperature);
    printf("  Top-P: %.2f\n", top_p);
    printf("  Top-K: %u\n", top_k);
    printf("  Seed: %u\n", seed);
    printf("\nPerformance:\n");
    printf("  Threads: %u (0=auto)\n", num_threads);
    printf("  Batch Size: %u\n", batch_size);
    printf("  Use MMAP: %s\n", use_mmap ? "yes" : "no");
    printf("  Lock Memory: %s\n", lock_memory ? "yes" : "no");
    printf("\nMemory:\n");
    printf("  Arena: %llu MB\n", arena_size_mb);
    printf("  KV Cache: %llu MB\n", kv_cache_size_mb);
    printf("\nHardware:\n");
    printf("  AVX-512: %s\n", use_avx512 ? "enabled" : "disabled");
    printf("  AVX2: %s\n", use_avx2 ? "enabled" : "disabled");
    printf("  GPU: %s\n", use_gpu ? "enabled" : "disabled");
    printf("\nLogging:\n");
    printf("  Level: %s\n", log_level.c_str());
    printf("  File: %s\n", log_file.empty() ? "stdout" : log_file.c_str());
    printf("  Colors: %s\n", log_colors ? "yes" : "no");
    printf("\nServer:\n");
    printf("  Host: %s\n", server_host.c_str());
    printf("  Port: %u\n", server_port);
    printf("=================================================================\n");
}

std::string SovereignConfig::GetDefaultConfigPath() {
    char path[MAX_PATH];
    if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0) {
        return "sovereign_config.json";
    }
    
    // Get directory of executable
    char* last_slash = strrchr(path, '\\');
    if (last_slash) {
        *(last_slash + 1) = '\0';
        return std::string(path) + "sovereign_config.json";
    }
    
    return "sovereign_config.json";
}

// =============================================================================
// SystemInfo Implementation
// =============================================================================
SystemInfo SystemInfo::Detect() {
    SystemInfo info;
    
    // CPU info
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    info.cpu_cores = sys_info.dwNumberOfProcessors;
    info.cpu_threads = sys_info.dwNumberOfProcessors;  // Simplified
    
    // Memory info
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    GlobalMemoryStatusEx(&mem_status);
    info.total_ram_mb = mem_status.ullTotalPhys / (1024 * 1024);
    info.available_ram_mb = mem_status.ullAvailPhys / (1024 * 1024);
    
    // CPU features (simplified - would need CPUID in production)
    info.has_avx2 = true;  // Assume AVX2 on modern systems
    info.has_fma = true;
    info.has_avx512 = false;  // Conservative default
    
    return info;
}

void SystemInfo::Print() const {
    printf("=================================================================\n");
    printf("System Information\n");
    printf("=================================================================\n");
    printf("CPU:\n");
    printf("  Cores: %u\n", cpu_cores);
    printf("  Threads: %u\n", cpu_threads);
    printf("  AVX-512: %s\n", has_avx512 ? "yes" : "no");
    printf("  AVX2: %s\n", has_avx2 ? "yes" : "no");
    printf("  FMA: %s\n", has_fma ? "yes" : "no");
    printf("\nMemory:\n");
    printf("  Total: %llu MB\n", total_ram_mb);
    printf("  Available: %llu MB\n", available_ram_mb);
    printf("=================================================================\n");
}

// =============================================================================
// Status Codes
// =============================================================================
const char* SovereignStatusToString(SovereignStatus status) {
    switch (status) {
        case SovereignStatus::OK: return "OK";
        case SovereignStatus::ERR_INVALID_CONFIG: return "Invalid configuration";
        case SovereignStatus::ERR_OUT_OF_MEMORY: return "Out of memory";
        case SovereignStatus::ERR_MODEL_LOAD: return "Failed to load model";
        case SovereignStatus::ERR_MODEL_FORMAT: return "Unsupported model format";
        case SovereignStatus::ERR_HARDWARE_UNSUPPORTED: return "Hardware not supported";
        case SovereignStatus::ERR_FILE_NOT_FOUND: return "File not found";
        case SovereignStatus::ERR_PERMISSION_DENIED: return "Permission denied";
        case SovereignStatus::ERR_RUNTIME: return "Runtime error";
        case SovereignStatus::ERR_NOT_INITIALIZED: return "Not initialized";
        case SovereignStatus::ERR_ALREADY_RUNNING: return "Already running";
        case SovereignStatus::ERR_INVALID_ARGUMENT: return "Invalid argument";
        case SovereignStatus::ERR_QUANTIZATION: return "Quantization error";
        case SovereignStatus::ERR_TOKENIZER: return "Tokenizer error";
        default: return "Unknown error";
    }
}

} // namespace Sovereign
