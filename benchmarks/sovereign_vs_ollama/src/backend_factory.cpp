// Backend Factory and Configuration Management Implementation
// Copyright (c) 2026 RawrXD Team

#include "backend_factory.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace rawrxd::benchmark {

// ============================================================================
// Backend Factory Implementation
// ============================================================================

std::unique_ptr<BackendAdapter> BackendFactory::Create(BackendType type) {
    switch (type) {
        case BackendType::SOVEREIGN:
            return CreateSovereignBackendAdapter();
        case BackendType::OLLAMA:
            return CreateOllamaBackendAdapter();
        default:
            return nullptr;
    }
}

std::unique_ptr<BackendAdapter> BackendFactory::Create(const std::string& name) {
    std::string lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    if (lower_name == "sovereign" || lower_name == "rawrxd") {
        return Create(BackendType::SOVEREIGN);
    } else if (lower_name == "ollama") {
        return Create(BackendType::OLLAMA);
    }
    
    return nullptr;
}

std::vector<BackendType> BackendFactory::GetAvailableBackends() {
    return {
        BackendType::SOVEREIGN,
        BackendType::OLLAMA
    };
}

bool BackendFactory::IsAvailable(BackendType type) {
    switch (type) {
        case BackendType::SOVEREIGN:
        case BackendType::OLLAMA:
            return true;
        default:
            return false;
    }
}

const char* BackendFactory::GetDisplayName(BackendType type) {
    switch (type) {
        case BackendType::SOVEREIGN:
            return "RawrXD Sovereign";
        case BackendType::OLLAMA:
            return "Ollama";
        default:
            return "Unknown";
    }
}

const char* BackendFactory::GetDescription(BackendType type) {
    switch (type) {
        case BackendType::SOVEREIGN:
            return "RawrXD Sovereign Runtime with native agentic capabilities";
        case BackendType::OLLAMA:
            return "Ollama HTTP API for local LLM inference";
        default:
            return "Unknown backend";
    }
}

// ============================================================================
// Configuration Manager Implementation
// ============================================================================

BenchmarkConfig ConfigurationManager::LoadFromFile(const std::string& path) {
    BenchmarkConfig config;
    
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Warning: Could not open config file: " << path << std::endl;
        return config;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;
        
        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos) continue;
        
        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);
        
        // Trim whitespace
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);
        
        // Parse key-value pairs
        if (key == "backend") {
            if (value == "sovereign") config.backend = BackendType::SOVEREIGN;
            else if (value == "ollama") config.backend = BackendType::OLLAMA;
        } else if (key == "model_name") {
            config.model_name = value;
        } else if (key == "model_path") {
            config.model_path = value;
        } else if (key == "swarm_size") {
            config.swarm_size = std::stoi(value);
        } else if (key == "context_length") {
            config.context_length = std::stoi(value);
        } else if (key == "max_tokens") {
            config.max_tokens = std::stoi(value);
        } else if (key == "temperature") {
            config.temperature = std::stof(value);
        } else if (key == "gpu_backend") {
            config.gpu_backend = value;
        } else if (key == "gpu_layers") {
            config.gpu_layers = std::stoi(value);
        } else if (key == "threads") {
            config.threads = std::stoi(value);
        } else if (key == "ollama_url") {
            config.ollama_url = value;
        } else if (key == "ollama_model") {
            config.ollama_model = value;
        } else if (key == "sovereign_endpoint") {
            config.sovereign_endpoint = value;
        } else if (key == "enable_seg") {
            config.enable_seg = (value == "true" || value == "1");
        } else if (key == "enable_learning") {
            config.enable_learning = (value == "true" || value == "1");
        } else if (key == "enable_telemetry") {
            config.enable_telemetry = (value == "true" || value == "1");
        } else if (key == "warmup_runs") {
            config.warmup_runs = std::stoi(value);
        } else if (key == "measured_runs") {
            config.measured_runs = std::stoi(value);
        } else if (key == "verbose") {
            config.verbose = (value == "true" || value == "1");
        } else if (key == "output_dir") {
            config.output_dir = value;
        }
    }
    
    return config;
}

bool ConfigurationManager::SaveToFile(const BenchmarkConfig& config, 
                                        const std::string& path) {
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    file << "# RawrXD Benchmark Configuration\n";
    file << "# Generated automatically\n\n";
    
    file << "backend=" << BackendTypeToString(config.backend) << "\n";
    file << "model_name=" << config.model_name << "\n";
    file << "model_path=" << config.model_path << "\n";
    file << "swarm_size=" << config.swarm_size << "\n";
    file << "context_length=" << config.context_length << "\n";
    file << "max_tokens=" << config.max_tokens << "\n";
    file << "temperature=" << config.temperature << "\n";
    file << "gpu_backend=" << config.gpu_backend << "\n";
    file << "gpu_layers=" << config.gpu_layers << "\n";
    file << "threads=" << config.threads << "\n";
    file << "\n";
    
    file << "# Ollama Settings\n";
    file << "ollama_url=" << config.ollama_url << "\n";
    file << "ollama_model=" << config.ollama_model << "\n";
    file << "\n";
    
    file << "# Sovereign Settings\n";
    file << "sovereign_endpoint=" << config.sovereign_endpoint << "\n";
    file << "enable_seg=" << (config.enable_seg ? "true" : "false") << "\n";
    file << "enable_learning=" << (config.enable_learning ? "true" : "false") << "\n";
    file << "enable_telemetry=" << (config.enable_telemetry ? "true" : "false") << "\n";
    file << "\n";
    
    file << "# Benchmark Control\n";
    file << "warmup_runs=" << config.warmup_runs << "\n";
    file << "measured_runs=" << config.measured_runs << "\n";
    file << "verbose=" << (config.verbose ? "true" : "false") << "\n";
    file << "output_dir=" << config.output_dir << "\n";
    
    return true;
}

BenchmarkConfig ConfigurationManager::LoadFromEnvironment() {
    BenchmarkConfig config;
    
    // Backend type
    std::string backend = EnvironmentConfig::GetString(EnvironmentConfig::BACKEND_TYPE);
    if (!backend.empty()) {
        if (backend == "sovereign") config.backend = BackendType::SOVEREIGN;
        else if (backend == "ollama") config.backend = BackendType::OLLAMA;
    }
    
    // Model
    config.model_name = EnvironmentConfig::GetString(EnvironmentConfig::MODEL_NAME, 
                                                        config.model_name);
    
    // Endpoint
    std::string endpoint = EnvironmentConfig::GetString(EnvironmentConfig::ENDPOINT);
    if (!endpoint.empty()) {
        if (config.backend == BackendType::SOVEREIGN) {
            config.sovereign_endpoint = endpoint;
        } else if (config.backend == BackendType::OLLAMA) {
            config.ollama_url = endpoint;
        }
    }
    
    // Swarm size
    config.swarm_size = EnvironmentConfig::GetInt(EnvironmentConfig::SWARM_SIZE, 
                                                     config.swarm_size);
    
    // Warmup and measured runs
    config.warmup_runs = EnvironmentConfig::GetInt(EnvironmentConfig::WARMUP_RUNS, 
                                                  config.warmup_runs);
    config.measured_runs = EnvironmentConfig::GetInt(EnvironmentConfig::MEASURED_RUNS, 
                                                       config.measured_runs);
    
    // Output directory
    config.output_dir = EnvironmentConfig::GetString(EnvironmentConfig::OUTPUT_DIR, 
                                                        config.output_dir);
    
    // Verbose
    config.verbose = EnvironmentConfig::GetBool(EnvironmentConfig::VERBOSE, 
                                                   config.verbose);
    
    return config;
}

BenchmarkConfig ConfigurationManager::LoadFromArgs(int argc, char** argv) {
    BenchmarkConfig config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--backend" && i + 1 < argc) {
            std::string backend = argv[++i];
            if (backend == "sovereign") config.backend = BackendType::SOVEREIGN;
            else if (backend == "ollama") config.backend = BackendType::OLLAMA;
        } else if (arg == "--model" && i + 1 < argc) {
            config.model_name = argv[++i];
        } else if (arg == "--endpoint" && i + 1 < argc) {
            std::string endpoint = argv[++i];
            if (config.backend == BackendType::SOVEREIGN) {
                config.sovereign_endpoint = endpoint;
            } else {
                config.ollama_url = endpoint;
            }
        } else if (arg == "--swarm-size" && i + 1 < argc) {
            config.swarm_size = std::stoi(argv[++i]);
        } else if (arg == "--max-tokens" && i + 1 < argc) {
            config.max_tokens = std::stoi(argv[++i]);
        } else if (arg == "--temperature" && i + 1 < argc) {
            config.temperature = std::stof(argv[++i]);
        } else if (arg == "--warmup-runs" && i + 1 < argc) {
            config.warmup_runs = std::stoi(argv[++i]);
        } else if (arg == "--measured-runs" && i + 1 < argc) {
            config.measured_runs = std::stoi(argv[++i]);
        } else if (arg == "--output-dir" && i + 1 < argc) {
            config.output_dir = argv[++i];
        } else if (arg == "--verbose" || arg == "-v") {
            config.verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [options]\n"
                      << "\nOptions:\n"
                      << "  --backend <type>       Backend type (sovereign, ollama)\n"
                      << "  --model <name>         Model name\n"
                      << "  --endpoint <url>        Backend endpoint URL\n"
                      << "  --swarm-size <n>       Number of agents in swarm\n"
                      << "  --max-tokens <n>       Maximum tokens to generate\n"
                      << "  --temperature <f>      Sampling temperature\n"
                      << "  --warmup-runs <n>      Number of warmup runs\n"
                      << "  --measured-runs <n>     Number of measured runs\n"
                      << "  --output-dir <path>    Output directory for reports\n"
                      << "  --verbose, -v          Enable verbose output\n"
                      << "  --help, -h             Show this help message\n";
            std::exit(0);
        }
    }
    
    return config;
}

BenchmarkConfig ConfigurationManager::Merge(const BenchmarkConfig& base,
                                            const BenchmarkConfig& override) {
    BenchmarkConfig result = base;
    
    // Only override non-default values
    if (override.backend != BackendType::UNKNOWN) result.backend = override.backend;
    if (!override.model_name.empty()) result.model_name = override.model_name;
    if (!override.model_path.empty()) result.model_path = override.model_path;
    if (override.swarm_size != DEFAULT_SWARM_SIZE) result.swarm_size = override.swarm_size;
    if (override.context_length != 4096) result.context_length = override.context_length;
    if (override.max_tokens != 512) result.max_tokens = override.max_tokens;
    if (override.temperature != 0.7f) result.temperature = override.temperature;
    if (!override.gpu_backend.empty()) result.gpu_backend = override.gpu_backend;
    if (override.gpu_layers != 99) result.gpu_layers = override.gpu_layers;
    if (override.threads != 16) result.threads = override.threads;
    if (!override.ollama_url.empty()) result.ollama_url = override.ollama_url;
    if (!override.ollama_model.empty()) result.ollama_model = override.ollama_model;
    if (!override.sovereign_endpoint.empty()) result.sovereign_endpoint = override.sovereign_endpoint;
    if (override.warmup_runs != WARMUP_RUNS) result.warmup_runs = override.warmup_runs;
    if (override.measured_runs != MEASURED_RUNS) result.measured_runs = override.measured_runs;
    if (override.verbose) result.verbose = override.verbose;
    if (!override.output_dir.empty()) result.output_dir = override.output_dir;
    
    return result;
}

bool ConfigurationManager::Validate(const BenchmarkConfig& config, std::string& error) {
    // Validate backend type
    if (!BackendFactory::IsAvailable(config.backend)) {
        error = "Invalid or unsupported backend type";
        return false;
    }
    
    // Validate model name
    if (config.model_name.empty()) {
        error = "Model name cannot be empty";
        return false;
    }
    
    // Validate numeric ranges
    if (config.swarm_size < 1 || config.swarm_size > 1024) {
        error = "Swarm size must be between 1 and 1024";
        return false;
    }
    
    if (config.max_tokens < 1 || config.max_tokens > 32768) {
        error = "Max tokens must be between 1 and 32768";
        return false;
    }
    
    if (config.temperature < 0.0f || config.temperature > 2.0f) {
        error = "Temperature must be between 0.0 and 2.0";
        return false;
    }
    
    if (config.warmup_runs < 0 || config.warmup_runs > 100) {
        error = "Warmup runs must be between 0 and 100";
        return false;
    }
    
    if (config.measured_runs < 1 || config.measured_runs > 10000) {
        error = "Measured runs must be between 1 and 10000";
        return false;
    }
    
    return true;
}

void ConfigurationManager::Print(const BenchmarkConfig& config) {
    std::cout << "Benchmark Configuration:\n"
              << "  Backend: " << BackendTypeToString(config.backend) << "\n"
              << "  Model: " << config.model_name << "\n"
              << "  Swarm Size: " << config.swarm_size << "\n"
              << "  Context Length: " << config.context_length << "\n"
              << "  Max Tokens: " << config.max_tokens << "\n"
              << "  Temperature: " << config.temperature << "\n"
              << "  GPU Backend: " << config.gpu_backend << "\n"
              << "  GPU Layers: " << config.gpu_layers << "\n"
              << "  Threads: " << config.threads << "\n"
              << "  Warmup Runs: " << config.warmup_runs << "\n"
              << "  Measured Runs: " << config.measured_runs << "\n"
              << "  Output Directory: " << config.output_dir << "\n"
              << "  Verbose: " << (config.verbose ? "true" : "false") << "\n";
    
    if (config.backend == BackendType::SOVEREIGN) {
        std::cout << "  Sovereign Endpoint: " << config.sovereign_endpoint << "\n"
                  << "  Enable SEG: " << (config.enable_seg ? "true" : "false") << "\n"
                  << "  Enable Learning: " << (config.enable_learning ? "true" : "false") << "\n"
                  << "  Enable Telemetry: " << (config.enable_telemetry ? "true" : "false") << "\n";
    } else if (config.backend == BackendType::OLLAMA) {
        std::cout << "  Ollama URL: " << config.ollama_url << "\n"
                  << "  Ollama Model: " << config.ollama_model << "\n";
    }
}

// ============================================================================
// Environment Configuration Implementation
// ============================================================================

std::string EnvironmentConfig::GetString(const std::string& name,
                                           const std::string& default_value) {
    const char* value = std::getenv(name.c_str());
    return value ? value : default_value;
}

int EnvironmentConfig::GetInt(const std::string& name, int default_value) {
    const char* value = std::getenv(name.c_str());
    if (!value) return default_value;
    try {
        return std::stoi(value);
    } catch (...) {
        return default_value;
    }
}

bool EnvironmentConfig::GetBool(const std::string& name, bool default_value) {
    const char* value = std::getenv(name.c_str());
    if (!value) return default_value;
    std::string str(value);
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str == "true" || str == "1" || str == "yes";
}

float EnvironmentConfig::GetFloat(const std::string& name, float default_value) {
    const char* value = std::getenv(name.c_str());
    if (!value) return default_value;
    try {
        return std::stof(value);
    } catch (...) {
        return default_value;
    }
}

bool EnvironmentConfig::Has(const std::string& name) {
    return std::getenv(name.c_str()) != nullptr;
}

bool EnvironmentConfig::Set(const std::string& name, const std::string& value) {
    #ifdef _WIN32
        return _putenv((name + "=" + value).c_str()) == 0;
    #else
        return setenv(name.c_str(), value.c_str(), 1) == 0;
    #endif
}

} // namespace rawrxd::benchmark
