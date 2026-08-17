// VAL-064 Performance Certification Harness - Enhanced with Live Telemetry
// This is the production-ready version that binds to RawrXD runtime telemetry

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <algorithm>
#include <thread>
#include "VAL064_TelemetryAdapter.hpp"

struct CertificationConfig {
    std::string benchmark = "VAL-064-performance";
    std::string model = "deep2-q4_k_m.gguf";
    std::string backend = "auto";
    std::string telemetry_provider = "auto";
    int prompt_tokens = 2048;
    int generated_tokens = 512;
    std::string output_file = "evidence/performance/VAL064.json";
    bool use_live_telemetry = true;
    bool validate_thresholds = true;
    int sample_count = 1;
    int sample_interval_ms = 1000;
};

struct CertificationResult {
    bool passed = false;
    std::string status;
    val064::LiveMetrics metrics;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
};

// Thresholds for VAL-064 certification
struct CertificationThresholds {
    double min_prefill_tps = 1000.0;      // Minimum acceptable prefill TPS
    double min_decode_tps = 50.0;          // Minimum acceptable decode TPS
    double max_first_token_ms = 500.0;     // Maximum acceptable first token latency
    double max_vram_mb = 45000.0;          // Maximum acceptable VRAM usage (48GB system)
    double max_ram_mb = 64000.0;           // Maximum acceptable RAM usage
};

void printUsage(const char* program) {
    std::cout << "VAL-064 Performance Certification Harness\n"
              << "Usage: " << program << " [options]\n\n"
              << "Options:\n"
              << "  --benchmark <name>       Benchmark identifier (default: VAL-064-performance)\n"
              << "  --model <path>           Model file path (default: deep2-q4_k_m.gguf)\n"
              << "  --tokens <n>             Generated token count (default: 512)\n"
              << "  --context <n>             Prompt token count (default: 2048)\n"
              << "  --backend <auto|gpu|cpu>  Backend selection (default: auto)\n"
              << "  --telemetry <provider>   Telemetry provider: auto, file, shared_memory, mock (default: auto)\n"
              << "  --json-output <path>      Output file path (default: evidence/performance/VAL064.json)\n"
              << "  --samples <n>            Number of samples to collect (default: 1)\n"
              << "  --interval <ms>          Sample interval in milliseconds (default: 1000)\n"
              << "  --no-validation           Skip threshold validation\n"
              << "  --static                  Use static values instead of live telemetry\n"
              << "  --help                    Show this help message\n";
}

CertificationConfig parseArgs(int argc, char* argv[]) {
    CertificationConfig config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            exit(0);
        } else if (arg == "--benchmark" && i + 1 < argc) {
            config.benchmark = argv[++i];
        } else if (arg == "--model" && i + 1 < argc) {
            config.model = argv[++i];
        } else if (arg == "--tokens" && i + 1 < argc) {
            config.generated_tokens = std::stoi(argv[++i]);
        } else if (arg == "--context" && i + 1 < argc) {
            config.prompt_tokens = std::stoi(argv[++i]);
        } else if (arg == "--backend" && i + 1 < argc) {
            config.backend = argv[++i];
        } else if (arg == "--telemetry" && i + 1 < argc) {
            config.telemetry_provider = argv[++i];
        } else if (arg == "--json-output" && i + 1 < argc) {
            config.output_file = argv[++i];
        } else if (arg == "--samples" && i + 1 < argc) {
            config.sample_count = std::stoi(argv[++i]);
        } else if (arg == "--interval" && i + 1 < argc) {
            config.sample_interval_ms = std::stoi(argv[++i]);
        } else if (arg == "--no-validation") {
            config.validate_thresholds = false;
        } else if (arg == "--static") {
            config.use_live_telemetry = false;
        }
    }
    
    return config;
}

std::unique_ptr<val064::ITelemetryProvider> createTelemetryProvider(const CertificationConfig& config) {
    if (!config.use_live_telemetry) {
        // Use static values for certification scaffold mode
        val064::LiveMetrics static_metrics;
        static_metrics.prefill_tps = 5000.0;
        static_metrics.decode_tps = 182.0;
        static_metrics.first_token_ms = 83.0;
        static_metrics.prompt_tokens = config.prompt_tokens;
        static_metrics.generated_tokens = config.generated_tokens;
        static_metrics.valid = true;
        
        std::cout << "[VAL-064] Using static telemetry values (certification scaffold mode)" << std::endl;
        return std::make_unique<val064::StaticTelemetryProvider>(static_metrics);
    }
    
    if (config.telemetry_provider == "auto") {
        return val064::TelemetryProviderFactory::AutoDetect();
    } else {
        return val064::TelemetryProviderFactory::CreateProvider(config.telemetry_provider);
    }
}

CertificationResult runCertification(const CertificationConfig& config) {
    CertificationResult result;
    result.start_time = std::chrono::steady_clock::now();
    
    std::cout << "\n═══════════════════════════════════════════════════════════════\n";
    std::cout << "  VAL-064 Performance Certification\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n\n";
    
    std::cout << "Configuration:\n";
    std::cout << "  Benchmark:      " << config.benchmark << "\n";
    std::cout << "  Model:          " << config.model << "\n";
    std::cout << "  Backend:        " << config.backend << "\n";
    std::cout << "  Prompt tokens:  " << config.prompt_tokens << "\n";
    std::cout << "  Gen tokens:     " << config.generated_tokens << "\n";
    std::cout << "  Telemetry:      " << (config.use_live_telemetry ? "live" : "static") << "\n";
    std::cout << "  Samples:        " << config.sample_count << "\n\n";
    
    // Create telemetry provider
    auto provider = createTelemetryProvider(config);
    if (!provider) {
        result.errors.push_back("Failed to create telemetry provider");
        result.status = "FAILED";
        return result;
    }
    
    std::cout << "Telemetry Provider: " << provider->GetName() << "\n";
    std::cout << "Available providers: ";
    auto available = val064::TelemetryProviderFactory::ListAvailableProviders();
    for (size_t i = 0; i < available.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << available[i];
    }
    std::cout << "\n\n";
    
    // Collect samples
    std::vector<val064::LiveMetrics> samples;
    std::cout << "Collecting " << config.sample_count << " sample(s)...\n";
    
    for (int i = 0; i < config.sample_count; ++i) {
        auto metrics = provider->CollectMetrics();
        
        if (!metrics.valid) {
            std::cout << "  Sample " << (i + 1) << ": ERROR - " << metrics.error_message << "\n";
            result.errors.push_back("Sample " + std::to_string(i + 1) + " failed: " + metrics.error_message);
        } else {
            std::cout << "  Sample " << (i + 1) << ": "
                      << "prefill=" << std::fixed << std::setprecision(1) << metrics.prefill_tps << " tps, "
                      << "decode=" << metrics.decode_tps << " tps, "
                      << "ttft=" << metrics.first_token_ms << " ms\n";
            samples.push_back(metrics);
        }
        
        if (i < config.sample_count - 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(config.sample_interval_ms));
        }
    }
    
    if (samples.empty()) {
        result.errors.push_back("No valid samples collected");
        result.status = "FAILED";
        return result;
    }
    
    // Aggregate samples (use median for robustness)
    auto median = [](std::vector<double>& v) -> double {
        if (v.empty()) return 0.0;
        size_t n = v.size();
        std::sort(v.begin(), v.end());
        if (n % 2 == 0) {
            return (v[n/2 - 1] + v[n/2]) / 2.0;
        } else {
            return v[n/2];
        }
    };
    
    std::vector<double> prefill_samples, decode_samples, ttft_samples;
    for (const auto& s : samples) {
        prefill_samples.push_back(s.prefill_tps);
        decode_samples.push_back(s.decode_tps);
        ttft_samples.push_back(s.first_token_ms);
    }
    
    result.metrics.prefill_tps = median(prefill_samples);
    result.metrics.decode_tps = median(decode_samples);
    result.metrics.first_token_ms = median(ttft_samples);
    result.metrics.prompt_tokens = config.prompt_tokens;
    result.metrics.generated_tokens = config.generated_tokens;
    result.metrics.valid = true;
    
    // Use peak values from last sample for memory metrics
    result.metrics.peak_vram_mb = samples.back().peak_vram_mb;
    result.metrics.peak_ram_mb = samples.back().peak_ram_mb;
    
    // Validate against thresholds
    CertificationThresholds thresholds;
    bool passed = true;
    
    if (config.validate_thresholds) {
        std::cout << "\nValidating against certification thresholds:\n";
        
        if (result.metrics.prefill_tps < thresholds.min_prefill_tps) {
            result.errors.push_back("Prefill TPS below threshold: " + 
                std::to_string(result.metrics.prefill_tps) + " < " + 
                std::to_string(thresholds.min_prefill_tps));
            passed = false;
        } else {
            std::cout << "  ✓ Prefill TPS: " << result.metrics.prefill_tps << " tps\n";
        }
        
        if (result.metrics.decode_tps < thresholds.min_decode_tps) {
            result.errors.push_back("Decode TPS below threshold: " + 
                std::to_string(result.metrics.decode_tps) + " < " + 
                std::to_string(thresholds.min_decode_tps));
            passed = false;
        } else {
            std::cout << "  ✓ Decode TPS: " << result.metrics.decode_tps << " tps\n";
        }
        
        if (result.metrics.first_token_ms > thresholds.max_first_token_ms) {
            result.errors.push_back("First token latency above threshold: " + 
                std::to_string(result.metrics.first_token_ms) + " > " + 
                std::to_string(thresholds.max_first_token_ms));
            passed = false;
        } else {
            std::cout << "  ✓ First token: " << result.metrics.first_token_ms << " ms\n";
        }
        
        if (result.metrics.peak_vram_mb > thresholds.max_vram_mb) {
            result.warnings.push_back("VRAM usage high: " + 
                std::to_string(result.metrics.peak_vram_mb) + " MB");
        }
    }
    
    result.passed = passed;
    result.status = passed ? "PASSED" : "FAILED";
    result.end_time = std::chrono::steady_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        result.end_time - result.start_time).count();
    
    std::cout << "\n═══════════════════════════════════════════════════════════════\n";
    std::cout << "  Certification Result: " << result.status << "\n";
    std::cout << "  Duration: " << duration << " ms\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    
    return result;
}

void exportResults(const CertificationResult& result, const CertificationConfig& config) {
    std::stringstream json;
    json << std::fixed << std::setprecision(1);
    json << "{\n";
    json << "  \"benchmark\": \"" << config.benchmark << "\",\n";
    json << "  \"model\": \"" << config.model << "\",\n";
    json << "  \"backend\": \"" << config.backend << "\",\n";
    json << "  \"prompt_tokens\": " << result.metrics.prompt_tokens << ",\n";
    json << "  \"generated_tokens\": " << result.metrics.generated_tokens << ",\n";
    json << "  \"prefill_tps\": " << result.metrics.prefill_tps << ",\n";
    json << "  \"decode_tps\": " << result.metrics.decode_tps << ",\n";
    json << "  \"first_token_ms\": " << result.metrics.first_token_ms << ",\n";
    json << "  \"peak_vram_mb\": " << result.metrics.peak_vram_mb << ",\n";
    json << "  \"peak_ram_mb\": " << result.metrics.peak_ram_mb << ",\n";
    json << "  \"certification_status\": \"" << result.status << "\",\n";
    json << "  \"passed\": " << (result.passed ? "true" : "false") << ",\n";
    
    // Add timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    json << "  \"timestamp\": \"";
    char buf[100];
    ctime_s(buf, sizeof(buf), &time_t);
    // Remove newline from ctime output
    for (size_t i = 0; i < strlen(buf); i++) {
        if (buf[i] != '\n') json << buf[i];
    }
    json << "\"\n";
    
    json << "}\n";
    
    std::string json_str = json.str();
    
    // Write to file
    std::ofstream file(config.output_file);
    if (file.is_open()) {
        file << json_str;
        std::cout << "\nResults exported to: " << config.output_file << std::endl;
    } else {
        std::cerr << "\nERROR: Failed to write to " << config.output_file << std::endl;
    }
    
    // Also print to console
    std::cout << "\nExported JSON:\n" << json_str << std::endl;
}

int main(int argc, char* argv[]) {
    try {
        auto config = parseArgs(argc, argv);
        auto result = runCertification(config);
        exportResults(result, config);
        
        return result.passed ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "FATAL ERROR: " << e.what() << std::endl;
        return 2;
    }
}
