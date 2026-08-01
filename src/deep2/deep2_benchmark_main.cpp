// ============================================================================
// deep2_benchmark_main.cpp - CLI Entry Point for Deep2 Benchmark Harness
// ============================================================================
//
// Usage:
//   deep2_benchmark.exe --model <path> --phase single --prompt "..." --max-tokens 8192
//   deep2_benchmark.exe --model <path> --phase endurance --ctx-sizes 1k,4k,8k,16k,32k
//   deep2_benchmark.exe --model <path> --phase saturation --streams 4
//   deep2_benchmark.exe --model <path> --phase thermal --duration 1800
//   deep2_benchmark.exe --model <path> --phase certify  (runs full suite)
//
// Output formats:
//   --output-format json   (default)
//   --output-format markdown
//   --output-format telemetry  (structured for CI/CD)
//
// ============================================================================

#include "Deep2Benchmark.h"
#include "Deep2Engine.h"
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace Deep2;

// ============================================================================
// Command Line Parsing
// ============================================================================
struct CommandLineArgs {
    std::string modelPath;
    std::string phase = "certify";  // single, endurance, saturation, thermal, certify
    std::string prompt = "Write a large C++ project with full documentation and test coverage.";
    uint64_t maxTokens = 8192;
    uint32_t contextSize = 32768;
    std::vector<uint32_t> enduranceContexts;
    uint32_t saturationStreams = 4;
    uint64_t saturationTokensPerStream = 2048;
    uint32_t thermalDuration = 1800;
    uint32_t thermalInterval = 5;
    std::string outputPath = "deep2_benchmark_report.json";
    std::string outputFormat = "json";
    bool verbose = true;
    bool help = false;
};

void printUsage(const char* prog) {
    std::cout << R"(
Deep2 Maximum Streamable Throughput Benchmark
=============================================

Usage: )" << prog << R"( [OPTIONS]

Required:
  --model <path>              Path to GGUF model file

Phases:
  --phase single               Single-stream maximum throughput test
  --phase endurance            Context scaling endurance matrix
  --phase saturation             Multi-stream saturation test
  --phase thermal              Thermal stability soak test
  --phase certify              Full certification suite (default)

Single Stream Options:
  --prompt <text>             Test prompt (default: code generation)
  --max-tokens <n>            Maximum tokens to generate (default: 8192)
  --ctx-size <n>              Context window size (default: 32768)

Endurance Options:
  --ctx-sizes <list>          Comma-separated context sizes (default: 1k,4k,8k,16k,32k)

Saturation Options:
  --streams <n>               Number of concurrent streams (default: 4)
  --tokens-per-stream <n>    Tokens per stream (default: 2048)

Thermal Options:
  --duration <seconds>        Test duration in seconds (default: 1800 = 30 min)
  --sample-interval <sec>     Sampling interval (default: 5)

Output:
  --output <path>             Output file path (default: deep2_benchmark_report.json)
  --format <type>             Output format: json, markdown, telemetry (default: json)
  --quiet                      Minimal output

Examples:
  # Full certification
  deep2_benchmark.exe --model F:\Models\deep2-q4_k_m.gguf --phase certify

  # Quick single-stream test
  deep2_benchmark.exe --model deep2.gguf --phase single --max-tokens 2048

  # Endurance matrix with custom contexts
  deep2_benchmark.exe --model deep2.gguf --phase endurance --ctx-sizes 512,1024,2048,4096

  # 4-stream saturation test
  deep2_benchmark.exe --model deep2.gguf --phase saturation --streams 4

  # 30-minute thermal soak
  deep2_benchmark.exe --model deep2.gguf --phase thermal --duration 1800

)";
}

std::vector<uint32_t> parseContextSizes(const std::string& str) {
    std::vector<uint32_t> result;
    std::stringstream ss(str);
    std::string token;
    
    while (std::getline(ss, token, ',')) {
        // Trim whitespace
        size_t start = token.find_first_not_of(" \t");
        size_t end = token.find_last_not_of(" \t");
        if (start == std::string::npos) continue;
        token = token.substr(start, end - start + 1);
        
        // Parse with k/m suffix support
        uint32_t multiplier = 1;
        if (token.back() == 'k' || token.back() == 'K') {
            multiplier = 1024;
            token = token.substr(0, token.length() - 1);
        } else if (token.back() == 'm' || token.back() == 'M') {
            multiplier = 1024 * 1024;
            token = token.substr(0, token.length() - 1);
        }
        
        result.push_back(std::stoul(token) * multiplier);
    }
    
    return result;
}

CommandLineArgs parseArgs(int argc, char** argv) {
    CommandLineArgs args;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            args.help = true;
        }
        else if (arg == "--model" && i + 1 < argc) {
            args.modelPath = argv[++i];
        }
        else if (arg == "--phase" && i + 1 < argc) {
            args.phase = argv[++i];
        }
        else if (arg == "--prompt" && i + 1 < argc) {
            args.prompt = argv[++i];
        }
        else if (arg == "--max-tokens" && i + 1 < argc) {
            args.maxTokens = std::stoull(argv[++i]);
        }
        else if (arg == "--ctx-size" && i + 1 < argc) {
            args.contextSize = std::stoul(argv[++i]);
        }
        else if (arg == "--ctx-sizes" && i + 1 < argc) {
            args.enduranceContexts = parseContextSizes(argv[++i]);
        }
        else if (arg == "--streams" && i + 1 < argc) {
            args.saturationStreams = std::stoul(argv[++i]);
        }
        else if (arg == "--tokens-per-stream" && i + 1 < argc) {
            args.saturationTokensPerStream = std::stoull(argv[++i]);
        }
        else if (arg == "--duration" && i + 1 < argc) {
            args.thermalDuration = std::stoul(argv[++i]);
        }
        else if (arg == "--sample-interval" && i + 1 < argc) {
            args.thermalInterval = std::stoul(argv[++i]);
        }
        else if (arg == "--output" && i + 1 < argc) {
            args.outputPath = argv[++i];
        }
        else if (arg == "--format" && i + 1 < argc) {
            args.outputFormat = argv[++i];
        }
        else if (arg == "--quiet") {
            args.verbose = false;
        }
    }
    
    // Default endurance contexts if not specified
    if (args.enduranceContexts.empty()) {
        args.enduranceContexts = {1024, 4096, 8192, 16384, 32768};
    }
    
    return args;
}

// ============================================================================
// Console Output Helpers
// ============================================================================
void printBanner() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║     DEEP2 MAXIMUM STREAMABLE THROUGHPUT BENCHMARK                        ║
║                                                                          ║
║     Production Certification Protocol for RawrXD/Deep2 Engine            ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝

)";
}

void printProgress(const std::string& phase, int current, int total) {
    int width = 40;
    float progress = (float)current / total;
    int pos = (int)(width * progress);
    
    std::cout << "\r[" << phase << "] ";
    std::cout << "[";
    for (int i = 0; i < width; ++i) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << (int)(progress * 100) << "%";
    std::cout.flush();
}

// ============================================================================
// Main Entry Point
// ============================================================================
int main(int argc, char** argv) {
    CommandLineArgs args = parseArgs(argc, argv);
    
    if (args.help || args.modelPath.empty()) {
        printUsage(argv[0]);
        return args.help ? 0 : 1;
    }
    
    if (args.verbose) {
        printBanner();
        std::cout << "Model: " << args.modelPath << "\n";
        std::cout << "Phase: " << args.phase << "\n\n";
    }
    
    // Initialize benchmark harness
    BenchmarkHarness harness;
    
    if (args.verbose) std::cout << "[INIT] Loading model...\n";
    
    auto initStart = std::chrono::high_resolution_clock::now();
    if (!harness.initialize(args.modelPath)) {
        std::cerr << "[ERROR] Failed to initialize Deep2 engine with model: " << args.modelPath << "\n";
        return 1;
    }
    auto initEnd = std::chrono::high_resolution_clock::now();
    double initMs = std::chrono::duration<double, std::milli>(initEnd - initStart).count();
    
    if (args.verbose) std::cout << "[INIT] Model loaded in " << initMs << " ms\n\n";
    
    // Execute requested phase
    if (args.phase == "single") {
        // Single-stream test
        if (args.verbose) std::cout << "[SINGLE-STREAM] Running maximum throughput test...\n";
        
        auto bench = harness.runSingleStreamTest(args.prompt, args.maxTokens, args.contextSize);
        
        std::cout << "\n=== Single-Stream Results ===\n";
        std::cout << "Prompt Tokens:      " << bench.prompt_tokens << "\n";
        std::cout << "Generated Tokens:   " << bench.generated_tokens << "\n";
        std::cout << "Prefill TPS:        " << bench.prefill_tps << "\n";
        std::cout << "Decode TPS:         " << bench.decode_tps << "\n";
        std::cout << "Sustained TPS:      " << bench.sustained_tps << "\n";
        std::cout << "First Token:        " << (bench.first_token_ns / 1e6) << " ms\n";
        std::cout << "Avg Token Latency:  " << (bench.per_token_avg_ns / 1e6) << " ms\n";
        std::cout << "Variance (CV):      " << bench.tps_variance << "\n";
        std::cout << "Stream Stable:      " << (bench.stream_stable ? "YES" : "NO") << "\n";
        
    }
    else if (args.phase == "endurance") {
        // Endurance matrix
        if (args.verbose) {
            std::cout << "[ENDURANCE] Running context scaling matrix...\n";
            std::cout << "Contexts: ";
            for (auto ctx : args.enduranceContexts) std::cout << ctx << " ";
            std::cout << "\n\n";
        }
        
        auto results = harness.runEnduranceMatrix(args.enduranceContexts, 2048);
        
        std::cout << "\n=== Endurance Matrix Results ===\n";
        std::cout << "Context | Prefill TPS | Decode TPS | Stable\n";
        std::cout << "--------|-------------|------------|-------\n";
        for (const auto& r : results) {
            std::cout << r.context_size << " | " 
                      << r.prefill_tps << " | " 
                      << r.decode_tps << " | " 
                      << (r.stable ? "YES" : "NO") << "\n";
        }
        
    }
    else if (args.phase == "saturation") {
        // Saturation test
        if (args.verbose) {
            std::cout << "[SATURATION] Running multi-stream test...\n";
            std::cout << "Streams: " << args.saturationStreams << "\n\n";
        }
        
        auto result = harness.runSaturationTest(
            args.saturationStreams,
            args.saturationTokensPerStream,
            8192
        );
        
        std::cout << "\n=== Saturation Results ===\n";
        std::cout << "Concurrent Streams:     " << result.num_streams << "\n";
        std::cout << "Aggregate TPS:        " << result.aggregate_tps << "\n";
        std::cout << "Worst First-Token:    " << result.worst_first_token_ms << " ms\n";
        std::cout << "Avg Stream TPS:       " << result.avg_stream_tps << "\n";
        std::cout << "Total Tokens:         " << result.total_tokens_generated << "\n";
        std::cout << "All Streams Stable:   " << (result.all_streams_stable ? "YES" : "NO") << "\n";
        
    }
    else if (args.phase == "thermal") {
        // Thermal test
        if (args.verbose) {
            std::cout << "[THERMAL] Running thermal soak test...\n";
            std::cout << "Duration: " << args.thermalDuration << " seconds\n\n";
        }
        
        auto result = harness.runThermalTest(args.thermalDuration, args.thermalInterval);
        
        std::cout << "\n=== Thermal Results ===\n";
        std::cout << "Duration:             " << result.duration_seconds << " seconds\n";
        std::cout << "Peak Temperature:     " << result.peak_temp_c << " °C\n";
        std::cout << "Throttle Events:      " << result.throttle_events << "\n";
        std::cout << "Avg Power Draw:       " << result.avg_power_watts << " W\n";
        std::cout << "TPS Start:            " << result.tps_start << "\n";
        std::cout << "TPS End:              " << result.tps_end << "\n";
        std::cout << "TPS Degradation:      " << result.tps_degradation_percent << "%\n";
        
    }
    else if (args.phase == "certify") {
        // Full certification suite
        BenchmarkConfig config;
        config.model_path = args.modelPath;
        config.model_name = args.modelPath;
        config.prompt_text = args.prompt;
        config.max_tokens = args.maxTokens;
        config.context_size = args.contextSize;
        config.endurance_contexts = args.enduranceContexts;
        config.saturation_streams = args.saturationStreams;
        config.saturation_tokens_per_stream = args.saturationTokensPerStream;
        config.thermal_duration_seconds = args.thermalDuration;
        config.thermal_sample_interval_seconds = args.thermalInterval;
        config.output_path = args.outputPath;
        config.verbose = args.verbose;
        
        auto report = harness.runFullCertification(config);
        
        if (args.verbose) {
            std::cout << "\n";
            std::cout << "╔══════════════════════════════════════════════════════════════════════════╗\n";
            std::cout << "║                                                                          ║\n";
            if (report.overall_certified) {
                std::cout << "║     ✅ CERTIFICATION PASSED                                              ║\n";
            } else {
                std::cout << "║     ❌ CERTIFICATION FAILED                                              ║\n";
            }
            std::cout << "║                                                                          ║\n";
            std::cout << "║     Certification ID: " << report.certification_id << "\n";
            std::cout << "║                                                                          ║\n";
            std::cout << "╚══════════════════════════════════════════════════════════════════════════╝\n";
            std::cout << "\nReports saved:\n";
            std::cout << "  JSON:    " << args.outputPath << "\n";
            std::cout << "  Markdown: " << args.outputPath.substr(0, args.outputPath.rfind('.')) << ".md\n";
        }
        
        return report.overall_certified ? 0 : 1;
    }
    else {
        std::cerr << "[ERROR] Unknown phase: " << args.phase << "\n";
        std::cerr << "Valid phases: single, endurance, saturation, thermal, certify\n";
        return 1;
    }
    
    std::cout << "\n[DONE] Benchmark complete.\n";
    return 0;
}
