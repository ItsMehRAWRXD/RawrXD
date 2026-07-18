#include "hotpatch_tps_benchmark.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <iomanip>

using namespace rawrxd::benchmarks;

void PrintUsage(const char* program) {
    std::cout << "Hotpatch TPS Benchmark Runner\n";
    std::cout << "==============================\n\n";
    std::cout << "Usage: " << program << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --model <name>           Model name (phi-3-mini, llama-3-8b, llama-3-70b)\n";
    std::cout << "  --patch-type <type>      Patch type (scheduler, gemm, attention, memory, simd, kv, batching, thread, quant, rope)\n";
    std::cout << "  --baseline-duration <s>  Baseline sampling duration (default: 120)\n";
    std::cout << "  --post-patch-duration <s> Post-patch sampling duration (default: 120)\n";
    std::cout << "  --confidence <level>     Confidence level (0.80, 0.90, 0.95, 0.99)\n";
    std::cout << "  --output <dir>           Output directory for results\n";
    std::cout << "  --format <format>        Output format (json, markdown, csv, all)\n";
    std::cout << "  --matrix                 Run full matrix benchmark (small/medium/large)\n";
    std::cout << "  --compare <file>         Compare against previous results\n";
    std::cout << "  --help                   Show this help\n";
}

HotpatchType ParsePatchType(const std::string& type) {
    static const std::map<std::string, HotpatchType> type_map = {
        {"scheduler", HotpatchType::SCHEDULER_OPTIMIZATION},
        {"gemm", HotpatchType::KERNEL_GEMM_REPLACE},
        {"attention", HotpatchType::KERNEL_ATTENTION_REPLACE},
        {"memory", HotpatchType::MEMORY_ALLOCATOR_PATCH},
        {"simd", HotpatchType::SIMD_PATH_SELECTION},
        {"kv", HotpatchType::KV_CACHE_POLICY},
        {"batching", HotpatchType::BATCHING_STRATEGY},
        {"thread", HotpatchType::THREAD_AFFINITY_PATCH},
        {"quant", HotpatchType::QUANTIZATION_KERNEL},
        {"rope", HotpatchType::ROPE_KERNEL_REPLACE}
    };
    
    auto it = type_map.find(type);
    if (it != type_map.end()) return it->second;
    return HotpatchType::KERNEL_GEMM_REPLACE;  // Default
}

void ProgressCallback(BenchmarkPhase phase, double progress) {
    const char* phase_name = "Unknown";
    switch (phase) {
        case BenchmarkPhase::WARMUP: phase_name = "Warmup"; break;
        case BenchmarkPhase::BASELINE_SAMPLING: phase_name = "Baseline"; break;
        case BenchmarkPhase::PATCH_APPLICATION: phase_name = "Patching"; break;
        case BenchmarkPhase::POST_PATCH_SAMPLING: phase_name = "Post-Patch"; break;
        case BenchmarkPhase::COOLDOWN: phase_name = "Cooldown"; break;
    }
    
    int bar_width = 30;
    int pos = static_cast<int>(bar_width * progress);
    
    std::cout << "\r[" << phase_name << "] [";
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << std::fixed << std::setprecision(1) << (progress * 100.0) << "%";
    std::cout.flush();
}

void SampleCallback(const TPSMeasurement& sample) {
    // Optional: real-time sample display
    // std::cout << "\rSample: " << sample.generation_tps << " tok/s";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    // Parse arguments
    HotpatchTPSConfig config;
    std::string output_dir = "./hotpatch_results";
    std::string output_format = "all";
    bool run_matrix = false;
    std::string compare_file;
    
    // Default to small model
    config = GetSmallModelConfig();
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            PrintUsage(argv[0]);
            return 0;
        }
        else if (arg == "--model" && i + 1 < argc) {
            std::string model = argv[++i];
            if (model == "phi-3-mini" || model == "small") {
                config = GetSmallModelConfig();
            } else if (model == "llama-3-8b" || model == "medium") {
                config = GetMediumModelConfig();
            } else if (model == "llama-3-70b" || model == "large") {
                config = GetLargeModelConfig();
            } else {
                config.model_name = model;
            }
        }
        else if (arg == "--patch-type" && i + 1 < argc) {
            config.patch_type = ParsePatchType(argv[++i]);
        }
        else if (arg == "--baseline-duration" && i + 1 < argc) {
            config.baseline_sampling_seconds = std::stoi(argv[++i]);
        }
        else if (arg == "--post-patch-duration" && i + 1 < argc) {
            config.post_patch_sampling_seconds = std::stoi(argv[++i]);
        }
        else if (arg == "--confidence" && i + 1 < argc) {
            config.confidence_level = std::stod(argv[++i]);
        }
        else if (arg == "--output" && i + 1 < argc) {
            output_dir = argv[++i];
        }
        else if (arg == "--format" && i + 1 < argc) {
            output_format = argv[++i];
        }
        else if (arg == "--matrix") {
            run_matrix = true;
        }
        else if (arg == "--compare" && i + 1 < argc) {
            compare_file = argv[++i];
        }
    }
    
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     RawrXD Hotpatch TPS Benchmark                            ║\n";
    std::cout << "║     Live Runtime Optimization Validation                     ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
    
    if (run_matrix) {
        std::cout << "Running full matrix benchmark (small/medium/large models)...\n\n";
        auto results = RunHotpatchMatrixBenchmark();
        
        std::cout << "\n=== Matrix Benchmark Results ===\n\n";
        std::cout << std::left << std::setw(12) << "Category" 
                  << std::setw(20) << "Patch Type"
                  << std::setw(12) << "Baseline"
                  << std::setw(12) << "Hotpatched"
                  << std::setw(12) << "Improvement"
                  << std::setw(8) << "Signif"
                  << std::setw(10) << "Effect"
                  << "\n";
        std::cout << std::string(86, '-') << "\n";
        
        for (const auto& comp : results) {
            std::cout << std::left << std::setw(12) << comp.model_category
                      << std::setw(20) << comp.patch_type_used
                      << std::setw(12) << std::fixed << std::setprecision(1) << comp.baseline_prompt_tps
                      << std::setw(12) << comp.hotpatched_prompt_tps
                      << std::setw(11) << std::setprecision(1) << comp.improvement_percent << "%"
                      << std::setw(8) << (comp.statistically_significant ? "YES" : "NO")
                      << std::setw(10) << std::setprecision(2) << comp.effect_size
                      << "\n";
        }
        
        // Save matrix results
        std::ofstream matrix_out(output_dir + "/matrix_results.json");
        matrix_out << "[\n";
        for (size_t i = 0; i < results.size(); ++i) {
            matrix_out << "  {\n";
            matrix_out << "    \"category\": \"" << results[i].model_category << "\",\n";
            matrix_out << "    \"patch_type\": \"" << results[i].patch_type_used << "\",\n";
            matrix_out << "    \"baseline_tps\": " << results[i].baseline_prompt_tps << ",\n";
            matrix_out << "    \"hotpatched_tps\": " << results[i].hotpatched_prompt_tps << ",\n";
            matrix_out << "    \"improvement_percent\": " << results[i].improvement_percent << ",\n";
            matrix_out << "    \"effect_size\": " << results[i].effect_size << ",\n";
            matrix_out << "    \"significant\": " << (results[i].statistically_significant ? "true" : "false") << "\n";
            matrix_out << "  }" << (i < results.size() - 1 ? "," : "") << "\n";
        }
        matrix_out << "]\n";
        
    } else {
        // Single benchmark run
        auto benchmark = CreateHotpatchTPSBenchmark(config);
        benchmark->SetProgressCallback(ProgressCallback);
        benchmark->SetSampleCallback(SampleCallback);
        
        auto results = benchmark->Run();
        
        std::cout << "\n\n=== Exporting Results ===\n";
        
        // Create output directory
        std::string cmd = "mkdir -p " + output_dir;
        system(cmd.c_str());
        
        // Export based on format
        if (output_format == "json" || output_format == "all") {
            std::string json_file = output_dir + "/hotpatch_results.json";
            std::ofstream json_out(json_file);
            json_out << results.ToJson();
            std::cout << "JSON: " << json_file << "\n";
        }
        
        if (output_format == "markdown" || output_format == "all") {
            std::string md_file = output_dir + "/hotpatch_results.md";
            std::ofstream md_out(md_file);
            md_out << results.ToMarkdown();
            std::cout << "Markdown: " << md_file << "\n";
        }
        
        if (output_format == "csv" || output_format == "all") {
            std::string csv_file = output_dir + "/hotpatch_samples.csv";
            std::ofstream csv_out(csv_file);
            csv_out << results.ToCsv();
            std::cout << "CSV: " << csv_file << "\n";
        }
        
        // Print summary
        std::cout << "\n=== Final Summary ===\n";
        std::cout << "Baseline Generation TPS: " << std::fixed << std::setprecision(2) 
                  << results.baseline.generation_tps_stats.mean << "\n";
        std::cout << "Hotpatched Generation TPS: " << results.post_patch.generation_tps_stats.mean << "\n";
        std::cout << "Improvement: " << results.improvement_percent << "%\n";
        std::cout << "Effect Size (Cohen's d): " << results.generation_tps_effect_size << "\n";
        std::cout << "Statistically Significant: " << (results.generation_tps_significant ? "YES ***" : "NO") << "\n";
        std::cout << "Verdict: " << results.verdict << "\n";
    }
    
    std::cout << "\nDone.\n";
    return 0;
}
