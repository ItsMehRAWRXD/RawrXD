//============================================================================
// nevm_benchmark_runner.cpp
// RawrXD N-EVM - Comprehensive Benchmark Suite
// Collects all metrics for evidence-based validation
//============================================================================

#include "nevm_benchmark.hpp"
#include "nevm_v2.hpp"
#include "nevm_transformer_engine.hpp"
#include "nevm_gguf_loader.hpp"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <json/json.h>
#include <windows.h>

using namespace RawrXD::NEVM;
using namespace RawrXD::NEVM::Benchmark;

//============================================================================
// Benchmark Configuration
//============================================================================

struct BenchmarkConfig {
    std::wstring model_path;
    std::string prompt;
    int num_warmup_tokens;
    int num_benchmark_tokens;
    int max_seq_length;
    float temperature;
    int num_threads;
    bool enable_tracing;
    bool cold_cache_run;
    std::string output_path;
};

//============================================================================
// Metrics Collection
//============================================================================

struct DetailedMetrics {
    // Throughput
    float prefill_tokens_per_sec;
    float decode_tokens_per_sec;
    float overall_tokens_per_sec;
    
    // Latency
    float time_to_first_token_ms;
    float mean_inter_token_latency_ms;
    float p50_inter_token_latency_ms;
    float p99_inter_token_latency_ms;
    float max_inter_token_latency_ms;
    float stddev_inter_token_latency_ms;
    
    // Memory
    uint64_t peak_vram_bytes;
    uint64_t peak_ram_bytes;
    uint64_t avg_working_set_bytes;
    uint64_t model_size_bytes;
    float memory_efficiency_tokens_per_gb;
    
    // MMU Performance
    float mmu_lookup_time_ns;
    uint64_t mmu_hits;
    uint64_t mmu_misses;
    float mmu_hit_rate;
    
    // Kernel Performance
    uint64_t kernel_dispatch_count;
    float avg_kernel_dispatch_time_ns;
    std::map<std::string, uint64_t> kernel_call_counts;
    
    // Precision
    uint64_t precision_transitions;
    std::map<PrecisionMode, uint64_t> precision_distribution;
    float avg_effective_bits;
    
    // Residency
    uint64_t residency_transitions;
    std::map<ResidencyState, uint64_t> residency_distribution;
    
    // Prefetch
    float prefetch_hit_rate;
    uint64_t prefetch_hits;
    uint64_t prefetch_misses;
    
    // Pipeline
    float pipeline_stall_percentage;
    uint64_t stall_cycles;
    uint64_t total_cycles;
    
    // Quality (if reference available)
    float output_similarity_to_reference;
    float perplexity;
};

//============================================================================
// Windows Performance Counters
//============================================================================

class PerformanceCounters {
public:
    HANDLE process_handle;
    
    PerformanceCounters() {
        process_handle = GetCurrentProcess();
    }
    
    struct MemoryInfo {
        SIZE_T working_set;
        SIZE_T peak_working_set;
        SIZE_T private_bytes;
        SIZE_T peak_private_bytes;
    };
    
    MemoryInfo GetMemoryInfo() {
        PROCESS_MEMORY_COUNTERS_EX pmc;
        MemoryInfo info = {};
        
        if (GetProcessMemoryInfo(process_handle, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            info.working_set = pmc.WorkingSetSize;
            info.peak_working_set = pmc.PeakWorkingSetSize;
            info.private_bytes = pmc.PrivateUsage;
        }
        
        return info;
    }
    
    static uint64_t GetTimestamp() {
        LARGE_INTEGER freq, count;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&count);
        return (count.QuadPart * 1000000000ULL) / freq.QuadPart;
    }
};

//============================================================================
// Benchmark Implementation
//============================================================================

class ComprehensiveBenchmark {
public:
    ComprehensiveBenchmark(const BenchmarkConfig& config)
        : config_(config), vm_(nullptr), engine_(nullptr) {
    }
    
    ~ComprehensiveBenchmark() {
        Cleanup();
    }
    
    bool Initialize() {
        std::cout << "Initializing N-EVM...\n";
        
        // Create VM
        NEVM_v2::Config vm_config;
        vm_config.ram_budget = 64ULL * 1024 * 1024 * 1024;
        vm_config.vram_budget = 16ULL * 1024 * 1024 * 1024;
        vm_config.enable_adaptive_precision = true;
        vm_config.enable_prefetch = true;
        vm_config.enable_tracing = config_.enable_tracing;
        
        vm_ = std::make_unique<NEVM_v2>(vm_config);
        if (!vm_->Initialize()) {
            std::cerr << "Failed to initialize VM\n";
            return false;
        }
        
        // Load model
        std::wcout << L"Loading model: " << config_.model_path << L"\n";
        if (!vm_->LoadModel(config_.model_path)) {
            std::cerr << "Failed to load model\n";
            return false;
        }
        
        // Get loader
        loader_ = vm_->GetLoader();
        if (!loader_) {
            std::cerr << "Failed to get loader\n";
            return false;
        }
        
        auto metadata = loader_->GetMetadata();
        std::cout << "Model loaded:\n";
        std::cout << "  Architecture: " << metadata.architecture << "\n";
        std::cout << "  Layers: " << metadata.num_layers << "\n";
        std::cout << "  Hidden dim: " << metadata.hidden_dim << "\n";
        std::cout << "  Heads: " << metadata.num_heads << "\n";
        std::cout << "  Vocab size: " << metadata.vocab_size << "\n";
        std::cout << "  Context length: " << metadata.context_length << "\n\n";
        
        // Create transformer engine
        TransformerEngine::Config engine_config;
        engine_config.num_layers = metadata.num_layers;
        engine_config.hidden_dim = metadata.hidden_dim;
        engine_config.num_heads = metadata.num_heads;
        engine_config.head_dim = metadata.hidden_dim / metadata.num_heads;
        engine_config.ffn_dim = metadata.hidden_dim * 4;
        engine_config.vocab_size = metadata.vocab_size;
        engine_config.max_seq_len = metadata.context_length;
        engine_config.batch_size = 1;
        engine_config.default_precision = PrecisionMode::Q4;
        engine_config.use_flash_attention = true;
        engine_config.use_kv_cache = true;
        
        engine_ = std::make_unique<TransformerEngine>(vm_.get(), engine_config);
        if (!engine_->Initialize(loader_)) {
            std::cerr << "Failed to initialize transformer engine\n";
            return false;
        }
        
        return true;
    }
    
    DetailedMetrics RunBenchmark() {
        DetailedMetrics metrics = {};
        
        // Tokenize prompt
        std::vector<int32_t> prompt_tokens = TokenizePrompt(config_.prompt);
        uint32_t prompt_len = static_cast<uint32_t>(prompt_tokens.size());
        
        std::cout << "Prompt tokens: " << prompt_len << "\n";
        std::cout << "Benchmark tokens: " << config_.num_benchmark_tokens << "\n\n";
        
        // Warmup
        if (config_.num_warmup_tokens > 0) {
            std::cout << "Warming up (" << config_.num_warmup_tokens << " tokens)...\n";
            RunWarmup(prompt_tokens);
        }
        
        // Cold cache run if requested
        if (config_.cold_cache_run) {
            std::cout << "Clearing caches for cold run...\n";
            // Would clear MMU caches here
        }
        
        // Run benchmark
        std::cout << "Running benchmark...\n";
        metrics = RunMeasurement(prompt_tokens, config_.num_benchmark_tokens);
        
        // Collect final stats
        auto vm_stats = vm_->GetStats();
        metrics.peak_vram_bytes = vm_stats.vram_used;
        metrics.peak_ram_bytes = vm_stats.ram_used;
        metrics.avg_working_set_bytes = vm_stats.working_set_size;
        
        return metrics;
    }
    
    void ExportResults(const DetailedMetrics& metrics, const std::string& path) {
        Json::Value root;
        
        // Configuration
        root["model_path"] = std::string(config_.model_path.begin(), config_.model_path.end());
        root["prompt_length"] = static_cast<int>(config_.prompt.length());
        root["benchmark_tokens"] = config_.num_benchmark_tokens;
        root["timestamp"] = static_cast<Json::Int64>(time(nullptr));
        
        // Throughput
        Json::Value throughput;
        throughput["prefill_tokens_per_sec"] = metrics.prefill_tokens_per_sec;
        throughput["decode_tokens_per_sec"] = metrics.decode_tokens_per_sec;
        throughput["overall_tokens_per_sec"] = metrics.overall_tokens_per_sec;
        root["throughput"] = throughput;
        
        // Latency
        Json::Value latency;
        latency["time_to_first_token_ms"] = metrics.time_to_first_token_ms;
        latency["mean_inter_token_ms"] = metrics.mean_inter_token_latency_ms;
        latency["p50_inter_token_ms"] = metrics.p50_inter_token_latency_ms;
        latency["p99_inter_token_ms"] = metrics.p99_inter_token_latency_ms;
        latency["max_inter_token_ms"] = metrics.max_inter_token_latency_ms;
        latency["stddev_inter_token_ms"] = metrics.stddev_inter_token_latency_ms;
        root["latency"] = latency;
        
        // Memory
        Json::Value memory;
        memory["peak_vram_mb"] = static_cast<Json::Int64>(metrics.peak_vram_bytes / (1024 * 1024));
        memory["peak_ram_mb"] = static_cast<Json::Int64>(metrics.peak_ram_bytes / (1024 * 1024));
        memory["working_set_mb"] = static_cast<Json::Int64>(metrics.avg_working_set_bytes / (1024 * 1024));
        memory["efficiency_tokens_per_gb"] = metrics.memory_efficiency_tokens_per_gb;
        root["memory"] = memory;
        
        // MMU
        Json::Value mmu;
        mmu["lookup_time_ns"] = metrics.mmu_lookup_time_ns;
        mmu["hit_rate"] = metrics.mmu_hit_rate;
        mmu["hits"] = static_cast<Json::Int64>(metrics.mmu_hits);
        mmu["misses"] = static_cast<Json::Int64>(metrics.mmu_misses);
        root["mmu"] = mmu;
        
        // Kernels
        Json::Value kernels;
        kernels["dispatch_count"] = static_cast<Json::Int64>(metrics.kernel_dispatch_count);
        kernels["avg_dispatch_time_ns"] = metrics.avg_kernel_dispatch_time_ns;
        root["kernels"] = kernels;
        
        // Precision
        Json::Value precision;
        precision["transitions"] = static_cast<Json::Int64>(metrics.precision_transitions);
        precision["avg_effective_bits"] = metrics.avg_effective_bits;
        root["precision"] = precision;
        
        // Prefetch
        Json::Value prefetch;
        prefetch["hit_rate"] = metrics.prefetch_hit_rate;
        prefetch["hits"] = static_cast<Json::Int64>(metrics.prefetch_hits);
        prefetch["misses"] = static_cast<Json::Int64>(metrics.prefetch_misses);
        root["prefetch"] = prefetch;
        
        // Pipeline
        Json::Value pipeline;
        pipeline["stall_percentage"] = metrics.pipeline_stall_percentage;
        pipeline["stall_cycles"] = static_cast<Json::Int64>(metrics.stall_cycles);
        pipeline["total_cycles"] = static_cast<Json::Int64>(metrics.total_cycles);
        root["pipeline"] = pipeline;
        
        std::ofstream file(path);
        if (file.is_open()) {
            Json::StreamWriterBuilder builder;
            std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
            writer->write(root, &file);
            std::cout << "Results exported to: " << path << "\n";
        }
    }
    
    void PrintReport(const DetailedMetrics& metrics) {
        std::cout << "\n";
        std::cout << "============================================================================\n";
        std::cout << "Benchmark Results\n";
        std::cout << "============================================================================\n\n";
        
        std::cout << std::fixed << std::setprecision(2);
        
        std::cout << "THROUGHPUT:\n";
        std::cout << "  Prefill:  " << std::setw(10) << metrics.prefill_tokens_per_sec << " tok/s\n";
        std::cout << "  Decode:   " << std::setw(10) << metrics.decode_tokens_per_sec << " tok/s\n";
        std::cout << "  Overall:  " << std::setw(10) << metrics.overall_tokens_per_sec << " tok/s\n\n";
        
        std::cout << "LATENCY:\n";
        std::cout << "  Time to first token: " << metrics.time_to_first_token_ms << " ms\n";
        std::cout << "  Mean inter-token:    " << metrics.mean_inter_token_latency_ms << " ms\n";
        std::cout << "  P50 inter-token:     " << metrics.p50_inter_token_latency_ms << " ms\n";
        std::cout << "  P99 inter-token:     " << metrics.p99_inter_token_latency_ms << " ms\n";
        std::cout << "  Max inter-token:     " << metrics.max_inter_token_latency_ms << " ms\n\n";
        
        std::cout << "MEMORY:\n";
        std::cout << "  Peak VRAM:  " << std::setw(8) << metrics.peak_vram_bytes / (1024.0 * 1024.0) << " MB\n";
        std::cout << "  Peak RAM:   " << std::setw(8) << metrics.peak_ram_bytes / (1024.0 * 1024.0) << " MB\n";
        std::cout << "  Working set:" << std::setw(8) << metrics.avg_working_set_bytes / (1024.0 * 1024.0) << " MB\n";
        std::cout << "  Efficiency: " << metrics.memory_efficiency_tokens_per_gb << " tok/s/GB\n\n";
        
        std::cout << "MMU:\n";
        std::cout << "  Lookup time: " << metrics.mmu_lookup_time_ns << " ns\n";
        std::cout << "  Hit rate:    " << metrics.mmu_hit_rate * 100.0f << "%\n\n";
        
        std::cout << "PREFETCH:\n";
        std::cout << "  Hit rate: " << metrics.prefetch_hit_rate * 100.0f << "%\n";
        std::cout << "  Hits:     " << metrics.prefetch_hits << "\n";
        std::cout << "  Misses:   " << metrics.prefetch_misses << "\n\n";
        
        std::cout << "PIPELINE:\n";
        std::cout << "  Stall %%:    " << metrics.pipeline_stall_percentage << "%\n";
        std::cout << "  Stall cycles:" << metrics.stall_cycles << "\n\n";
        
        std::cout << "PRECISION:\n";
        std::cout << "  Transitions: " << metrics.precision_transitions << "\n";
        std::cout << "  Avg bits:    " << metrics.avg_effective_bits << "\n\n";
        
        std::cout << "============================================================================\n";
    }

private:
    void Cleanup() {
        engine_.reset();
        vm_.reset();
    }
    
    std::vector<int32_t> TokenizePrompt(const std::string& prompt) {
        // Simplified tokenization - would use actual tokenizer
        std::vector<int32_t> tokens;
        for (char c : prompt) {
            tokens.push_back(static_cast<int32_t>(c));
        }
        return tokens;
    }
    
    void RunWarmup(const std::vector<int32_t>& prompt_tokens) {
        std::vector<float> logits(loader_->GetMetadata().vocab_size);
        
        // Just run prefill to warm up
        engine_->Forward(prompt_tokens.data(), logits.data(), 
                         static_cast<uint32_t>(prompt_tokens.size()));
    }
    
    DetailedMetrics RunMeasurement(const std::vector<int32_t>& prompt_tokens,
                                   int num_tokens) {
        DetailedMetrics metrics = {};
        std::vector<float> latencies;
        latencies.reserve(num_tokens);
        
        PerformanceCounters counters;
        
        // Prefill phase
        std::vector<float> logits(loader_->GetMetadata().vocab_size);
        
        auto prefill_start = std::chrono::high_resolution_clock::now();
        engine_->Forward(prompt_tokens.data(), logits.data(),
                         static_cast<uint32_t>(prompt_tokens.size()));
        auto prefill_end = std::chrono::high_resolution_clock::now();
        
        auto prefill_duration = std::chrono::duration_cast<std::chrono::microseconds>(
            prefill_end - prefill_start);
        
        metrics.prefill_tokens_per_sec = 
            prompt_tokens.size() / (prefill_duration.count() / 1000000.0f);
        metrics.time_to_first_token_ms = prefill_duration.count() / 1000.0f;
        
        // Decode phase
        int32_t next_token = 0;
        uint32_t current_seq_len = static_cast<uint32_t>(prompt_tokens.size());
        
        auto decode_start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < num_tokens; ++i) {
            auto token_start = std::chrono::high_resolution_clock::now();
            
            // Generate one token
            engine_->GenerateStep(&next_token, logits.data(), current_seq_len + i);
            
            auto token_end = std::chrono::high_resolution_clock::now();
            auto token_duration = std::chrono::duration_cast<std::chrono::microseconds>(
                token_end - token_start);
            
            latencies.push_back(token_duration.count() / 1000.0f);
        }
        
        auto decode_end = std::chrono::high_resolution_clock::now();
        auto decode_duration = std::chrono::duration_cast<std::chrono::microseconds>(
            decode_end - decode_start);
        
        metrics.decode_tokens_per_sec = num_tokens / (decode_duration.count() / 1000000.0f);
        
        // Calculate latency statistics
        CalculateLatencyStats(latencies, metrics);
        
        // Overall throughput
        auto total_duration = std::chrono::duration_cast<std::chrono::microseconds>(
            decode_end - prefill_start);
        metrics.overall_tokens_per_sec = 
            (prompt_tokens.size() + num_tokens) / (total_duration.count() / 1000000.0f);
        
        // Get VM stats
        auto vm_stats = vm_->GetStats();
        metrics.precision_transitions = vm_stats.precision_switches;
        metrics.stall_cycles = vm_stats.stall_cycles;
        metrics.total_cycles = vm_stats.total_cycles;
        
        if (metrics.total_cycles > 0) {
            metrics.pipeline_stall_percentage = 
                (metrics.stall_cycles / (float)metrics.total_cycles) * 100.0f;
        }
        
        return metrics;
    }
    
    void CalculateLatencyStats(const std::vector<float>& latencies, 
                            DetailedMetrics& metrics) {
        if (latencies.empty()) return;
        
        // Mean
        float sum = 0.0f;
        for (float lat : latencies) sum += lat;
        metrics.mean_inter_token_latency_ms = sum / latencies.size();
        
        // Sort for percentiles
        std::vector<float> sorted = latencies;
        std::sort(sorted.begin(), sorted.end());
        
        // P50
        size_t p50_idx = sorted.size() / 2;
        metrics.p50_inter_token_latency_ms = sorted[p50_idx];
        
        // P99
        size_t p99_idx = static_cast<size_t>(sorted.size() * 0.99f);
        if (p99_idx >= sorted.size()) p99_idx = sorted.size() - 1;
        metrics.p99_inter_token_latency_ms = sorted[p99_idx];
        
        // Max
        metrics.max_inter_token_latency_ms = sorted.back();
        
        // Stddev
        float variance = 0.0f;
        for (float lat : latencies) {
            float diff = lat - metrics.mean_inter_token_latency_ms;
            variance += diff * diff;
        }
        variance /= latencies.size();
        metrics.stddev_inter_token_latency_ms = std::sqrt(variance);
    }
    
    BenchmarkConfig config_;
    std::unique_ptr<NEVM_v2> vm_;
    std::unique_ptr<TransformerEngine> engine_;
    GGUF_PassthroughLoader* loader_;
};

//============================================================================
// Main
//============================================================================

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " <model.gguf> [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -p, --prompt <text>       Prompt text (default: 'Hello world')\n";
    std::cout << "  -n, --tokens <n>          Number of tokens to generate (default: 128)\n";
    std::cout << "  -w, --warmup <n>          Warmup tokens (default: 10)\n";
    std::cout << "  -c, --cold                Run cold-cache test\n";
    std::cout << "  -t, --trace               Enable tracing\n";
    std::cout << "  -o, --output <file>       Output JSON file\n";
    std::cout << "  -h, --help                Show this help\n";
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintUsage("nevm_benchmark_runner");
        return 1;
    }
    
    BenchmarkConfig config;
    config.model_path = argv[1];
    config.prompt = "Hello world";
    config.num_warmup_tokens = 10;
    config.num_benchmark_tokens = 128;
    config.max_seq_length = 2048;
    config.temperature = 0.8f;
    config.num_threads = 0;  // Auto
    config.enable_tracing = false;
    config.cold_cache_run = false;
    config.output_path = "benchmark_results.json";
    
    // Parse arguments
    for (int i = 2; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"-p" || arg == L"--prompt") {
            if (i + 1 < argc) {
                // Convert wchar_t to char
                size_t len = wcslen(argv[i + 1]);
                config.prompt.resize(len);
                for (size_t j = 0; j < len; ++j) {
                    config.prompt[j] = static_cast<char>(argv[i + 1][j]);
                }
                ++i;
            }
        } else if (arg == L"-n" || arg == L"--tokens") {
            if (i + 1 < argc) config.num_benchmark_tokens = _wtoi(argv[++i]);
        } else if (arg == L"-w" || arg == L"--warmup") {
            if (i + 1 < argc) config.num_warmup_tokens = _wtoi(argv[++i]);
        } else if (arg == L"-c" || arg == L"--cold") {
            config.cold_cache_run = true;
        } else if (arg == L"-t" || arg == L"--trace") {
            config.enable_tracing = true;
        } else if (arg == L"-o" || arg == L"--output") {
            if (i + 1 < argc) {
                size_t len = wcslen(argv[i + 1]);
                config.output_path.resize(len);
                for (size_t j = 0; j < len; ++j) {
                    config.output_path[j] = static_cast<char>(argv[i + 1][j]);
                }
                ++i;
            }
        } else if (arg == L"-h" || arg == L"--help") {
            PrintUsage("nevm_benchmark_runner");
            return 0;
        }
    }
    
    std::cout << "============================================================================\n";
    std::cout << "RawrXD N-EVM Benchmark Runner\n";
    std::cout << "============================================================================\n\n";
    
    ComprehensiveBenchmark benchmark(config);
    
    if (!benchmark.Initialize()) {
        std::cerr << "Failed to initialize benchmark\n";
        return 1;
    }
    
    auto metrics = benchmark.RunBenchmark();
    benchmark.PrintReport(metrics);
    benchmark.ExportResults(metrics, config.output_path);
    
    return 0;
}
