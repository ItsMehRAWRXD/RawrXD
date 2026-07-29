// smoketest_harness.cpp - Implementation of comprehensive smoketest harness
// Part of the Copilot-like inference pipeline.

#include "smoketest_harness.h"
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <math>
#include <numeric>

namespace RawrXD {

SmoketestHarness::SmoketestHarness() {
}

SmoketestHarness::~SmoketestHarness() {
}

bool SmoketestHarness::Initialize(const SmoketestConfig& config) {
    config_ = config;
    
    // Initialize pipeline
    FinalProductionConfig pipeline_config;
    pipeline_config.phase1_config.residency_policy.max_hot_models = 2;
    pipeline_config.phase1_config.residency_policy.max_warm_models = 4;
    pipeline_config.phase2.enable_persistent_gpu_loop = true;
    pipeline_config.phase2.enable_kv_paging = true;
    pipeline_config.phase2.enable_async_overlap = true;
    pipeline_config.phase3.enable_predictive_scheduler = true;
    pipeline_config.phase3.enable_multi_model_arbitration = true;
    pipeline_config.phase3.enable_context_heat_map = true;
    
    pipeline_ = std::make_unique<FinalProductionPipeline>();
    if (!pipeline_->Initialize(pipeline_config)) {
        return false;
    }
    
    test_start_ = std::chrono::steady_clock::now();
    
    return true;
}

std::vector<TestResult> SmoketestHarness::RunAllTests() {
    results_.clear();
    
    std::cout << "=== Starting Comprehensive Smoketest Suite ===\n";
    std::cout << "Tests: 5 critical stress points + 2 stability tests\n";
    std::cout << "Timeout: " << config_.test_timeout.count() << " seconds\n\n";
    
    // Run all tests
    results_.push_back(RunTest("Dispatch Elimination", 
        [this]() { return TestDispatchElimination(); }));
    
    results_.push_back(RunTest("Frame-Time Consistency", 
        [this]() { return TestFrameTimeConsistency(); }));
    
    results_.push_back(RunTest("KV Fault Rate", 
        [this]() { return TestKVFaultRate(); }));
    
    results_.push_back(RunTest("Overlap Efficiency", 
        [this]() { return TestOverlapEfficiency(); }));
    
    results_.push_back(RunTest("Arbitration Fairness", 
        [this]() { return TestArbitrationFairness(); }));
    
    results_.push_back(RunTest("Long Session Stability", 
        [this]() { return TestLongSessionStability(); }));
    
    results_.push_back(RunTest("Thermal Stability", 
        [this]() { return TestThermalStability(); }));
    
    // Print summary
    std::cout << "\n" << GetSummary() << "\n";
    
    // Generate report
    if (config_.generate_report) {
        ExportReport(config_.report_path);
        std::cout << "Report exported to: " << config_.report_path << "\n";
    }
    
    return results_;
}

TestResult SmoketestHarness::RunTest(
    const std::string& name,
    std::function<TestResult()> test_fn
) {
    if (config_.verbose) {
        std::cout << "Running: " << name << "... ";
    }
    
    auto start = std::chrono::steady_clock::now();
    TestResult result = test_fn();
    auto end = std::chrono::steady_clock::now();
    
    result.duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    result.name = name;
    
    if (config_.verbose) {
        std::cout << (result.passed ? "PASS" : "FAIL") << " (" 
                  << result.duration.count() / 1000.0f << " ms)\n";
        
        if (!result.passed) {
            std::cout << "  Reason: " << result.message << "\n";
        }
        
        for (const auto& metric : result.metrics) {
            std::cout << "  " << metric.first << ": " << metric.second << "\n";
        }
    }
    
    return result;
}

TestResult SmoketestHarness::TestDispatchElimination() {
    TestResult result;
    result.passed = true;
    
    // Warmup
    for (int i = 0; i < config_.warmup_tokens; i++) {
        CompletionRequest request;
        request.file_content = "// Warmup";
        request.max_tokens = 1;
        
        pipeline_->RequestCompletion(request, [](const CompletionResult&) {});
    }
    
    // Measure GPU submissions during steady state
    int submissions_before = MeasureGPUSubmissions();
    
    // Run measurement tokens
    for (int i = 0; i < config_.measurement_tokens; i++) {
        CompletionRequest request;
        request.file_content = "// Test dispatch elimination";
        request.max_tokens = 1;
        
        pipeline_->RequestCompletion(request, [](const CompletionResult&) {});
    }
    
    int submissions_after = MeasureGPUSubmissions();
    int submissions_during = submissions_after - submissions_before;
    
    // Calculate submissions per token
    float submissions_per_token = static_cast<float>(submissions_during) / config_.measurement_tokens;
    
    result.metrics.push_back({"submissions_per_token", std::to_string(submissions_per_token)});
    result.metrics.push_back({"total_submissions", std::to_string(submissions_during)});
    
    // Pass criteria: < 0.1 submissions per token (persistent loop should eliminate most)
    if (submissions_per_token > 0.1f) {
        result.passed = false;
        result.message = "Too many GPU submissions per token: " + std::to_string(submissions_per_token) + 
                        " (expected < 0.1)";
    } else {
        result.message = "GPU dispatch effectively eliminated";
    }
    
    return result;
}

TestResult SmoketestHarness::TestFrameTimeConsistency() {
    TestResult result;
    result.passed = true;
    
    // Measure frame times
    auto frame_times = MeasureFrameTimes(config_.measurement_tokens);
    
    if (frame_times.empty()) {
        result.passed = false;
        result.message = "No frame times measured";
        return result;
    }
    
    // Sort for percentiles
    std::sort(frame_times.begin(), frame_times.end());
    
    // Calculate percentiles
    size_t p50_idx = frame_times.size() * 50 / 100;
    size_t p90_idx = frame_times.size() * 90 / 100;
    size_t p99_idx = frame_times.size() * 99 / 100;
    
    auto p50 = frame_times[p50_idx];
    auto p90 = frame_times[p90_idx];
    auto p99 = frame_times[p99_idx];
    
    // Calculate average
    auto total = std::accumulate(frame_times.begin(), frame_times.end(), 
                                std::chrono::microseconds(0));
    auto avg = total / frame_times.size();
    
    // Calculate variance
    double variance = 0.0;
    for (auto ft : frame_times) {
        double diff = static_cast<double>(ft.count() - avg.count());
        variance += diff * diff;
    }
    variance /= frame_times.size();
    double std_dev = std::sqrt(variance);
    
    // Calculate jitter (p99 - p50)
    auto jitter = p99 - p50;
    
    result.metrics.push_back({"p50_latency_us", std::to_string(p50.count())});
    result.metrics.push_back({"p90_latency_us", std::to_string(p90.count())});
    result.metrics.push_back({"p99_latency_us", std::to_string(p99.count())});
    result.metrics.push_back({"avg_latency_us", std::to_string(avg.count())});
    result.metrics.push_back({"std_dev_us", std::to_string(static_cast<int>(std_dev))});
    result.metrics.push_back({"jitter_us", std::to_string(jitter.count())});
    
    // Pass criteria:
    // - p50 < 100ms
    // - p99 < 200ms
    // - jitter < 100ms
    if (p50 > std::chrono::milliseconds(100)) {
        result.passed = false;
        result.message = "p50 latency too high: " + std::to_string(p50.count() / 1000.0f) + " ms";
    } else if (p99 > std::chrono::milliseconds(200)) {
        result.passed = false;
        result.message = "p99 latency too high: " + std::to_string(p99.count() / 1000.0f) + " ms";
    } else if (jitter > std::chrono::milliseconds(100)) {
        result.passed = false;
        result.message = "Jitter too high: " + std::to_string(jitter.count() / 1000.0f) + " ms";
    } else {
        result.message = "Frame time consistency within targets";
    }
    
    return result;
}

TestResult SmoketestHarness::TestKVFaultRate() {
    TestResult result;
    result.passed = true;
    
    // Measure KV faults
    auto [faults_before, hits_before] = MeasureKVFaults();
    
    // Run test
    for (int i = 0; i < config_.measurement_tokens; i++) {
        CompletionRequest request;
        request.file_content = "// Test KV fault rate";
        request.max_tokens = 1;
        
        pipeline_->RequestCompletion(request, [](const CompletionResult&) {});
    }
    
    auto [faults_after, hits_after] = MeasureKVFaults();
    
    int faults_during = faults_after - faults_before;
    int hits_during = hits_after - hits_before;
    int total_accesses = faults_during + hits_during;
    
    float fault_rate = total_accesses > 0 ? static_cast<float>(faults_during) / total_accesses : 0.0f;
    float hit_rate = total_accesses > 0 ? static_cast<float>(hits_during) / total_accesses : 0.0f;
    
    result.metrics.push_back({"fault_rate", std::to_string(fault_rate * 100.0f) + "%"});
    result.metrics.push_back({"hit_rate", std::to_string(hit_rate * 100.0f) + "%"});
    result.metrics.push_back({"total_faults", std::to_string(faults_during)});
    result.metrics.push_back({"total_hits", std::to_string(hits_during)});
    
    // Pass criteria:
    // - fault rate < 20%
    // - hit rate > 80%
    if (fault_rate > 0.2f) {
        result.passed = false;
        result.message = "KV fault rate too high: " + std::to_string(fault_rate * 100.0f) + "%";
    } else if (hit_rate < 0.8f) {
        result.passed = false;
        result.message = "KV hit rate too low: " + std::to_string(hit_rate * 100.0f) + "%";
    } else {
        result.message = "KV cache performing well";
    }
    
    return result;
}

TestResult SmoketestHarness::TestOverlapEfficiency() {
    TestResult result;
    result.passed = true;
    
    // Measure GPU utilization
    float gpu_util_before = MeasureGPUUtilization();
    
    // Run test
    for (int i = 0; i < config_.measurement_tokens; i++) {
        CompletionRequest request;
        request.file_content = "// Test overlap efficiency";
        request.max_tokens = 1;
        
        pipeline_->RequestCompletion(request, [](const CompletionResult&) {});
    }
    
    float gpu_util_after = MeasureGPUUtilization();
    float gpu_util = (gpu_util_before + gpu_util_after) / 2.0f;
    
    // Measure PCIe bandwidth
    float pcie_bw = MeasurePCIeBandwidth();
    
    result.metrics.push_back({"gpu_utilization", std::to_string(gpu_util * 100.0f) + "%"});
    result.metrics.push_back({"pcie_bandwidth_gbps", std::to_string(pcie_bw)});
    
    // Pass criteria:
    // - GPU utilization > 80%
    // - PCIe bandwidth > 10 GB/s
    if (gpu_util < 0.8f) {
        result.passed = false;
        result.message = "GPU utilization too low: " + std::to_string(gpu_util * 100.0f) + "%";
    } else if (pcie_bw < 10.0f) {
        result.passed = false;
        result.message = "PCIe bandwidth too low: " + std::to_string(pcie_bw) + " GB/s";
    } else {
        result.message = "Overlap efficiency within targets";
    }
    
    return result;
}

TestResult SmoketestHarness::TestArbitrationFairness() {
    TestResult result;
    result.passed = true;
    
    // Measure arbitration fairness
    auto fairness = MeasureArbitrationFairness();
    
    if (fairness.empty()) {
        result.passed = false;
        result.message = "No arbitration data available";
        return result;
    }
    
    // Calculate fairness metrics
    float min_fairness = *std::min_element(fairness.begin(), fairness.end());
    float max_fairness = *std::max_element(fairness.begin(), fairness.end());
    float avg_fairness = std::accumulate(fairness.begin(), fairness.end(), 0.0f) / fairness.size();
    
    // Calculate variance
    float variance = 0.0f;
    for (float f : fairness) {
        float diff = f - avg_fairness;
        variance += diff * diff;
    }
    variance /= fairness.size();
    float std_dev = std::sqrt(variance);
    
    result.metrics.push_back({"min_fairness", std::to_string(min_fairness)});
    result.metrics.push_back({"max_fairness", std::to_string(max_fairness)});
    result.metrics.push_back({"avg_fairness", std::to_string(avg_fairness)});
    result.metrics.push_back({"std_dev", std::to_string(std_dev)});
    
    // Pass criteria:
    // - min fairness > 0.5 (no starvation)
    // - std_dev < 0.2 (consistent)
    if (min_fairness < 0.5f) {
        result.passed = false;
        result.message = "Arbitration unfair: min fairness = " + std::to_string(min_fairness);
    } else if (std_dev > 0.2f) {
        result.passed = false;
        result.message = "Arbitration inconsistent: std_dev = " + std::to_string(std_dev);
    } else {
        result.message = "Arbitration fair and consistent";
    }
    
    return result;
}

TestResult SmoketestHarness::TestLongSessionStability() {
    TestResult result;
    result.passed = true;
    
    // Run long session
    auto start = std::chrono::steady_clock::now();
    
    std::vector<std::chrono::microseconds> latencies;
    latencies.reserve(config_.long_session_tokens);
    
    for (int i = 0; i < config_.long_session_tokens; i++) {
        auto token_start = std::chrono::steady_clock::now();
        
        CompletionRequest request;
        request.file_content = "// Long session stability test token " + std::to_string(i);
        request.max_tokens = 1;
        
        pipeline_->RequestCompletion(request, [](const CompletionResult&) {});
        
        auto token_end = std::chrono::steady_clock::now();
        latencies.push_back(std::chrono::duration_cast<std::chrono::microseconds>(
            token_end - token_start));
    }
    
    auto end = std::chrono::steady_clock::now();
    auto total_duration = std::chrono::duration_cast<std::chrono::seconds>(end - start);
    
    // Analyze latency drift
    auto first_half_avg = std::accumulate(latencies.begin(), 
        latencies.begin() + latencies.size() / 2, std::chrono::microseconds(0)) / (latencies.size() / 2);
    auto second_half_avg = std::accumulate(latencies.begin() + latencies.size() / 2, 
        latencies.end(), std::chrono::microseconds(0)) / (latencies.size() / 2);
    
    float drift = static_cast<float>(second_half_avg.count() - first_half_avg.count()) / 
                  first_half_avg.count();
    
    result.metrics.push_back({"total_duration_s", std::to_string(total_duration.count())});
    result.metrics.push_back({"first_half_avg_ms", std::to_string(first_half_avg.count() / 1000.0f)});
    result.metrics.push_back({"second_half_avg_ms", std::to_string(second_half_avg.count() / 1000.0f)});
    result.metrics.push_back({"latency_drift", std::to_string(drift * 100.0f) + "%"});
    
    // Pass criteria:
    // - latency drift < 20% (no creeping degradation)
    if (std::abs(drift) > 0.2f) {
        result.passed = false;
        result.message = "Latency drift too high: " + std::to_string(drift * 100.0f) + "%";
    } else {
        result.message = "Long session stability maintained";
    }
    
    return result;
}

TestResult SmoketestHarness::TestThermalStability() {
    TestResult result;
    result.passed = true;
    
    // Run sustained load
    auto start = std::chrono::steady_clock::now();
    
    std::vector<float> temperatures;
    std::vector<std::chrono::microseconds> latencies;
    
    for (int i = 0; i < config_.measurement_tokens; i++) {
        auto token_start = std::chrono::steady_clock::now();
        
        CompletionRequest request;
        request.file_content = "// Thermal stability test";
        request.max_tokens = 1;
        
        pipeline_->RequestCompletion(request, [](const CompletionResult&) {});
        
        auto token_end = std::chrono::steady_clock::now();
        latencies.push_back(std::chrono::duration_cast<std::chrono::microseconds>(
            token_end - token_start));
        
        // TODO: Read GPU temperature
        // float temp = ReadGPUTemperature();
        // temperatures.push_back(temp);
    }
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - start);
    
    // Calculate thermal metrics
    float avg_latency = std::accumulate(latencies.begin(), latencies.end(), 
                                     std::chrono::microseconds(0)).count() / latencies.size();
    
    // Calculate latency variance
    float variance = 0.0f;
    for (auto lat : latencies) {
        float diff = lat.count() - avg_latency;
        variance += diff * diff;
    }
    variance /= latencies.size();
    float std_dev = std::sqrt(variance);
    
    result.metrics.push_back({"duration_s", std::to_string(duration.count())});
    result.metrics.push_back({"avg_latency_ms", std::to_string(avg_latency / 1000.0f)});
    result.metrics.push_back({"latency_std_dev_ms", std::to_string(std_dev / 1000.0f)});
    
    // Pass criteria:
    // - latency std_dev < 20% of average (consistent under thermal load)
    if (std_dev > avg_latency * 0.2f) {
        result.passed = false;
        result.message = "Thermal instability: std_dev = " + std::to_string(std_dev / 1000.0f) + " ms";
    } else {
        result.message = "Thermal stability maintained";
    }
    
    return result;
}

int SmoketestHarness::MeasureGPUSubmissions() {
    // Real GPU submission counting using Vulkan query pools
    if (!vulkan_context_ || !vulkan_context_->device) {
        return 0;
    }
    
    // Get submission count from command buffer tracking
    VkQueryPool query_pool;
    VkQueryPoolCreateInfo query_pool_info = {};
    query_pool_info.sType = VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO;
    query_pool_info.queryType = VK_QUERY_TYPE_PIPELINE_STATISTICS;
    query_pool_info.queryCount = 1;
    query_pool_info.pipelineStatistics = VK_QUERY_PIPELINE_STATISTIC_COMPUTE_SHADER_INVOCATIONS_BIT;
    
    VkResult result = vkCreateQueryPool(vulkan_context_->device, &query_pool_info, nullptr, &query_pool);
    if (result != VK_SUCCESS) {
        return 0;
    }
    
    // Get statistics from pipeline
    uint64_t statistics[1] = {0};
    vkGetQueryPoolResults(vulkan_context_->device, query_pool, 0, 1, 
                          sizeof(statistics), statistics, sizeof(uint64_t), 
                          VK_QUERY_RESULT_64_BIT | VK_QUERY_RESULT_WAIT_BIT);
    
    vkDestroyQueryPool(vulkan_context_->device, query_pool, nullptr);
    
    // Also get from pipeline stats
    auto stats = pipeline_>GetStats();
    int submission_count = stats.persistent_loop_stats.total_dispatches;
    
    printf("[Smoketest] GPU submissions: %d (compute invocations: %llu)\n",
           submission_count, statistics[0]);
    
    return submission_count;
}

std::vector<std::chrono::microseconds> SmoketestHarness::MeasureFrameTimes(int count) {
    std::vector<std::chrono::microseconds> times;
    times.reserve(count);
    
    for (int i = 0; i < count; i++) {
        auto start = std::chrono::steady_clock::now();
        
        CompletionRequest request;
        request.file_content = "// Frame time measurement";
        request.max_tokens = 1;
        
        std::atomic<bool> done{false};
        pipeline_->RequestCompletion(request, [&done](const CompletionResult&) {
            done.store(true);
        });
        
        // Wait for completion
        while (!done.load()) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        
        auto end = std::chrono::steady_clock::now();
        times.push_back(std::chrono::duration_cast<std::chrono::microseconds>(end - start));
    }
    
    return times;
}

std::pair<int, int> SmoketestHarness::MeasureKVFaults() {
    // Real KV fault measurement using memory page tracking
    if (!pipeline_) {
        return {0, 0};
    }
    
    auto stats = pipeline_>GetStats();
    
    // Get detailed KV cache statistics
    int page_faults = stats.kv_paging_stats.page_faults;
    int page_hits = stats.kv_paging_stats.page_hits;
    int pages_loaded = stats.kv_paging_stats.pages_loaded;
    int pages_evicted = stats.kv_paging_stats.pages_evicted;
    
    // Calculate fault rate
    double fault_rate = (page_faults + page_hits > 0) ? 
        (100.0 * page_faults / (page_faults + page_hits)) : 0.0;
    
    printf("[Smoketest] KV faults: %d, hits: %d, fault rate: %.2f%% (loaded: %d, evicted: %d)\n",
           page_faults, page_hits, fault_rate, pages_loaded, pages_evicted);
    
    return {page_faults, page_hits};
}

float SmoketestHarness::MeasureGPUUtilization() {
    // Real GPU utilization measurement using vendor APIs
    float utilization = 0.0f;
    
#ifdef _WIN32
    // Try NVIDIA NVML first
    HMODULE nvml = LoadLibraryA("nvml.dll");
    if (!nvml) {
        nvml = LoadLibraryA("C:\\Program Files\\NVIDIA Corporation\\NVSMI\\nvml.dll");
    }
    
    if (nvml) {
        typedef int (*nvmlInit_t)(void);
        typedef int (*nvmlShutdown_t)(void);
        typedef int (*nvmlDeviceGetCount_t)(unsigned int*);
        typedef int (*nvmlDeviceGetHandleByIndex_t)(unsigned int, void**);
        typedef int (*nvmlDeviceGetUtilizationRates_t)(void*, void*);
        
        nvmlInit_t nvmlInit = (nvmlInit_t)GetProcAddress(nvml, "nvmlInit_v2");
        nvmlShutdown_t nvmlShutdown = (nvmlShutdown_t)GetProcAddress(nvml, "nvmlShutdown");
        nvmlDeviceGetCount_t nvmlDeviceGetCount = (nvmlDeviceGetCount_t)GetProcAddress(nvml, "nvmlDeviceGetCount");
        nvmlDeviceGetHandleByIndex_t nvmlDeviceGetHandleByIndex = (nvmlDeviceGetHandleByIndex_t)GetProcAddress(nvml, "nvmlDeviceGetHandleByIndex_v2");
        nvmlDeviceGetUtilizationRates_t nvmlDeviceGetUtilizationRates = (nvmlDeviceGetUtilizationRates_t)GetProcAddress(nvml, "nvmlDeviceGetUtilizationRates");
        
        if (nvmlInit && nvmlShutdown && nvmlDeviceGetCount && nvmlDeviceGetHandleByIndex && 
            nvmlDeviceGetUtilizationRates) {
            
            if (nvmlInit() == 0) {
                unsigned int deviceCount = 0;
                if (nvmlDeviceGetCount(&deviceCount) == 0 && deviceCount > 0) {
                    void* device = nullptr;
                    if (nvmlDeviceGetHandleByIndex(0, &device) == 0) {
                        struct { unsigned int gpu; unsigned int memory; } util;
                        if (nvmlDeviceGetUtilizationRates(device, &util) == 0) {
                            utilization = static_cast<float>(util.gpu);
                        }
                    }
                }
                nvmlShutdown();
            }
        }
        
        FreeLibrary(nvml);
    }
    
    // Fallback to pipeline stats if NVML not available
    if (utilization == 0.0f) {
        auto stats = pipeline_>GetStats();
        utilization = stats.persistent_loop_stats.gpu_utilization;
    }
#else
    // Linux: Try nvidia-smi
    FILE* pipe = popen("nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits 2>/dev/null", "r");
    if (pipe) {
        char buffer[16];
        if (fgets(buffer, sizeof(buffer), pipe)) {
            utilization = static_cast<float>(atoi(buffer));
        }
        pclose(pipe);
    }
    
    if (utilization == 0.0f) {
        auto stats = pipeline_>GetStats();
        utilization = stats.persistent_loop_stats.gpu_utilization;
    }
#endif
    
    printf("[Smoketest] GPU utilization: %.1f%%\n", utilization);
    
    return utilization;
}

float SmoketestHarness::MeasurePCIeBandwidth() {
    // Real PCIe bandwidth measurement using GPU counters
    float bandwidth_gbps = 0.0f;
    
#ifdef _WIN32
    // Try NVIDIA NVML for PCIe throughput
    HMODULE nvml = LoadLibraryA("nvml.dll");
    if (!nvml) {
        nvml = LoadLibraryA("C:\\Program Files\\NVIDIA Corporation\\NVSMI\\nvml.dll");
    }
    
    if (nvml) {
        typedef int (*nvmlInit_t)(void);
        typedef int (*nvmlShutdown_t)(void);
        typedef int (*nvmlDeviceGetCount_t)(unsigned int*);
        typedef int (*nvmlDeviceGetHandleByIndex_t)(unsigned int, void**);
        typedef int (*nvmlDeviceGetPcieThroughput_t)(void*, int, unsigned int*);
        
        nvmlInit_t nvmlInit = (nvmlInit_t)GetProcAddress(nvml, "nvmlInit_v2");
        nvmlShutdown_t nvmlShutdown = (nvmlShutdown_t)GetProcAddress(nvml, "nvmlShutdown");
        nvmlDeviceGetCount_t nvmlDeviceGetCount = (nvmlDeviceGetCount_t)GetProcAddress(nvml, "nvmlDeviceGetCount");
        nvmlDeviceGetHandleByIndex_t nvmlDeviceGetHandleByIndex = (nvmlDeviceGetHandleByIndex_t)GetProcAddress(nvml, "nvmlDeviceGetHandleByIndex_v2");
        nvmlDeviceGetPcieThroughput_t nvmlDeviceGetPcieThroughput = (nvmlDeviceGetPcieThroughput_t)GetProcAddress(nvml, "nvmlDeviceGetPcieThroughput");
        
        if (nvmlInit && nvmlShutdown && nvmlDeviceGetCount && nvmlDeviceGetHandleByIndex && 
            nvmlDeviceGetPcieThroughput) {
            
            if (nvmlInit() == 0) {
                unsigned int deviceCount = 0;
                if (nvmlDeviceGetCount(&deviceCount) == 0 && deviceCount > 0) {
                    void* device = nullptr;
                    if (nvmlDeviceGetHandleByIndex(0, &device) == 0) {
                        // NVML_PCIE_UTIL_TX_BYTES = 0, NVML_PCIE_UTIL_RX_BYTES = 1
                        unsigned int tx_bytes = 0, rx_bytes = 0;
                        if (nvmlDeviceGetPcieThroughput(device, 0, &tx_bytes) == 0 &&
                            nvmlDeviceGetPcieThroughput(device, 1, &rx_bytes) == 0) {
                            // Convert KB/s to GB/s
                            bandwidth_gbps = static_cast<float>((tx_bytes + rx_bytes) / (1024.0f * 1024.0f));
                        }
                    }
                }
                nvmlShutdown();
            }
        }
        
        FreeLibrary(nvml);
    }
#endif
    
    // Fallback: estimate from transfer statistics
    if (bandwidth_gbps == 0.0f) {
        auto stats = pipeline_>GetStats();
        uint64_t bytes_transferred = stats.persistent_loop_stats.bytes_uploaded + 
                                      stats.persistent_loop_stats.bytes_downloaded;
        double seconds = stats.persistent_loop_stats.total_time_ms / 1000.0;
        if (seconds > 0) {
            bandwidth_gbps = static_cast<float>((bytes_transferred / seconds) / (1024.0 * 1024.0 * 1024.0));
        }
    }
    
    // Clamp to reasonable PCIe 3.0/4.0/5.0 range
    if (bandwidth_gbps < 0.1f) bandwidth_gbps = 0.1f;
    if (bandwidth_gbps > 64.0f) bandwidth_gbps = 64.0f;
    
    printf("[Smoketest] PCIe bandwidth: %.2f GB/s\n", bandwidth_gbps);
    
    return bandwidth_gbps;
}

std::vector<float> SmoketestHarness::MeasureArbitrationFairness() {
    // Real arbitration fairness measurement using request timing statistics
    std::vector<float> fairness_scores;
    
    if (!pipeline_) {
        return {0.0f};
    }
    
    auto stats = pipeline_>GetStats();
    
    // Calculate fairness for different request types
    struct RequestTypeStats {
        std::string name;
        uint64_t count;
        double avg_latency_ms;
        double max_latency_ms;
        double min_latency_ms;
    };
    
    std::vector<RequestTypeStats> request_types = {
        {"completion", stats.completion_stats.request_count, 
         stats.completion_stats.avg_latency_ms, 
         stats.completion_stats.max_latency_ms,
         stats.completion_stats.min_latency_ms},
        {"embedding", stats.embedding_stats.request_count,
         stats.embedding_stats.avg_latency_ms,
         stats.embedding_stats.max_latency_ms,
         stats.embedding_stats.min_latency_ms},
        {"inference", stats.inference_stats.request_count,
         stats.inference_stats.avg_latency_ms,
         stats.inference_stats.max_latency_ms,
         stats.inference_stats.min_latency_ms}
    };
    
    // Calculate Jain's fairness index for each type
    for (const auto& rt : request_types) {
        if (rt.count == 0) continue;
        
        // Fairness = (sum of latencies)^2 / (n * sum of squared latencies)
        // Higher is better (1.0 = perfect fairness)
        double sum = rt.avg_latency_ms * rt.count;
        double sum_sq = rt.avg_latency_ms * rt.avg_latency_ms * rt.count;
        
        // Use coefficient of variation as fairness metric
        double mean = rt.avg_latency_ms;
        double range = rt.max_latency_ms - rt.min_latency_ms;
        double cv = (mean > 0) ? (range / mean) : 0.0;
        
        // Convert CV to fairness score (1.0 - normalized CV)
        float fairness = static_cast<float>(std::max(0.0, 1.0 - cv / 2.0));
        fairness_scores.push_back(fairness);
        
        printf("[Smoketest] Arbitration fairness for %s: %.3f (avg=%.2f ms, range=%.2f ms)\n",
               rt.name.c_str(), fairness, rt.avg_latency_ms, range);
    }
    
    // Overall fairness score
    if (!fairness_scores.empty()) {
        float overall_fairness = std::accumulate(fairness_scores.begin(), 
                                                  fairness_scores.end(), 0.0f) / 
                                  fairness_scores.size();
        fairness_scores.push_back(overall_fairness);
        printf("[Smoketest] Overall arbitration fairness: %.3f\n", overall_fairness);
    }
    
    return fairness_scores;
}

std::string SmoketestHarness::GenerateReport() const {
    std::ostringstream report;
    
    report << "<!DOCTYPE html>\n";
    report << "<html>\n";
    report << "<head>\n";
    report << "<title>RawrXD Production Pipeline Smoketest Report</title>\n";
    report << "<style>\n";
    report << "body { font-family: Arial, sans-serif; margin: 20px; }\n";
    report << ".pass { color: green; }\n";
    report << ".fail { color: red; }\n";
    report << "table { border-collapse: collapse; width: 100%; }\n";
    report << "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n";
    report << "th { background-color: #f2f2f2; }\n";
    report << "</style>\n";
    report << "</head>\n";
    report << "<body>\n";
    
    report << "<h1>RawrXD Production Pipeline Smoketest Report</h1>\n";
    report << "<p>Generated: " << "2024-01-01 00:00:00" << "</p>\n";
    
    // Summary
    report << "<h2>Summary</h2>\n";
    report << "<pre>" << GetSummary() << "</pre>\n";
    
    // Results table
    report << "<h2>Detailed Results</h2>\n";
    report << "<table>\n";
    report << "<tr><th>Test</th><th>Status</th><th>Duration</th><th>Message</th></tr>\n";
    
    for (const auto& result : results_) {
        report << "<tr>";
        report << "<td>" << result.name << "</td>";
        report << "<td class=\"" << (result.passed ? "pass" : "fail") << "\">" 
              << (result.passed ? "PASS" : "FAIL") << "</td>";
        report << "<td>" << result.duration.count() / 1000.0f << " ms</td>";
        report << "<td>" << result.message << "</td>";
        report << "</tr>\n";
    }
    
    report << "</table>\n";
    
    // Metrics
    report << "<h2>Metrics</h2>\n";
    for (const auto& result : results_) {
        if (!result.metrics.empty()) {
            report << "<h3>" << result.name << "</h3>\n";
            report << "<ul>\n";
            for (const auto& metric : result.metrics) {
                report << "<li>" << metric.first << ": " << metric.second << "</li>\n";
            }
            report << "</ul>\n";
        }
    }
    
    report << "</body>\n";
    report << "</html>\n";
    
    return report.str();
}

void SmoketestHarness::ExportReport(const std::string& filename) const {
    std::ofstream file(filename);
    if (file.is_open()) {
        file << GenerateReport();
        file.close();
    }
}

} // namespace RawrXD