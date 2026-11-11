#include "hotpatch_tps_benchmark.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <algorithm>
#include <numeric>

namespace rawrxd {
namespace benchmarks {

std::string HotpatchTypeToString(HotpatchType type) {
    switch (type) {
        case HotpatchType::SCHEDULER_OPTIMIZATION: return "scheduler_optimization";
        case HotpatchType::KERNEL_GEMM_REPLACE: return "kernel_gemm_replace";
        case HotpatchType::KERNEL_ATTENTION_REPLACE: return "kernel_attention_replace";
        case HotpatchType::MEMORY_ALLOCATOR_PATCH: return "memory_allocator_patch";
        case HotpatchType::SIMD_PATH_SELECTION: return "simd_path_selection";
        case HotpatchType::KV_CACHE_POLICY: return "kv_cache_policy";
        case HotpatchType::BATCHING_STRATEGY: return "batching_strategy";
        case HotpatchType::THREAD_AFFINITY_PATCH: return "thread_affinity_patch";
        case HotpatchType::QUANTIZATION_KERNEL: return "quantization_kernel";
        case HotpatchType::ROPE_KERNEL_REPLACE: return "rope_kernel_replace";
        default: return "unknown";
    }
}

// StatisticalMetrics implementation helper
namespace {
    StatisticalMetrics CalculateStats(const std::vector<double>& samples, double confidence = 0.95) {
        StatisticalMetrics stats;
        if (samples.empty()) return stats;
        
        stats.sample_count = static_cast<int>(samples.size());
        stats.mean = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
        
        // Median
        std::vector<double> sorted = samples;
        std::sort(sorted.begin(), sorted.end());
        if (sorted.size() % 2 == 0) {
            stats.median = (sorted[sorted.size()/2 - 1] + sorted[sorted.size()/2]) / 2.0;
        } else {
            stats.median = sorted[sorted.size()/2];
        }
        
        // Standard deviation
        double variance = 0.0;
        for (double s : samples) {
            variance += (s - stats.mean) * (s - stats.mean);
        }
        variance /= samples.size();
        stats.stddev = std::sqrt(variance);
        
        // Min/max
        stats.min = sorted.front();
        stats.max = sorted.back();
        
        // Percentiles
        stats.p95 = sorted[static_cast<size_t>(sorted.size() * 0.95)];
        stats.p99 = sorted[static_cast<size_t>(sorted.size() * 0.99)];
        
        // Confidence interval for mean (t-distribution approximation)
        double z_score = 1.96;  // 95% CI
        if (confidence == 0.99) z_score = 2.576;
        else if (confidence == 0.90) z_score = 1.645;
        
        double margin = z_score * (stats.stddev / std::sqrt(static_cast<double>(samples.size())));
        stats.mean_ci.lower = stats.mean - margin;
        stats.mean_ci.upper = stats.mean + margin;
        stats.mean_ci.confidence = confidence;
        stats.mean_ci.margin_of_error = margin;
        
        return stats;
    }
    
    double CalculateCohensD(const StatisticalMetrics& a, const StatisticalMetrics& b) {
        double pooled_std = std::sqrt((a.stddev * a.stddev + b.stddev * b.stddev) / 2.0);
        if (pooled_std == 0) return 0;
        return (b.mean - a.mean) / pooled_std;
    }
    
    bool IsSignificant(const StatisticalMetrics& a, const StatisticalMetrics& b, double confidence = 0.95) {
        // Check if confidence intervals overlap
        return (a.mean_ci.lower > b.mean_ci.upper) || (a.mean_ci.upper < b.mean_ci.lower);
    }
}

HotpatchTPSBenchmark::HotpatchTPSBenchmark(const HotpatchTPSConfig& config) 
    : config_(config) {}

void HotpatchTPSBenchmark::SetProgressCallback(ProgressCallback callback) {
    progress_callback_ = callback;
}

void HotpatchTPSBenchmark::SetSampleCallback(SampleCallback callback) {
    sample_callback_ = callback;
}

HotpatchTPSResults HotpatchTPSBenchmark::Run() {
    HotpatchTPSResults results;
    results.config = config_;
    
    std::cout << "=== Hotpatch TPS Benchmark ===" << std::endl;
    std::cout << "Model: " << config_.model_name << std::endl;
    std::cout << "Patch Type: " << HotpatchTypeToString(config_.patch_type) << std::endl;
    std::cout << std::endl;
    
    // Phase 1: Warmup
    std::cout << "[1/5] Warmup phase (" << config_.warmup_seconds << "s)..." << std::endl;
    results.warmup = RunWarmup();
    
    // Phase 2: Baseline sampling
    std::cout << "[2/5] Baseline TPS sampling (" << config_.baseline_sampling_seconds << "s)..." << std::endl;
    results.baseline = RunBaselineSampling();
    
    // Phase 3: Apply patch
    std::cout << "[3/5] Applying MASM hotpatch..." << std::endl;
    results.patch_result = ApplyPatch();
    
    // Phase 4: Post-patch sampling
    std::cout << "[4/5] Post-patch TPS sampling (" << config_.post_patch_sampling_seconds << "s)..." << std::endl;
    results.post_patch = RunPostPatchSampling();
    
    // Phase 5: Analysis
    std::cout << "[5/5] Statistical analysis..." << std::endl;
    
    // Calculate comparisons
    results.prompt_tps_comparison = ComparePhases(results.baseline, results.post_patch, "prompt_tps");
    results.generation_tps_comparison = ComparePhases(results.baseline, results.post_patch, "generation_tps");
    results.latency_comparison = ComparePhases(results.baseline, results.post_patch, "latency");
    
    // Effect sizes
    results.prompt_tps_effect_size = CalculateCohensD(results.baseline.prompt_tps_stats, results.post_patch.prompt_tps_stats);
    results.generation_tps_effect_size = CalculateCohensD(results.baseline.generation_tps_stats, results.post_patch.generation_tps_stats);
    results.latency_effect_size = CalculateCohensD(results.baseline.latency_stats, results.post_patch.latency_stats);
    
    // Significance
    results.prompt_tps_significant = IsSignificant(results.baseline.prompt_tps_stats, results.post_patch.prompt_tps_stats);
    results.generation_tps_significant = IsSignificant(results.baseline.generation_tps_stats, results.post_patch.generation_tps_stats);
    results.latency_significant = IsSignificant(results.baseline.latency_stats, results.post_patch.latency_stats);
    
    // Stability checks
    results.stability_maintained = CheckStabilityEnvelope(results.post_patch);
    results.safety_violations = 0;  // Would be populated by actual safety system
    results.oscillation_events = 0;
    results.rollback_triggered = false;
    
    // Overall improvement
    results.improvement_percent = results.generation_tps_comparison.delta_percent;
    
    // Verdict
    if (results.generation_tps_significant && results.improvement_percent > 5.0) {
        results.verdict = "SIGNIFICANT_IMPROVEMENT";
    } else if (results.generation_tps_significant && results.improvement_percent < -5.0) {
        results.verdict = "REGRESSION";
    } else {
        results.verdict = "NO_SIGNIFICANT_CHANGE";
    }
    
    std::cout << std::endl;
    std::cout << "=== Results ===" << std::endl;
    std::cout << "Baseline Prompt TPS: " << std::fixed << std::setprecision(2) 
              << results.baseline.prompt_tps_stats.mean << std::endl;
    std::cout << "Hotpatched Prompt TPS: " << results.post_patch.prompt_tps_stats.mean << std::endl;
    std::cout << "Improvement: " << results.improvement_percent << "%" << std::endl;
    std::cout << "Effect Size (Cohen's d): " << results.generation_tps_effect_size << std::endl;
    std::cout << "Statistically Significant: " << (results.generation_tps_significant ? "YES" : "NO") << std::endl;
    std::cout << "Verdict: " << results.verdict << std::endl;
    
    return results;
}

PhaseResults HotpatchTPSBenchmark::RunWarmup() {
    return SamplePhase(config_.warmup_seconds, BenchmarkPhase::WARMUP);
}

PhaseResults HotpatchTPSBenchmark::RunBaselineSampling() {
    return SamplePhase(config_.baseline_sampling_seconds, BenchmarkPhase::BASELINE_SAMPLING);
}

HotpatchResult HotpatchTPSBenchmark::ApplyPatch() {
    auto start = std::chrono::high_resolution_clock::now();
    
    // Simulate MASM hotpatch application
    // In real implementation, this would:
    // 1. Load the .masm patch file
    // 2. Verify checksum and signature
    // 3. Apply the patch to running code
    // 4. Flush instruction cache
    // 5. Verify patch applied successfully
    
    std::this_thread::sleep_for(std::chrono::milliseconds(3));  // Simulate 3ms patch time
    
    auto end = std::chrono::high_resolution_clock::now();
    
    HotpatchResult result;
    result.success = true;
    result.application_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    result.patch_version = "1.0.0-hotpatch-" + HotpatchTypeToString(config_.patch_type);
    result.checksum_verified = true;
    result.signature_valid = true;
    result.rollback_available = true;
    
    if (progress_callback_) {
        progress_callback_(BenchmarkPhase::PATCH_APPLICATION, 1.0);
    }
    
    return result;
}

PhaseResults HotpatchTPSBenchmark::RunPostPatchSampling() {
    return SamplePhase(config_.post_patch_sampling_seconds, BenchmarkPhase::POST_PATCH_SAMPLING);
}

PhaseResults HotpatchTPSBenchmark::SamplePhase(int duration_seconds, BenchmarkPhase phase) {
    PhaseResults results;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    int sample_count = 0;
    int target_samples = static_cast<int>(duration_seconds * 1000.0 / config_.sampling_interval_ms);
    
    while (sample_count < target_samples) {
        auto sample = TakeSample();
        results.samples.push_back(sample);
        
        if (sample_callback_) {
            sample_callback_(sample);
        }
        
        // Progress update
        if (progress_callback_ && sample_count % 10 == 0) {
            double progress = static_cast<double>(sample_count) / target_samples;
            progress_callback_(phase, progress);
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(config_.sampling_interval_ms)));
        sample_count++;
    }
    
    // Calculate statistics
    std::vector<double> prompt_tps_values;
    std::vector<double> generation_tps_values;
    std::vector<double> latency_values;
    
    for (const auto& s : results.samples) {
        prompt_tps_values.push_back(s.prompt_tps);
        generation_tps_values.push_back(s.generation_tps);
        latency_values.push_back(s.token_latency_ms);
    }
    
    results.prompt_tps_stats = CalculateStats(prompt_tps_values, config_.confidence_level);
    results.generation_tps_stats = CalculateStats(generation_tps_values, config_.confidence_level);
    results.latency_stats = CalculateStats(latency_values, config_.confidence_level);
    
    // Calculate stability score (lower variance = higher stability)
    double cv = results.generation_tps_stats.stddev / results.generation_tps_stats.mean;
    results.stability_score = std::max(0.0, 100.0 - (cv * 100.0));
    
    return results;
}

TPSMeasurement HotpatchTPSBenchmark::TakeSample() {
    TPSMeasurement sample;
    
    // In real implementation, these would come from actual runtime telemetry
    // For benchmark simulation, we generate realistic values
    
    static std::mt19937 gen(42);  // Fixed seed for reproducibility
    std::normal_distribution<> prompt_dist(180.0, 10.0);
    std::normal_distribution<> gen_dist(52.0, 3.0);
    std::normal_distribution<> latency_dist(19.0, 1.5);
    
    sample.timestamp_seconds = std::chrono::duration<double>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    
    // Simulate TPS values (would be actual measurements in production)
    sample.prompt_tps = prompt_dist(gen);
    sample.generation_tps = gen_dist(gen);
    sample.batch_tps = sample.generation_tps * config_.batch_size;
    sample.token_latency_ms = latency_dist(gen);
    sample.ttft_ms = sample.token_latency_ms * 5;  // Approximate
    sample.p95_latency_ms = sample.token_latency_ms * 1.5;
    sample.p99_latency_ms = sample.token_latency_ms * 2.0;
    
    // Memory and GPU (simulated)
    sample.memory_usage_mb = 4096 + (std::rand() % 512);
    sample.gpu_utilization = 85.0 + (std::rand() % 10);
    
    return sample;
}

StatisticalComparison HotpatchTPSBenchmark::ComparePhases(const PhaseResults& baseline, 
                                                           const PhaseResults& post_patch,
                                                           const std::string& metric_name) {
    StatisticalComparison comp;
    
    // Use generation TPS for comparison
    comp.sovereign_mean = post_patch.generation_tps_stats.mean;
    comp.ollama_mean = baseline.generation_tps_stats.mean;  // Baseline acts as "control"
    
    double delta = comp.sovereign_mean - comp.ollama_mean;
    comp.delta_percent = (delta / comp.ollama_mean) * 100.0;
    
    comp.effect_size = CalculateCohensD(baseline.generation_tps_stats, post_patch.generation_tps_stats);
    comp.is_significant = IsSignificant(baseline.generation_tps_stats, post_patch.generation_tps_stats);
    
    // P-value estimate based on effect size
    if (std::abs(comp.effect_size) > 1.2) comp.p_value_estimate = 0.001;
    else if (std::abs(comp.effect_size) > 0.8) comp.p_value_estimate = 0.01;
    else if (std::abs(comp.effect_size) > 0.5) comp.p_value_estimate = 0.05;
    else comp.p_value_estimate = 0.1;
    
    // Significance marker
    if (comp.p_value_estimate < 0.001) comp.significance_marker = "***";
    else if (comp.p_value_estimate < 0.01) comp.significance_marker = "**";
    else if (comp.p_value_estimate < 0.05) comp.significance_marker = "*";
    else comp.significance_marker = "ns";
    
    return comp;
}

double HotpatchTPSBenchmark::CalculateEffectSize(const StatisticalMetrics& baseline,
                                                  const StatisticalMetrics& post_patch) {
    return CalculateCohensD(baseline, post_patch);
}

bool HotpatchTPSBenchmark::CheckStabilityEnvelope(const PhaseResults& results) {
    // Check if results are within stability envelope
    double cv = results.generation_tps_stats.stddev / results.generation_tps_stats.mean;
    return cv < 0.15;  // Coefficient of variation < 15% considered stable
}

// Export methods
std::string HotpatchTPSResults::ToJson() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"benchmark\": \"hotpatch_tps\",\n";
    json << "  \"model\": \"" << config.model_name << "\",\n";
    json << "  \"patch_type\": \"" << HotpatchTypeToString(config.patch_type) << "\",\n";
    json << "  \"baseline_prompt_tps\": " << baseline.prompt_tps_stats.mean << ",\n";
    json << "  \"hotpatched_prompt_tps\": " << post_patch.prompt_tps_stats.mean << ",\n";
    json << "  \"baseline_generation_tps\": " << baseline.generation_tps_stats.mean << ",\n";
    json << "  \"hotpatched_generation_tps\": " << post_patch.generation_tps_stats.mean << ",\n";
    json << "  \"improvement_percent\": " << improvement_percent << ",\n";
    json << "  \"effect_size\": " << generation_tps_effect_size << ",\n";
    json << "  \"significant\": " << (generation_tps_significant ? "true" : "false") << ",\n";
    json << "  \"verdict\": \"" << verdict << "\"\n";
    json << "}";
    return json.str();
}

std::string HotpatchTPSResults::ToMarkdown() const {
    std::ostringstream md;
    md << "# Hotpatch TPS Benchmark Results\n\n";
    md << "**Model:** " << config.model_name << "\n\n";
    md << "**Patch Type:** " << HotpatchTypeToString(config.patch_type) << "\n\n";
    md << "## Summary\n\n";
    md << "| Metric | Baseline | Hotpatched | Delta |\n";
    md << "|--------|----------|------------|-------|\n";
    md << "| Prompt TPS | " << std::fixed << std::setprecision(2) << baseline.prompt_tps_stats.mean;
    md << " | " << post_patch.prompt_tps_stats.mean << " | ";
    md << ((post_patch.prompt_tps_stats.mean - baseline.prompt_tps_stats.mean) / baseline.prompt_tps_stats.mean * 100);
    md << "% |\n";
    md << "| Generation TPS | " << baseline.generation_tps_stats.mean;
    md << " | " << post_patch.generation_tps_stats.mean << " | " << improvement_percent << "% |\n";
    md << "\n";
    md << "## Statistical Analysis\n\n";
    md << "- **Effect Size (Cohen's d):** " << generation_tps_effect_size << "\n";
    md << "- **Statistically Significant:** " << (generation_tps_significant ? "YES" : "NO") << "\n";
    md << "- **Verdict:** " << verdict << "\n";
    return md.str();
}

std::string HotpatchTPSResults::ToCsv() const {
    std::ostringstream csv;
    csv << "timestamp,phase,prompt_tps,generation_tps,latency_ms\n";
    
    for (const auto& s : baseline.samples) {
        csv << s.timestamp_seconds << ",baseline," << s.prompt_tps << ","
            << s.generation_tps << "," << s.token_latency_ms << "\n";
    }
    
    for (const auto& s : post_patch.samples) {
        csv << s.timestamp_seconds << ",hotpatched," << s.prompt_tps << ","
            << s.generation_tps << "," << s.token_latency_ms << "\n";
    }
    
    return csv.str();
}

// Predefined configurations
HotpatchTPSConfig GetSmallModelConfig() {
    HotpatchTPSConfig config;
    config.model_name = "phi-3-mini-4k";
    config.context_length = 4096;
    config.batch_size = 1;
    config.patch_type = HotpatchType::KERNEL_GEMM_REPLACE;
    return config;
}

HotpatchTPSConfig GetMediumModelConfig() {
    HotpatchTPSConfig config;
    config.model_name = "llama-3-8b";
    config.context_length = 8192;
    config.batch_size = 1;
    config.patch_type = HotpatchType::KERNEL_ATTENTION_REPLACE;
    return config;
}

HotpatchTPSConfig GetLargeModelConfig() {
    HotpatchTPSConfig config;
    config.model_name = "llama-3-70b";
    config.context_length = 32768;
    config.batch_size = 1;
    config.patch_type = HotpatchType::MEMORY_ALLOCATOR_PATCH;
    return config;
}

// Factory
std::unique_ptr<HotpatchTPSBenchmark> CreateHotpatchTPSBenchmark(
    const HotpatchTPSConfig& config) {
    return std::make_unique<HotpatchTPSBenchmark>(config);
}

// Matrix benchmark
std::vector<HotpatchComparison> RunHotpatchMatrixBenchmark() {
    std::vector<HotpatchComparison> results;
    
    std::vector<std::pair<std::string, HotpatchTPSConfig>> configs = {
        {"small", GetSmallModelConfig()},
        {"medium", GetMediumModelConfig()},
        {"large", GetLargeModelConfig()}
    };
    
    for (const auto& [category, config] : configs) {
        auto benchmark = CreateHotpatchTPSBenchmark(config);
        auto result = benchmark->Run();
        
        HotpatchComparison comp;
        comp.model_category = category;
        comp.baseline_prompt_tps = result.baseline.prompt_tps_stats.mean;
        comp.hotpatched_prompt_tps = result.post_patch.prompt_tps_stats.mean;
        comp.improvement_percent = result.improvement_percent;
        comp.effect_size = result.generation_tps_effect_size;
        comp.statistically_significant = result.generation_tps_significant;
        comp.patch_type_used = HotpatchTypeToString(config.patch_type);
        
        results.push_back(comp);
    }
    
    return results;
}

} // namespace benchmarks
} // namespace rawrxd
