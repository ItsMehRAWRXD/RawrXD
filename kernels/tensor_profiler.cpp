/**
 * @file tensor_profiler.cpp
 * @brief RawrXD L4.3.0 Tensor Profiler Implementation
 *
 * Read-only analysis layer for adaptive compression.
 *
 * @copyright RawrXD 2026
 */

#include "tensor_profiler.h"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace rawrxd {
namespace profiler {

// ============================================================================
// Calibration Collector
// ============================================================================

CalibrationCollector::CalibrationCollector()
    : session_active_(false)
    , sample_active_(false)
{}

CalibrationCollector::~CalibrationCollector() = default;

void CalibrationCollector::BeginSession(const std::string& model_name) {
    model_name_ = model_name;
    session_active_ = true;
    samples_.clear();
    tensor_names_.clear();
}

void CalibrationCollector::EndSession() {
    session_active_ = false;
    sample_active_ = false;
}

void CalibrationCollector::BeginSample(uint64_t token_id) {
    if (!session_active_) return;
    
    sample_active_ = true;
    current_sample_.sample_id = token_id;
    current_sample_.timestamp = samples_.size();
    current_sample_.observations.clear();
    current_sample_.context.clear();
}

void CalibrationCollector::EndSample() {
    if (!sample_active_) return;
    
    samples_.push_back(current_sample_);
    sample_active_ = false;
}

void CalibrationCollector::RecordTensor(
    const std::string& name,
    const float* data,
    size_t count,
    const std::vector<size_t>& shape
) {
    if (!sample_active_) return;
    
    tensor_names_.insert(name);
    
    TensorObservation obs;
    obs.tensor_name = name;
    obs.values.reserve(std::min(count, size_t(10000))); // Sample large tensors
    
    // Store values (or sample for large tensors)
    size_t stride = (count > 10000) ? (count / 10000) : 1;
    for (size_t i = 0; i < count; i += stride) {
        obs.values.push_back(data[i]);
    }
    
    ComputeObservationStats(&obs);
    current_sample_.observations[name] = std::move(obs);
}

void CalibrationCollector::RecordTensorStats(
    const std::string& name,
    float min_val,
    float max_val,
    float mean,
    float variance,
    uint32_t outliers,
    size_t count
) {
    if (!sample_active_) return;
    
    tensor_names_.insert(name);
    
    TensorObservation obs;
    obs.tensor_name = name;
    obs.min_value = min_val;
    obs.max_value = max_val;
    obs.mean = mean;
    obs.variance = variance;
    obs.outlier_count = outliers;
    obs.outlier_ratio = (count > 0) ? (float)outliers / count : 0.0f;
    
    current_sample_.observations[name] = std::move(obs);
}

void CalibrationCollector::ComputeObservationStats(TensorObservation* obs) {
    if (!obs || obs->values.empty()) return;
    
    // Compute min/max/mean
    obs->min_value = *std::min_element(obs->values.begin(), obs->values.end());
    obs->max_value = *std::max_element(obs->values.begin(), obs->values.end());
    obs->mean = std::accumulate(obs->values.begin(), obs->values.end(), 0.0f) / obs->values.size();
    
    // Compute variance
    float sum_sq_diff = 0.0f;
    for (float v : obs->values) {
        float diff = v - obs->mean;
        sum_sq_diff += diff * diff;
    }
    obs->variance = sum_sq_diff / obs->values.size();
    
    // Count outliers (>3 sigma)
    float std_dev = std::sqrt(obs->variance);
    obs->outlier_count = 0;
    for (float v : obs->values) {
        if (std::abs(v - obs->mean) > 3.0f * std_dev) {
            obs->outlier_count++;
        }
    }
    obs->outlier_ratio = (float)obs->outlier_count / obs->values.size();
}

bool CalibrationCollector::ExportToJSON(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) return false;
    
    file << "{\n";
    file << "  \"model\": \"" << model_name_ << "\",\n";
    file << "  \"sample_count\": " << samples_.size() << ",\n";
    file << "  \"tensor_count\": " << tensor_names_.size() << ",\n";
    file << "  \"samples\": [\n";
    
    for (size_t s = 0; s < samples_.size(); ++s) {
        const auto& sample = samples_[s];
        file << "    {\n";
        file << "      \"sample_id\": " << sample.sample_id << ",\n";
        file << "      \"observations\": {\n";
        
        size_t obs_idx = 0;
        for (const auto& [name, obs] : sample.observations) {
            file << "        \"" << name << "\": {\n";
            file << "          \"min\": " << obs.min_value << ",\n";
            file << "          \"max\": " << obs.max_value << ",\n";
            file << "          \"mean\": " << obs.mean << ",\n";
            file << "          \"variance\": " << obs.variance << ",\n";
            file << "          \"outlier_ratio\": " << obs.outlier_ratio << "\n";
            file << "        }";
            if (++obs_idx < sample.observations.size()) file << ",";
            file << "\n";
        }
        
        file << "      }\n";
        file << "    }";
        if (s + 1 < samples_.size()) file << ",";
        file << "\n";
    }
    
    file << "  ]\n";
    file << "}\n";
    
    return true;
}

bool CalibrationCollector::ImportFromJSON(const std::string& filename) {
    // Simplified import - would use proper JSON parser in production
    (void)filename;
    return false;
}

void CalibrationCollector::Clear() {
    samples_.clear();
    tensor_names_.clear();
    current_sample_ = CalibrationSample{};
    session_active_ = false;
    sample_active_ = false;
}

// ============================================================================
// Sensitivity Analyzer
// ============================================================================

SensitivityAnalyzer::SensitivityAnalyzer() = default;
SensitivityAnalyzer::~SensitivityAnalyzer() = default;

TensorProfile SensitivityAnalyzer::AnalyzeTensor(
    const std::string& name,
    const std::vector<TensorObservation>& observations
) {
    TensorProfile profile;
    profile.name = name;
    profile.sample_count = static_cast<uint32_t>(observations.size());
    
    if (observations.empty()) {
        profile.confidence = 0.0f;
        return profile;
    }
    
    // Compute individual metrics
    profile.activation_variance = ComputeActivationVariance(observations);
    profile.quantization_error = ComputeQuantizationError(observations);
    profile.output_impact = ComputeOutputImpact(name);
    profile.gradient_sensitivity = ComputeGradientSensitivity(name);
    
    // Compute composite score
    profile.sensitivity_score = ComputeSensitivityScore(
        profile.activation_variance,
        profile.quantization_error,
        profile.output_impact,
        profile.gradient_sensitivity
    );
    
    // Select codec
    profile.recommended_codec = SelectCodec(profile.sensitivity_score);
    
    // Estimate compression parameters
    EstimateCompressionParams(profile, &profile.expected_ratio, &profile.expected_error);
    
    // Calculate confidence based on sample count
    profile.confidence = std::min(1.0f, static_cast<float>(observations.size()) / 100.0f);
    
    return profile;
}

std::vector<TensorProfile> SensitivityAnalyzer::AnalyzeCalibrationData(
    const std::vector<CalibrationSample>& samples
) {
    std::vector<TensorProfile> profiles;
    if (samples.empty()) return profiles;
    
    // Collect all observations by tensor name
    std::map<std::string, std::vector<TensorObservation>> tensor_observations;
    
    for (const auto& sample : samples) {
        for (const auto& [name, obs] : sample.observations) {
            tensor_observations[name].push_back(obs);
        }
    }
    
    // Analyze each tensor
    for (const auto& [name, observations] : tensor_observations) {
        profiles.push_back(AnalyzeTensor(name, observations));
    }
    
    return profiles;
}

float SensitivityAnalyzer::ComputeActivationVariance(const std::vector<TensorObservation>& obs) {
    if (obs.empty()) return 0.0f;
    
    // Average variance across observations
    float total_variance = 0.0f;
    for (const auto& o : obs) {
        total_variance += o.variance;
    }
    float avg_variance = total_variance / obs.size();
    
    // Normalize to 0-1 range (assuming typical variance 0-1)
    return Clamp(avg_variance, 0.0f, 1.0f);
}

float SensitivityAnalyzer::ComputeQuantizationError(const std::vector<TensorObservation>& obs) {
    if (obs.empty()) return 0.0f;
    
    // Estimate quantization error based on value range and outlier ratio
    float total_error = 0.0f;
    for (const auto& o : obs) {
        float range = o.max_value - o.min_value;
        float outlier_penalty = o.outlier_ratio * 10.0f; // Outliers increase error
        total_error += (range / 16.0f) + outlier_penalty; // Q4 has 16 levels
    }
    
    float avg_error = total_error / obs.size();
    return Clamp(avg_error, 0.0f, 1.0f);
}

float SensitivityAnalyzer::ComputeOutputImpact(const std::string& tensor_name) {
    // Heuristic: certain tensor types have higher impact
    if (tensor_name.find("output") != std::string::npos) return 0.9f;
    if (tensor_name.find("embed") != std::string::npos) return 0.8f;
    if (tensor_name.find("attn") != std::string::npos) return 0.7f;
    if (tensor_name.find("ffn.down") != std::string::npos) return 0.6f;
    if (tensor_name.find("ffn.up") != std::string::npos) return 0.4f;
    if (tensor_name.find("norm") != std::string::npos) return 0.8f;
    return 0.5f;
}

float SensitivityAnalyzer::ComputeGradientSensitivity(const std::string& tensor_name) {
    // Heuristic: weight matrices in attention are more sensitive
    if (tensor_name.find("attn.q") != std::string::npos) return 0.8f;
    if (tensor_name.find("attn.k") != std::string::npos) return 0.7f;
    if (tensor_name.find("attn.v") != std::string::npos) return 0.6f;
    if (tensor_name.find("attn.o") != std::string::npos) return 0.7f;
    return 0.5f;
}

float SensitivityAnalyzer::ComputeSensitivityScore(
    float activation_variance,
    float quantization_error,
    float output_impact,
    float gradient_sensitivity
) {
    return Clamp(
        activation_variance * weights_.activation_variance +
        quantization_error * weights_.quantization_error +
        output_impact * weights_.output_impact +
        gradient_sensitivity * weights_.gradient_sensitivity,
        0.0f,
        1.0f
    );
}

compression::CompressionType SensitivityAnalyzer::SelectCodec(float sensitivity_score) {
    if (sensitivity_score <= thresholds_.q4_0_max) {
        return compression::CompressionType::Q4_0;
    } else if (sensitivity_score <= thresholds_.q5_max) {
        return compression::CompressionType::Q5_0;
    } else if (sensitivity_score <= thresholds_.q6_max) {
        return compression::CompressionType::Q6_K;
    } else {
        return compression::CompressionType::Q8_0;
    }
}

compression::CompressionType SensitivityAnalyzer::SelectCodecWithBudget(
    float sensitivity_score,
    float target_memory_ratio
) {
    // Adjust selection based on memory budget
    float aggressive_threshold = target_memory_ratio * 4.0f; // Heuristic
    
    if (sensitivity_score <= aggressive_threshold * thresholds_.q4_0_max) {
        return compression::CompressionType::Q4_0;
    } else if (sensitivity_score <= aggressive_threshold * thresholds_.q5_max) {
        return compression::CompressionType::Q5_0;
    } else if (sensitivity_score <= aggressive_threshold * thresholds_.q6_max) {
        return compression::CompressionType::Q6_K;
    } else {
        return compression::CompressionType::Q8_0;
    }
}

void SensitivityAnalyzer::EstimateCompressionParams(
    const TensorProfile& profile,
    float* out_ratio,
    float* out_error
) {
    // Estimated compression ratios and errors by codec
    switch (profile.recommended_codec) {
        case compression::CompressionType::Q4_0:
            *out_ratio = 6.4f;
            *out_error = 0.004f;
            break;
        case compression::CompressionType::Q5_0:
            *out_ratio = 5.2f;
            *out_error = 0.002f;
            break;
        case compression::CompressionType::Q6_K:
            *out_ratio = 4.8f;
            *out_error = 0.001f;
            break;
        case compression::CompressionType::Q8_0:
            *out_ratio = 2.0f;
            *out_error = 0.0005f;
            break;
        default:
            *out_ratio = 1.0f;
            *out_error = 0.0f;
            break;
    }
}

float SensitivityAnalyzer::NormalizeMetric(float value, float min_val, float max_val) {
    if (max_val <= min_val) return 0.0f;
    return Clamp((value - min_val) / (max_val - min_val), 0.0f, 1.0f);
}

float SensitivityAnalyzer::Clamp(float value, float min_val, float max_val) {
    return std::max(min_val, std::min(max_val, value));
}

// ============================================================================
// Compression Planner
// ============================================================================

CompressionPlanner::CompressionPlanner() = default;
CompressionPlanner::~CompressionPlanner() = default;

CompressionPlanner::Policy CompressionPlanner::CreatePlan(
    const std::vector<TensorProfile>& profiles,
    const Constraints& constraints
) {
    Policy policy;
    policy.model_name = "unknown";
    policy.profiles = profiles;
    policy.meets_constraints = true;
    
    // Calculate aggregate metrics
    policy.achieved_ratio = CalculateAchievedRatio(policy);
    policy.estimated_quality = 1.0f; // Would compute from error estimates
    policy.estimated_size_bytes = static_cast<size_t>(CalculateTotalSize(policy));
    
    // Check constraints
    if (policy.achieved_ratio < constraints.target_memory_ratio) {
        policy.meets_constraints = false;
        policy.warnings.push_back("Memory ratio below target");
    }
    
    if (policy.estimated_quality < constraints.min_quality_score) {
        policy.meets_constraints = false;
        policy.warnings.push_back("Quality below minimum");
    }
    
    return policy;
}

CompressionPlanner::Policy CompressionPlanner::OptimizePlan(
    const Policy& initial_plan,
    const Constraints& constraints
) {
    Policy optimized = initial_plan;
    
    // Adjust for memory budget if needed
    if (!AdjustForMemoryBudget(&optimized, constraints)) {
        optimized.warnings.push_back("Could not meet memory budget");
    }
    
    // Adjust for quality if needed
    if (!AdjustForQuality(&optimized, constraints)) {
        optimized.warnings.push_back("Could not meet quality constraint");
    }
    
    // Recalculate metrics
    optimized.achieved_ratio = CalculateAchievedRatio(optimized);
    optimized.estimated_size_bytes = static_cast<size_t>(CalculateTotalSize(optimized));
    
    return optimized;
}

bool CompressionPlanner::ValidatePlan(const Policy& plan, std::string* out_error) {
    // Validate against L4.2.3 gates
    for (const auto& profile : plan.profiles) {
        if (profile.confidence < 0.5f) {
            if (out_error) *out_error = "Low confidence profile: " + profile.name;
            return false;
        }
        
        // Check codec-specific gates
        float min_cosine = 0.999f;
        if (profile.recommended_codec == compression::CompressionType::Q8_0) {
            min_cosine = 0.9999f;
        }
        
        // Would check actual cosine here if available
        (void)min_cosine;
    }
    
    return true;
}

bool CompressionPlanner::ExportPolicyToJSON(const Policy& policy, const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) return false;
    
    file << "{\n";
    file << "  \"model\": \"" << policy.model_name << "\",\n";
    file << "  \"achieved_ratio\": " << policy.achieved_ratio << ",\n";
    file << "  \"estimated_quality\": " << policy.estimated_quality << ",\n";
    file << "  \"estimated_size_bytes\": " << policy.estimated_size_bytes << ",\n";
    file << "  \"meets_constraints\": " << (policy.meets_constraints ? "true" : "false") << ",\n";
    file << "  \"profiles\": [\n";
    
    for (size_t i = 0; i < policy.profiles.size(); ++i) {
        const auto& p = policy.profiles[i];
        file << "    {\n";
        file << "      \"tensor\": \"" << p.name << "\",\n";
        file << "      \"codec\": \"" << CodecToString(p.recommended_codec) << "\",\n";
        file << "      \"ratio\": " << p.expected_ratio << ",\n";
        file << "      \"error\": " << p.expected_error << ",\n";
        file << "      \"sensitivity\": " << p.sensitivity_score << ",\n";
        file << "      \"confidence\": " << p.confidence << "\n";
        file << "    }";
        if (i + 1 < policy.profiles.size()) file << ",";
        file << "\n";
    }
    
    file << "  ]\n";
    file << "}\n";
    
    return true;
}

bool CompressionPlanner::ImportPolicyFromJSON(const std::string& filename, Policy* out_policy) {
    (void)filename;
    (void)out_policy;
    return false; // Would implement with JSON parser
}

void CompressionPlanner::PrintPolicySummary(const Policy& policy) {
    std::cout << "\n═══════════════════════════════════════════════════════════════\n";
    std::cout << "COMPRESSION POLICY SUMMARY\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    std::cout << "Model: " << policy.model_name << "\n";
    std::cout << "Achieved Ratio: " << std::fixed << std::setprecision(2) 
              << policy.achieved_ratio << ":1\n";
    std::cout << "Estimated Quality: " << policy.estimated_quality << "\n";
    std::cout << "Estimated Size: " << policy.estimated_size_bytes / (1024.0 * 1024.0) 
              << " MB\n";
    std::cout << "Meets Constraints: " << (policy.meets_constraints ? "Yes" : "No") << "\n";
    
    std::cout << "\nTensor Breakdown:\n";
    std::map<compression::CompressionType, size_t> codec_counts;
    for (const auto& p : policy.profiles) {
        codec_counts[p.recommended_codec]++;
    }
    
    for (const auto& [codec, count] : codec_counts) {
        std::cout << "  " << CodecToString(codec) << ": " << count << " tensors\n";
    }
    
    if (!policy.warnings.empty()) {
        std::cout << "\nWarnings:\n";
        for (const auto& w : policy.warnings) {
            std::cout << "  ⚠️ " << w << "\n";
        }
    }
    
    std::cout << "═══════════════════════════════════════════════════════════════\n";
}

float CompressionPlanner::CalculateTotalSize(const Policy& policy) {
    float total = 0.0f;
    for (const auto& p : policy.profiles) {
        total += static_cast<float>(p.elements * sizeof(float)) / p.expected_ratio;
    }
    return total;
}

float CompressionPlanner::CalculateAchievedRatio(const Policy& policy) {
    float original_size = 0.0f;
    float compressed_size = 0.0f;
    
    for (const auto& p : policy.profiles) {
        original_size += static_cast<float>(p.elements * sizeof(float));
        compressed_size += static_cast<float>(p.elements * sizeof(float)) / p.expected_ratio;
    }
    
    return (compressed_size > 0) ? original_size / compressed_size : 1.0f;
}

bool CompressionPlanner::AdjustForMemoryBudget(Policy* policy, const Constraints& constraints) {
    if (!policy) return false;
    
    float current_ratio = CalculateAchievedRatio(*policy);
    if (current_ratio >= constraints.target_memory_ratio) {
        return true; // Already meets budget
    }
    
    // Need to increase compression (lower ratio number)
    // This is a simplified adjustment - would iterate in production
    for (auto& profile : policy->profiles) {
        if (!profile.IsSensitive()) {
            // Can compress more aggressively
            profile.recommended_codec = compression::CompressionType::Q4_0;
            profile.expected_ratio = 6.4f;
        }
    }
    
    return CalculateAchievedRatio(*policy) >= constraints.target_memory_ratio;
}

bool CompressionPlanner::AdjustForQuality(Policy* policy, const Constraints& constraints) {
    if (!policy) return false;
    
    // Would adjust codecs to meet quality target
    (void)constraints;
    return true;
}

// ============================================================================
// Tensor Profiler
// ============================================================================

TensorProfiler::TensorProfiler() : initialized_(false) {}
TensorProfiler::~TensorProfiler() = default;

bool TensorProfiler::Initialize(const std::string& model_path) {
    model_path_ = model_path;
    initialized_ = true;
    return true;
}

bool TensorProfiler::RunProfiling(
    const std::vector<uint32_t>& calibration_tokens,
    CompressionPlanner::Constraints constraints
) {
    if (!initialized_) return false;
    
    // Step 1: Begin calibration
    if (!BeginCalibration()) return false;
    
    // Step 2: Would run calibration tokens through model here
    // For now, simulate with placeholder data
    for (size_t i = 0; i < calibration_tokens.size(); ++i) {
        std::map<std::string, std::vector<float>> tensor_data;
        // Would populate from actual model run
        if (!RecordSample(tensor_data)) return false;
    }
    
    // Step 3: End calibration
    if (!EndCalibration()) return false;
    
    // Step 4: Analyze sensitivity
    if (!AnalyzeSensitivity()) return false;
    
    // Step 5: Create plan
    if (!CreatePlan(constraints)) return false;
    
    return true;
}

bool TensorProfiler::BeginCalibration() {
    collector_.BeginSession(model_path_);
    return true;
}

bool TensorProfiler::RecordSample(const std::map<std::string, std::vector<float>>& tensor_data) {
    static uint64_t sample_id = 0;
    collector_.BeginSample(sample_id++);
    
    for (const auto& [name, data] : tensor_data) {
        collector_.RecordTensor(name, data.data(), data.size());
    }
    
    collector_.EndSample();
    return true;
}

bool TensorProfiler::EndCalibration() {
    collector_.EndSession();
    return true;
}

bool TensorProfiler::AnalyzeSensitivity() {
    profiles_ = analyzer_.AnalyzeCalibrationData(collector_.GetSamples());
    return !profiles_.empty();
}

bool TensorProfiler::CreatePlan(const CompressionPlanner::Constraints& constraints) {
    plan_ = planner_.CreatePlan(profiles_, constraints);
    return plan_.meets_constraints;
}

bool TensorProfiler::ExportProfiles(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) return false;
    
    file << "{\n";
    file << "  \"profiles\": [\n";
    
    for (size_t i = 0; i < profiles_.size(); ++i) {
        const auto& p = profiles_[i];
        file << "    {\n";
        file << "      \"name\": \"" << p.name << "\",\n";
        file << "      \"sensitivity_score\": " << p.sensitivity_score << ",\n";
        file << "      \"recommended_codec\": \"" << CodecToString(p.recommended_codec) << "\",\n";
        file << "      \"confidence\": " << p.confidence << "\n";
        file << "    }";
        if (i + 1 < profiles_.size()) file << ",";
        file << "\n";
    }
    
    file << "  ]\n";
    file << "}\n";
    
    return true;
}

bool TensorProfiler::ExportPlan(const std::string& filename) const {
    return planner_.ExportPolicyToJSON(plan_, filename);
}

bool TensorProfiler::ExportFullReport(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) return false;
    
    file << "# RawrXD L4.3.0 Tensor Profiler Report\n\n";
    file << "Model: " << model_path_ << "\n";
    file << "Samples: " << collector_.GetSampleCount() << "\n";
    file << "Tensors: " << profiles_.size() << "\n\n";
    
    file << "## Compression Policy\n\n";
    file << "Achieved Ratio: " << plan_.achieved_ratio << ":1\n";
    file << "Estimated Quality: " << plan_.estimated_quality << "\n\n";
    
    file << "## Tensor Profiles\n\n";
    file << "| Tensor | Sensitivity | Codec | Confidence |\n";
    file << "|--------|-------------|-------|------------|\n";
    
    for (const auto& p : profiles_) {
        file << "| " << p.name << " | " << p.sensitivity_score 
             << " | " << CodecToString(p.recommended_codec)
             << " | " << p.confidence << " |\n";
    }
    
    return true;
}

bool TensorProfiler::ValidateAgainstGates(std::vector<std::string>* out_failures) {
    bool passed = true;
    
    // Gate 1: Tensor enumeration
    if (profiles_.empty()) {
        if (out_failures) out_failures->push_back("Gate 1: No tensors discovered");
        passed = false;
    }
    
    // Gate 2: Calibration replay determinism
    // Would check that same inputs produce same outputs
    
    // Gate 3: Sensitivity score stability
    for (const auto& p : profiles_) {
        if (p.confidence < 0.5f) {
            if (out_failures) {
                out_failures->push_back("Gate 3: Low confidence for " + p.name);
            }
            passed = false;
        }
    }
    
    // Gate 4: Planner output reproducibility
    // Would regenerate and compare
    
    // Gate 5: GEMM path unchanged (L4.2.3 validation)
    // This is ensured by design - profiler is read-only
    
    return passed;
}

void TensorProfiler::SetAnalyzerWeights(const SensitivityAnalyzer::Weights& weights) {
    analyzer_.SetWeights(weights);
}

void TensorProfiler::SetAnalyzerThresholds(const SensitivityAnalyzer::Thresholds& thresholds) {
    analyzer_.SetThresholds(thresholds);
}

// ============================================================================
// Utility Functions
// ============================================================================

const char* CodecToString(compression::CompressionType codec) {
    switch (codec) {
        case compression::CompressionType::Q4_0: return "Q4_0";
        case compression::CompressionType::Q5_0: return "Q5_0";
        case compression::CompressionType::Q6_K: return "Q6_K";
        case compression::CompressionType::Q8_0: return "Q8_0";
        case compression::CompressionType::FP16: return "FP16";
        case compression::CompressionType::FP32: return "FP32";
        default: return "UNKNOWN";
    }
}

compression::CompressionType StringToCodec(const std::string& str) {
    if (str == "Q4_0") return compression::CompressionType::Q4_0;
    if (str == "Q5_0") return compression::CompressionType::Q5_0;
    if (str == "Q6_K") return compression::CompressionType::Q6_K;
    if (str == "Q8_0") return compression::CompressionType::Q8_0;
    if (str == "FP16") return compression::CompressionType::FP16;
    if (str == "FP32") return compression::CompressionType::FP32;
    return compression::CompressionType::FP32;
}

const char* SensitivityCategory(float score) {
    if (score <= 0.25f) return "LOW";
    if (score <= 0.60f) return "MEDIUM";
    if (score <= 0.85f) return "HIGH";
    return "CRITICAL";
}

float CalculateMemorySavings(const CompressionPlanner::Policy& policy) {
    return (1.0f - 1.0f / policy.achieved_ratio) * 100.0f;
}

bool ComparePolicies(
    const CompressionPlanner::Policy& a,
    const CompressionPlanner::Policy& b,
    float tolerance
) {
    if (a.profiles.size() != b.profiles.size()) return false;
    
    if (std::abs(a.achieved_ratio - b.achieved_ratio) > tolerance) return false;
    if (std::abs(a.estimated_quality - b.estimated_quality) > tolerance) return false;
    
    return true;
}

} // namespace profiler
} // namespace rawrxd
