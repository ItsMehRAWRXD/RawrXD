/**
 * @file quantization_guard.cpp
 * @brief RawrXD L4.2.1 Numerical Hardening Implementation
 *
 * The "knock sensor" that auto-rejects invalid compression profiles.
 *
 * @copyright RawrXD 2026
 */

#include "quantization_guard.h"
#include <cmath>
#include <algorithm>
#include <cstring>
#include <random>
#include <iomanip>
#include <iostream>

namespace rawrxd {
namespace compression {

// ============================================================================
// Quantization Report
// ============================================================================

void QuantizationReport::Print() const {
    std::cout << "\n═══════════════════════════════════════════════════════════════\n";
    std::cout << "QUANTIZATION REPORT\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    
    std::cout << std::fixed << std::setprecision(4);
    std::cout << "Compression:\n";
    std::cout << "  Ratio: " << compression_ratio << ":1\n";
    std::cout << "  Original: " << original_bytes << " bytes\n";
    std::cout << "  Compressed: " << compressed_bytes << " bytes\n";
    std::cout << "  Reduction: " << (100.0f * (1.0f - 1.0f/compression_ratio)) << "%\n\n";
    
    std::cout << "Numerical Quality:\n";
    std::cout << "  Cosine Similarity: " << cosine_similarity;
    if (cosine_similarity >= QualityGates::PRODUCTION_COSINE) {
        std::cout << " ✅ PRODUCTION\n";
    } else if (cosine_similarity >= QualityGates::STANDARD_COSINE) {
        std::cout << " ✅ STANDARD\n";
    } else if (cosine_similarity >= QualityGates::EXPERIMENTAL_COSINE) {
        std::cout << " ⚠️ EXPERIMENTAL\n";
    } else {
        std::cout << " ❌ FAIL\n";
    }
    
    std::cout << "  RMSE: " << rmse;
    if (rmse <= QualityGates::PRODUCTION_RMSE) {
        std::cout << " ✅ PRODUCTION\n";
    } else if (rmse <= QualityGates::STANDARD_RMSE) {
        std::cout << " ✅ STANDARD\n";
    } else if (rmse <= QualityGates::EXPERIMENTAL_RMSE) {
        std::cout << " ⚠️ EXPERIMENTAL\n";
    } else {
        std::cout << " ❌ FAIL\n";
    }
    
    std::cout << "  Max Error: " << max_absolute_error;
    if (max_absolute_error <= QualityGates::PRODUCTION_MAX_ERROR) {
        std::cout << " ✅ PRODUCTION\n";
    } else if (max_absolute_error <= QualityGates::STANDARD_MAX_ERROR) {
        std::cout << " ✅ STANDARD\n";
    } else if (max_absolute_error <= QualityGates::EXPERIMENTAL_MAX_ERROR) {
        std::cout << " ⚠️ EXPERIMENTAL\n";
    } else {
        std::cout << " ❌ FAIL\n";
    }
    
    std::cout << "\nAnomaly Detection:\n";
    std::cout << "  Overflow: " << (overflow_detected ? "❌ YES" : "✅ NO") << "\n";
    std::cout << "  Underflow: " << (underflow_detected ? "❌ YES" : "✅ NO") << "\n";
    std::cout << "  NaN: " << (nan_detected ? "❌ YES" : "✅ NO") << "\n";
    std::cout << "  Inf: " << (inf_detected ? "❌ YES" : "✅ NO") << "\n";
    std::cout << "  Denormals: " << (denormal_detected ? "⚠️ YES" : "✅ NO") << "\n";
    
    if (!warnings.empty()) {
        std::cout << "\nWarnings:\n";
        for (const auto& w : warnings) {
            std::cout << "  ⚠️ " << w << "\n";
        }
    }
    
    std::cout << "\nValidation: " << (valid ? "✅ APPROVED" : "❌ REJECTED") << "\n";
    if (!valid && !rejection_reason.empty()) {
        std::cout << "Reason: " << rejection_reason << "\n";
    }
    
    std::cout << "═══════════════════════════════════════════════════════════════\n";
}

bool QuantizationReport::operator==(const QuantizationReport& other) const {
    return std::abs(compression_ratio - other.compression_ratio) < 0.01f &&
           std::abs(cosine_similarity - other.cosine_similarity) < 0.0001f &&
           std::abs(rmse - other.rmse) < 0.0001f &&
           valid == other.valid;
}

// ============================================================================
// Profile Constraints
// ============================================================================

bool ProfileConstraints::Validate() const {
    if (min_ratio < 1.0f || max_ratio > 32.0f) return false;
    if (min_ratio >= max_ratio) return false;
    if (min_cosine < 0.0f || min_cosine > 1.0f) return false;
    if (max_rmse < 0.0f) return false;
    if (max_error < 0.0f) return false;
    if (max_block_size == 0 || max_block_size > 4096) return false;
    return true;
}

// ============================================================================
// Quantization Guard Implementation
// ============================================================================

QuantizationGuard::QuantizationGuard() {
    // Default to standard gates
    policy_.min_cosine = QualityGates::STANDARD_COSINE;
    policy_.max_rmse = QualityGates::STANDARD_RMSE;
    policy_.max_error = QualityGates::STANDARD_MAX_ERROR;
}

QuantizationReport QuantizationGuard::ValidateProfile(
    CompressionCodec* codec,
    const ProfileConstraints& constraints
) {
    QuantizationReport report;
    
    if (!codec) {
        report.valid = false;
        report.rejection_reason = "Null codec pointer";
        return report;
    }
    
    if (!constraints.Validate()) {
        report.valid = false;
        report.rejection_reason = "Invalid constraints";
        return report;
    }
    
    // Generate test tensor
    const size_t TEST_SIZE = 4096;
    std::vector<float> test_data(TEST_SIZE);
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 0.1f);
    
    for (size_t i = 0; i < TEST_SIZE; i++) {
        test_data[i] = dist(rng);
    }
    
    // Compress
    size_t compressed_size = codec->GetCompressedSize(TEST_SIZE);
    std::vector<uint8_t> compressed(compressed_size);
    size_t actual_size = codec->EncodeBlock(test_data.data(), compressed.data(), TEST_SIZE);
    
    // Decompress
    std::vector<float> reconstructed(TEST_SIZE);
    codec->DecodeBlock(compressed.data(), reconstructed.data(), TEST_SIZE);
    
    // Fill report
    report.original_bytes = TEST_SIZE * sizeof(float);
    report.compressed_bytes = actual_size;
    report.compression_ratio = static_cast<float>(report.original_bytes) / static_cast<float>(actual_size);
    
    // Numerical analysis
    AnalyzeNumericalHealth(test_data.data(), reconstructed.data(), TEST_SIZE, &report);
    
    // Check codec self-test
    if (!codec->SelfTest()) {
        report.warnings.push_back("Codec self-test failed");
    }
    
    // Validate against gates
    report.valid = PassesQualityGates(report) && PassesHardLimits(report);
    
    if (!report.valid && report.rejection_reason.empty()) {
        if (!PassesHardLimits(report)) {
            report.rejection_reason = "Failed hard numerical limits";
        } else {
            report.rejection_reason = "Failed quality gates";
        }
    }
    
    return report;
}

QuantizationReport QuantizationGuard::QuickValidate(CompressionCodec* codec) {
    ProfileConstraints quick;
    quick.min_cosine = QualityGates::STANDARD_COSINE;
    quick.max_rmse = QualityGates::STANDARD_RMSE;
    quick.max_error = QualityGates::STANDARD_MAX_ERROR;
    return ValidateProfile(codec, quick);
}

QuantizationReport QuantizationGuard::ProductionValidate(CompressionCodec* codec) {
    ProfileConstraints prod;
    prod.min_cosine = QualityGates::PRODUCTION_COSINE;
    prod.max_rmse = QualityGates::PRODUCTION_RMSE;
    prod.max_error = QualityGates::PRODUCTION_MAX_ERROR;
    prod.require_finite = true;
    prod.require_no_nan = true;
    prod.require_no_inf = true;
    return ValidateProfile(codec, prod);
}

std::unique_ptr<CompressionCodec> QuantizationGuard::AutoSelect(
    const ProfileConstraints& constraints
) {
    // Try codecs in order of preference
    CompressionType candidates[] = {
        CompressionType::Q4_0,
        CompressionType::Q4_K,
        CompressionType::Q8_0
    };
    
    for (auto type : candidates) {
        auto codec = CodecFactory::Create(type);
        if (!codec) continue;
        
        auto report = ValidateProfile(codec.get(), constraints);
        if (report.valid) {
            return codec;
        }
    }
    
    return nullptr;
}

float QuantizationGuard::FindOptimalRatio(
    CompressionType base_type,
    const ProfileConstraints& constraints
) {
    auto codec = CodecFactory::Create(base_type);
    if (!codec) return 0.0f;
    
    auto report = ValidateProfile(codec.get(), constraints);
    return report.valid ? report.compression_ratio : 0.0f;
}

bool QuantizationGuard::CheckNumericalHealth(
    const float* data,
    size_t count,
    QuantizationReport* report
) {
    bool healthy = true;
    
    for (size_t i = 0; i < count; i++) {
        if (std::isnan(data[i])) {
            if (report) report->nan_detected = true;
            healthy = false;
        }
        if (std::isinf(data[i])) {
            if (report) report->inf_detected = true;
            healthy = false;
        }
        if (std::abs(data[i]) > 1e6f) {
            if (report) report->overflow_detected = true;
        }
        if (std::abs(data[i]) < 1e-38f && data[i] != 0.0f) {
            if (report) report->denormal_detected = true;
        }
    }
    
    return healthy;
}

bool QuantizationGuard::ValidateFP16Reconstruction(
    float original_scale,
    uint16_t fp16_encoded,
    float tolerance
) {
    float reconstructed = NumericalUtils::FP16ToFloat(fp16_encoded);
    float relative_error = std::abs(original_scale - reconstructed) / original_scale;
    return relative_error <= tolerance;
}

bool QuantizationGuard::ValidateQuantizationRange(
    const float* weights,
    size_t count,
    int bits,
    float* out_scale
) {
    float max_abs = 0.0f;
    for (size_t i = 0; i < count; i++) {
        max_abs = std::max(max_abs, std::abs(weights[i]));
    }
    
    if (max_abs == 0.0f) {
        if (out_scale) *out_scale = 1.0f;
        return true;
    }
    
    float scale = max_abs / ((1 << (bits - 1)) - 1);
    
    // Check if scale is representable
    if (!NumericalUtils::IsValidFP16(scale)) {
        return false;
    }
    
    if (out_scale) *out_scale = scale;
    return true;
}

void QuantizationGuard::SetPolicy(const ProfileConstraints& policy) {
    policy_ = policy;
}

void QuantizationGuard::SetValidationCallback(
    std::function<bool(const QuantizationReport&)> callback
) {
    custom_validator_ = callback;
}

bool QuantizationGuard::PassesQualityGates(const QuantizationReport& report) const {
    if (report.cosine_similarity < policy_.min_cosine) return false;
    if (report.rmse > policy_.max_rmse) return false;
    if (report.max_absolute_error > policy_.max_error) return false;
    return true;
}

bool QuantizationGuard::PassesHardLimits(const QuantizationReport& report) const {
    if (report.cosine_similarity < QualityGates::HARD_COSINE_MIN) return false;
    if (report.rmse > QualityGates::HARD_RMSE_MAX) return false;
    if (report.max_absolute_error > QualityGates::HARD_ERROR_MAX) return false;
    if (report.nan_detected) return false;
    if (report.inf_detected) return false;
    if (strict_mode_ && !report.warnings.empty()) return false;
    if (custom_validator_ && !custom_validator_(report)) return false;
    return true;
}

void QuantizationGuard::AnalyzeNumericalHealth(
    const float* original,
    const float* reconstructed,
    size_t count,
    QuantizationReport* report
) {
    if (!report) return;
    
    double sum_orig = 0.0, sum_recon = 0.0;
    double sum_orig_sq = 0.0, sum_recon_sq = 0.0;
    double dot_product = 0.0;
    double sum_squared_error = 0.0;
    
    report->max_absolute_error = 0.0f;
    report->mean_absolute_error = 0.0f;
    
    for (size_t i = 0; i < count; i++) {
        float orig = original[i];
        float recon = reconstructed[i];
        
        // Anomaly detection
        if (std::isnan(recon)) report->nan_detected = true;
        if (std::isinf(recon)) report->inf_detected = true;
        if (std::abs(recon) > 1e6f) report->overflow_detected = true;
        
        // Error metrics
        float error = std::abs(orig - recon);
        report->max_absolute_error = std::max(report->max_absolute_error, error);
        report->mean_absolute_error += error;
        sum_squared_error += error * error;
        
        // Statistics
        sum_orig += orig;
        sum_recon += recon;
        sum_orig_sq += orig * orig;
        sum_recon_sq += recon * recon;
        dot_product += orig * recon;
    }
    
    report->mean_absolute_error /= static_cast<float>(count);
    report->rmse = static_cast<float>(std::sqrt(sum_squared_error / count));
    
    // Cosine similarity
    double norm_orig = std::sqrt(sum_orig_sq);
    double norm_recon = std::sqrt(sum_recon_sq);
    if (norm_orig > 0 && norm_recon > 0) {
        report->cosine_similarity = static_cast<float>(dot_product / (norm_orig * norm_recon));
    } else {
        report->cosine_similarity = 0.0f;
    }
    
    // Correlation coefficient
    double mean_orig = sum_orig / count;
    double mean_recon = sum_recon / count;
    double cov = dot_product - count * mean_orig * mean_recon;
    double var_orig = sum_orig_sq - count * mean_orig * mean_orig;
    double var_recon = sum_recon_sq - count * mean_recon * mean_recon;
    
    if (var_orig > 0 && var_recon > 0) {
        report->correlation_coefficient = static_cast<float>(cov / std::sqrt(var_orig * var_recon));
    } else {
        report->correlation_coefficient = 0.0f;
    }
    
    report->original_mean = static_cast<float>(mean_orig);
    report->reconstructed_mean = static_cast<float>(mean_recon);
}

// ============================================================================
// Compression Optimizer
// ============================================================================

CompressionOptimizer::CompressionOptimizer() {
    // Default constraints
    constraints_.target_ratio = 6.0f;
    constraints_.min_cosine = QualityGates::STANDARD_COSINE;
    constraints_.max_rmse = QualityGates::STANDARD_RMSE;
}

CompressionOptimizer& CompressionOptimizer::TargetRatio(float ratio) {
    constraints_.target_ratio = ratio;
    constraints_.min_ratio = ratio * 0.8f;
    constraints_.max_ratio = ratio * 1.2f;
    return *this;
}

CompressionOptimizer& CompressionOptimizer::MinimumCosine(float cosine) {
    constraints_.min_cosine = cosine;
    return *this;
}

CompressionOptimizer& CompressionOptimizer::MaximumRMSE(float rmse) {
    constraints_.max_rmse = rmse;
    return *this;
}

CompressionOptimizer& CompressionOptimizer::MaximumError(float error) {
    constraints_.max_error = error;
    return *this;
}

CompressionOptimizer& CompressionOptimizer::RequireFused(bool fused) {
    constraints_.prefer_fused_decode = fused;
    return *this;
}

CompressionOptimizer& CompressionOptimizer::AllowMixedPrecision(bool allow) {
    constraints_.allow_mixed_precision = allow;
    return *this;
}

CompressionOptimizer& CompressionOptimizer::MaxBlockSize(uint32_t size) {
    constraints_.max_block_size = size;
    return *this;
}

std::unique_ptr<CompressionCodec> CompressionOptimizer::Select() {
    auto result = guard_.AutoSelect(constraints_);
    if (result) {
        last_report_ = guard_.ValidateProfile(result.get(), constraints_);
    }
    return result;
}

std::vector<std::pair<std::unique_ptr<CompressionCodec>, QuantizationReport>>
CompressionOptimizer::GetAllValidProfiles() {
    std::vector<std::pair<std::unique_ptr<CompressionCodec>, QuantizationReport>> results;
    
    CompressionType types[] = {
        CompressionType::Q8_0,
        CompressionType::Q4_0,
        CompressionType::Q4_K
    };
    
    for (auto type : types) {
        auto codec = CodecFactory::Create(type);
        if (!codec) continue;
        
        auto report = guard_.ValidateProfile(codec.get(), constraints_);
        if (report.valid) {
            results.emplace_back(std::move(codec), report);
        }
    }
    
    // Sort by compression ratio (descending)
    std::sort(results.begin(), results.end(),
        [](const auto& a, const auto& b) {
            return a.second.compression_ratio > b.second.compression_ratio;
        });
    
    return results;
}

// ============================================================================
// Numerical Utilities
// ============================================================================

uint16_t NumericalUtils::FloatToFP16(float value) {
    // Simple FP32 to FP16 conversion
    // Real implementation would use proper IEEE 754 rounding
    uint32_t f32 = *reinterpret_cast<uint32_t*>(&value);
    uint32_t sign = (f32 >> 31) & 0x1;
    uint32_t exponent = (f32 >> 23) & 0xFF;
    uint32_t mantissa = f32 & 0x7FFFFF;
    
    if (exponent == 0xFF) {
        // Inf or NaN
        return (sign << 15) | 0x7C00 | (mantissa ? 0x200 : 0);
    }
    
    if (exponent == 0) {
        // Denormal or zero
        return sign << 15;
    }
    
    // Normal number
    int16_t new_exp = static_cast<int16_t>(exponent) - 127 + 15;
    if (new_exp >= 31) {
        // Overflow to infinity
        return (sign << 15) | 0x7C00;
    }
    if (new_exp <= 0) {
        // Underflow to zero
        return sign << 15;
    }
    
    uint32_t new_mantissa = mantissa >> 13;
    return static_cast<uint16_t>((sign << 15) | (new_exp << 10) | new_mantissa);
}

float NumericalUtils::FP16ToFloat(uint16_t value) {
    uint32_t sign = (value >> 15) & 0x1;
    uint32_t exponent = (value >> 10) & 0x1F;
    uint32_t mantissa = value & 0x3FF;
    
    if (exponent == 0) {
        if (mantissa == 0) {
            // Zero
            return sign ? -0.0f : 0.0f;
        }
        // Denormal
        float result = static_cast<float>(mantissa) / 1024.0f;
        return sign ? -result * 1.18e-38f : result * 1.18e-38f;
    }
    
    if (exponent == 31) {
        if (mantissa == 0) {
            // Infinity
            return sign ? -INFINITY : INFINITY;
        }
        // NaN
        return NAN;
    }
    
    // Normal number
    uint32_t f32 = (sign << 31) | ((exponent + 112) << 23) | (mantissa << 13);
    return *reinterpret_cast<float*>(&f32);
}

bool NumericalUtils::IsValidFP16(float value) {
    uint16_t fp16 = FloatToFP16(value);
    float reconstructed = FP16ToFloat(fp16);
    float relative_error = std::abs(value - reconstructed) / (std::abs(value) + 1e-8f);
    return relative_error < 0.01f;  // 1% tolerance
}

int NumericalUtils::QuantizeFloat(float value, float scale, int bits) {
    int max_val = (1 << (bits - 1)) - 1;
    int quantized = static_cast<int>(std::round(value / scale));
    return std::max(-max_val - 1, std::min(max_val, quantized));
}

float NumericalUtils::DequantizeInt(int value, float scale, int bits) {
    (void)bits;  // Unused in this implementation
    return static_cast<float>(value) * scale;
}

void NumericalUtils::ComputeStatistics(
    const float* data,
    size_t count,
    float* mean,
    float* std_dev,
    float* min_val,
    float* max_val
) {
    if (count == 0) return;
    
    double sum = 0.0;
    double sum_sq = 0.0;
    float min_v = data[0];
    float max_v = data[0];
    
    for (size_t i = 0; i < count; i++) {
        sum += data[i];
        sum_sq += data[i] * data[i];
        min_v = std::min(min_v, data[i]);
        max_v = std::max(max_v, data[i]);
    }
    
    if (mean) *mean = static_cast<float>(sum / count);
    if (std_dev) {
        double variance = (sum_sq / count) - (sum / count) * (sum / count);
        *std_dev = static_cast<float>(std::sqrt(std::max(0.0, variance)));
    }
    if (min_val) *min_val = min_v;
    if (max_val) *max_val = max_v;
}

float NumericalUtils::StableCosineSimilarity(
    const float* a,
    const float* b,
    size_t count
) {
    double dot = 0.0;
    double norm_a = 0.0;
    double norm_b = 0.0;
    
    for (size_t i = 0; i < count; i++) {
        dot += static_cast<double>(a[i]) * static_cast<double>(b[i]);
        norm_a += static_cast<double>(a[i]) * static_cast<double>(a[i]);
        norm_b += static_cast<double>(b[i]) * static_cast<double>(b[i]);
    }
    
    if (norm_a == 0.0 || norm_b == 0.0) return 0.0f;
    return static_cast<float>(dot / std::sqrt(norm_a * norm_b));
}

bool NumericalUtils::ContainsNaN(const float* data, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (std::isnan(data[i])) return true;
    }
    return false;
}

bool NumericalUtils::ContainsInf(const float* data, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (std::isinf(data[i])) return true;
    }
    return false;
}

bool NumericalUtils::ContainsDenormal(const float* data, size_t count) {
    for (size_t i = 0; i < count; i++) {
        float abs_val = std::abs(data[i]);
        if (abs_val > 0.0f && abs_val < 1.17549435e-38f) return true;
    }
    return false;
}

bool NumericalUtils::AllFinite(const float* data, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (!std::isfinite(data[i])) return false;
    }
    return true;
}

} // namespace compression
} // namespace rawrxd
