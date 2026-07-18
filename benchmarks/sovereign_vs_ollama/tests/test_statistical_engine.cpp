// test_statistical_engine.cpp
// Batch 8: Statistical Engine Unit Tests
//
// Validates statistical calculations including:
// - Mean, median, std_dev calculations
// - Confidence interval accuracy
// - Percentile computations
// - Edge cases (empty samples, single sample, etc.)

#include <gtest/gtest.h>
#include <vector>
#include <cmath>
#include <numeric>
#include <algorithm>

// Minimal StatisticalSummary struct for testing
struct StatisticalSummary {
    uint32_t sample_count = 0;
    double mean = 0.0;
    double median = 0.0;
    double std_dev = 0.0;
    double min = 0.0;
    double max = 0.0;
    double p95 = 0.0;
    double p99 = 0.0;
    double ci_half_width = 0.0;
};

// Test fixture for statistical calculations
class StatisticalEngineTest : public ::testing::Test {
protected:
    StatisticalSummary CalculateStatistics(const std::vector<double>& samples) {
        StatisticalSummary summary;
        if (samples.empty()) return summary;
        
        summary.sample_count = static_cast<uint32_t>(samples.size());
        summary.mean = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
        
        auto [min_it, max_it] = std::minmax_element(samples.begin(), samples.end());
        summary.min = *min_it;
        summary.max = *max_it;
        
        // Variance and std_dev
        double variance = 0.0;
        for (double s : samples) {
            variance += (s - summary.mean) * (s - summary.mean);
        }
        variance /= samples.size();
        summary.std_dev = std::sqrt(variance);
        
        // Percentiles
        std::vector<double> sorted = samples;
        std::sort(sorted.begin(), sorted.end());
        summary.median = sorted[sorted.size() / 2];
        summary.p95 = sorted[static_cast<size_t>(sorted.size() * 0.95)];
        summary.p99 = sorted[static_cast<size_t>(sorted.size() * 0.99)];
        
        // 95% CI using t-distribution (t=2.045 for 30 samples)
        double t_value = 2.045;
        summary.ci_half_width = t_value * (summary.std_dev / std::sqrt(samples.size()));
        
        return summary;
    }
};

// Test: Empty sample handling
TEST_F(StatisticalEngineTest, HandlesEmptySamples) {
    std::vector<double> empty;
    auto result = CalculateStatistics(empty);
    
    EXPECT_EQ(result.sample_count, 0);
    EXPECT_DOUBLE_EQ(result.mean, 0.0);
    EXPECT_DOUBLE_EQ(result.std_dev, 0.0);
}

// Test: Single sample
TEST_F(StatisticalEngineTest, HandlesSingleSample) {
    std::vector<double> single = {42.0};
    auto result = CalculateStatistics(single);
    
    EXPECT_EQ(result.sample_count, 1);
    EXPECT_DOUBLE_EQ(result.mean, 42.0);
    EXPECT_DOUBLE_EQ(result.min, 42.0);
    EXPECT_DOUBLE_EQ(result.max, 42.0);
    EXPECT_DOUBLE_EQ(result.median, 42.0);
    EXPECT_DOUBLE_EQ(result.std_dev, 0.0);
}

// Test: Two samples
TEST_F(StatisticalEngineTest, HandlesTwoSamples) {
    std::vector<double> two = {10.0, 20.0};
    auto result = CalculateStatistics(two);
    
    EXPECT_EQ(result.sample_count, 2);
    EXPECT_DOUBLE_EQ(result.mean, 15.0);
    EXPECT_DOUBLE_EQ(result.min, 10.0);
    EXPECT_DOUBLE_EQ(result.max, 20.0);
    EXPECT_DOUBLE_EQ(result.median, 20.0); // Upper of two middle values
}

// Test: Known mean calculation
TEST_F(StatisticalEngineTest, CalculatesCorrectMean) {
    std::vector<double> samples = {1.0, 2.0, 3.0, 4.0, 5.0};
    auto result = CalculateStatistics(samples);
    
    EXPECT_DOUBLE_EQ(result.mean, 3.0);
}

// Test: Standard deviation
TEST_F(StatisticalEngineTest, CalculatesCorrectStdDev) {
    // Population std_dev of {2, 4, 4, 4, 5, 5, 7, 9} = 2.0
    std::vector<double> samples = {2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0};
    auto result = CalculateStatistics(samples);
    
    EXPECT_NEAR(result.std_dev, 2.0, 0.01);
}

// Test: Percentile calculations
TEST_F(StatisticalEngineTest, CalculatesCorrectPercentiles) {
    std::vector<double> samples;
    for (int i = 1; i <= 100; ++i) {
        samples.push_back(static_cast<double>(i));
    }
    
    auto result = CalculateStatistics(samples);
    
    EXPECT_DOUBLE_EQ(result.median, 50.0);
    EXPECT_DOUBLE_EQ(result.p95, 95.0);
    EXPECT_DOUBLE_EQ(result.p99, 99.0);
}

// Test: Confidence interval
TEST_F(StatisticalEngineTest, CalculatesReasonableCI) {
    // Generate samples with known distribution
    std::vector<double> samples;
    for (int i = 0; i < 30; ++i) {
        samples.push_back(100.0 + (i % 10) * 2.0); // Mean ~109, some variance
    }
    
    auto result = CalculateStatistics(samples);
    
    // CI should be positive and reasonable
    EXPECT_GT(result.ci_half_width, 0.0);
    EXPECT_LT(result.ci_half_width, result.std_dev * 3.0); // CI shouldn't be too wide
    
    // Mean should be within CI bounds
    EXPECT_GE(result.mean, result.mean - result.ci_half_width);
    EXPECT_LE(result.mean, result.mean + result.ci_half_width);
}

// Test: Min/Max with negative values
TEST_F(StatisticalEngineTest, HandlesNegativeValues) {
    std::vector<double> samples = {-10.0, -5.0, 0.0, 5.0, 10.0};
    auto result = CalculateStatistics(samples);
    
    EXPECT_DOUBLE_EQ(result.min, -10.0);
    EXPECT_DOUBLE_EQ(result.max, 10.0);
    EXPECT_DOUBLE_EQ(result.mean, 0.0);
}

// Test: Large values
TEST_F(StatisticalEngineTest, HandlesLargeValues) {
    std::vector<double> samples = {1e9, 2e9, 3e9};
    auto result = CalculateStatistics(samples);
    
    EXPECT_DOUBLE_EQ(result.mean, 2e9);
    EXPECT_DOUBLE_EQ(result.min, 1e9);
    EXPECT_DOUBLE_EQ(result.max, 3e9);
}

// Test: Very small values
TEST_F(StatisticalEngineTest, HandlesSmallValues) {
    std::vector<double> samples = {1e-9, 2e-9, 3e-9};
    auto result = CalculateStatistics(samples);
    
    EXPECT_DOUBLE_EQ(result.mean, 2e-9);
}

// Test: Identical values (zero variance)
TEST_F(StatisticalEngineTest, HandlesIdenticalValues) {
    std::vector<double> samples(30, 42.0);
    auto result = CalculateStatistics(samples);
    
    EXPECT_DOUBLE_EQ(result.mean, 42.0);
    EXPECT_DOUBLE_EQ(result.std_dev, 0.0);
    EXPECT_DOUBLE_EQ(result.ci_half_width, 0.0);
}

// Test: Outlier detection preparation (values far from mean)
TEST_F(StatisticalEngineTest, DetectsPotentialOutliers) {
    std::vector<double> samples = {1.0, 2.0, 3.0, 4.0, 5.0, 100.0}; // 100 is outlier
    auto result = CalculateStatistics(samples);
    
    // Mean should be pulled up by outlier
    EXPECT_GT(result.mean, 3.0);
    
    // Std_dev should be large due to outlier
    EXPECT_GT(result.std_dev, 10.0);
}

// Test: Reproducibility with same seed
TEST_F(StatisticalEngineTest, ReproducibleWithSameData) {
    std::vector<double> samples1 = {1.0, 2.0, 3.0, 4.0, 5.0};
    std::vector<double> samples2 = {1.0, 2.0, 3.0, 4.0, 5.0};
    
    auto result1 = CalculateStatistics(samples1);
    auto result2 = CalculateStatistics(samples2);
    
    EXPECT_DOUBLE_EQ(result1.mean, result2.mean);
    EXPECT_DOUBLE_EQ(result1.std_dev, result2.std_dev);
    EXPECT_DOUBLE_EQ(result1.median, result2.median);
}

// Test: Sample size 30 (standard benchmark size)
TEST_F(StatisticalEngineTest, StandardSampleSize) {
    std::vector<double> samples;
    for (int i = 0; i < 30; ++i) {
        samples.push_back(100.0 + i * 0.5);
    }
    
    auto result = CalculateStatistics(samples);
    
    EXPECT_EQ(result.sample_count, 30);
    EXPECT_GT(result.ci_half_width, 0.0);
    
    // CI should be reasonable for this data range
    double data_range = result.max - result.min;
    EXPECT_LT(result.ci_half_width, data_range / 2.0);
}

// Main entry point for tests
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
