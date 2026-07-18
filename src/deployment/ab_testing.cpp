// RawrXD A/B Testing
// Phase 9 - Task 14: A/B Testing

#include <windows.h>
#include <vector>
#include <string>
#include <map>
#include <random>
#include <cmath>
#include <mutex>

// A/B test configuration
struct ABTestConfig {
    std::string testId;
    std::string modelA;
    std::string modelB;
    float trafficSplit;      // 0.0 - 1.0 (percentage to model B)
    int minSamples;          // Minimum samples for significance
    float confidenceLevel;   // 0.95 for 95%
    int durationHours;       // Test duration
};

// Metric tracking
struct MetricData {
    double sum;
    double sumSquared;
    int count;
    double min;
    double max;
};

// A/B test results
struct ABTestResults {
    std::string testId;
    int samplesA;
    int samplesB;
    double meanA;
    double meanB;
    double stdDevA;
    double stdDevB;
    double pValue;
    double confidenceInterval;
    bool significant;
    std::string winner;
};

// A/B test manager
class ABTestingManager {
private:
    std::map<std::string, ABTestConfig> activeTests;
    std::map<std::string, std::map<std::string, MetricData>> metrics; // test -> model -> metric
    std::mutex testMutex;
    std::random_device rd;
    std::mt19937 gen;
    
public:
    ABTestingManager() : gen(rd()) {}
    
    bool Initialize() {
        printf("A/B Testing manager initialized\n");
        return true;
    }
    
    // Create new A/B test
    bool CreateTest(const ABTestConfig& config) {
        std::lock_guard<std::mutex> lock(testMutex);
        
        if (activeTests.find(config.testId) != activeTests.end()) {
            printf("Test %s already exists\n", config.testId.c_str());
            return false;
        }
        
        activeTests[config.testId] = config;
        
        // Initialize metrics
        metrics[config.testId][config.modelA] = {};
        metrics[config.testId][config.modelB] = {};
        
        printf("Created A/B test: %s\n", config.testId.c_str());
        printf("  Model A: %s (%.0f%%)\n", config.modelA.c_str(), (1.0f - config.trafficSplit) * 100);
        printf("  Model B: %s (%.0f%%)\n", config.modelB.c_str(), config.trafficSplit * 100);
        
        return true;
    }
    
    // Route request to model A or B
    std::string RouteRequest(const std::string& testId, const std::string& userId) {
        std::lock_guard<std::mutex> lock(testMutex);
        
        auto it = activeTests.find(testId);
        if (it == activeTests.end()) {
            return "";  // Test not found
        }
        
        // Deterministic routing based on user ID
        std::hash<std::string> hasher;
        size_t hash = hasher(userId + testId);
        float normalized = (float)(hash % 1000) / 1000.0f;
        
        if (normalized < it->second.trafficSplit) {
            return it->second.modelB;
        } else {
            return it->second.modelA;
        }
    }
    
    // Record metric for a model
    void RecordMetric(const std::string& testId, const std::string& modelId,
                      const std::string& metricName, double value) {
        std::lock_guard<std::mutex> lock(testMutex);
        
        auto& metric = metrics[testId][modelId + "_" + metricName];
        
        if (metric.count == 0) {
            metric.min = value;
            metric.max = value;
        } else {
            if (value < metric.min) metric.min = value;
            if (value > metric.max) metric.max = value;
        }
        
        metric.sum += value;
        metric.sumSquared += value * value;
        metric.count++;
    }
    
    // Calculate test results
    ABTestResults CalculateResults(const std::string& testId, const std::string& metricName) {
        std::lock_guard<std::mutex> lock(testMutex);
        
        ABTestResults results = {};
        results.testId = testId;
        
        auto it = activeTests.find(testId);
        if (it == activeTests.end()) {
            return results;
        }
        
        const std::string& modelA = it->second.modelA;
        const std::string& modelB = it->second.modelB;
        
        auto& metricA = metrics[testId][modelA + "_" + metricName];
        auto& metricB = metrics[testId][modelB + "_" + metricName];
        
        results.samplesA = metricA.count;
        results.samplesB = metricB.count;
        
        if (metricA.count > 0) {
            results.meanA = metricA.sum / metricA.count;
            double varianceA = (metricA.sumSquared / metricA.count) - (results.meanA * results.meanA);
            results.stdDevA = sqrt(varianceA);
        }
        
        if (metricB.count > 0) {
            results.meanB = metricB.sum / metricB.count;
            double varianceB = (metricB.sumSquared / metricB.count) - (results.meanB * results.meanB);
            results.stdDevB = sqrt(varianceB);
        }
        
        // Calculate p-value using t-test
        if (metricA.count > 1 && metricB.count > 1) {
            results.pValue = CalculatePValue(results);
            results.significant = results.pValue < (1.0 - it->second.confidenceLevel);
        }
        
        // Determine winner
        if (results.significant) {
            if (results.meanB > results.meanA) {
                results.winner = modelB;
            } else {
                results.winner = modelA;
            }
        }
        
        return results;
    }
    
    // Check if test has reached significance
    bool HasReachedSignificance(const std::string& testId, const std::string& metricName) {
        auto results = CalculateResults(testId, metricName);
        
        auto it = activeTests.find(testId);
        if (it == activeTests.end()) return false;
        
        // Check sample size
        if (results.samplesA < it->second.minSamples || 
            results.samplesB < it->second.minSamples) {
            return false;
        }
        
        return results.significant;
    }
    
    // End test and return winner
    std::string EndTest(const std::string& testId, const std::string& metricName) {
        auto results = CalculateResults(testId, metricName);
        
        std::lock_guard<std::mutex> lock(testMutex);
        
        // Remove test
        activeTests.erase(testId);
        metrics.erase(testId);
        
        printf("A/B test %s ended\n", testId.c_str());
        printf("  Winner: %s\n", results.winner.c_str());
        printf("  P-value: %.4f\n", results.pValue);
        
        return results.winner;
    }
    
    // Get active tests
    std::vector<std::string> GetActiveTests() {
        std::lock_guard<std::mutex> lock(testMutex);
        
        std::vector<std::string> tests;
        for (const auto& pair : activeTests) {
            tests.push_back(pair.first);
        }
        return tests;
    }
    
    // Print test status
    void PrintStatus(const std::string& testId) {
        std::lock_guard<std::mutex> lock(testMutex);
        
        auto it = activeTests.find(testId);
        if (it == activeTests.end()) {
            printf("Test %s not found\n", testId.c_str());
            return;
        }
        
        printf("\n=== A/B Test: %s ===\n", testId.c_str());
        printf("Model A: %s\n", it->second.modelA.c_str());
        printf("Model B: %s\n", it->second.modelB.c_str());
        printf("Traffic split: %.0f%% / %.0f%%\n", 
               (1.0f - it->second.trafficSplit) * 100,
               it->second.trafficSplit * 100);
        
        // Show metrics
        for (const auto& metricPair : metrics[testId]) {
            printf("  %s: count=%d, mean=%.4f\n",
                   metricPair.first.c_str(),
                   metricPair.second.count,
                   metricPair.second.count > 0 ? 
                       metricPair.second.sum / metricPair.second.count : 0.0);
        }
    }
    
private:
    double CalculatePValue(const ABTestResults& results) {
        // Simplified t-test p-value calculation
        // In production, would use proper statistical library
        
        if (results.samplesA < 2 || results.samplesB < 2) return 1.0;
        
        double pooledStd = sqrt((results.stdDevA * results.stdDevA + 
                                results.stdDevB * results.stdDevB) / 2.0);
        
        if (pooledStd == 0) return 1.0;
        
        double tStatistic = (results.meanB - results.meanA) / 
                           (pooledStd * sqrt(1.0 / results.samplesA + 1.0 / results.samplesB));
        
        // Simplified p-value (two-tailed)
        double pValue = 2.0 * (1.0 - NormalCDF(fabs(tStatistic)));
        
        return pValue;
    }
    
    double NormalCDF(double x) {
        // Approximation of standard normal CDF
        return 0.5 * (1.0 + erf(x / sqrt(2.0)));
    }
};

// Global instance
static ABTestingManager g_ABTesting;

// C API
extern "C" {

bool ABTesting_Init() {
    return g_ABTesting.Initialize();
}

bool ABTesting_CreateTest(const char* testId, const char* modelA, const char* modelB,
                          float trafficSplit, int minSamples, float confidenceLevel) {
    ABTestConfig config;
    config.testId = testId;
    config.modelA = modelA;
    config.modelB = modelB;
    config.trafficSplit = trafficSplit;
    config.minSamples = minSamples;
    config.confidenceLevel = confidenceLevel;
    config.durationHours = 24;
    
    return g_ABTesting.CreateTest(config);
}

const char* ABTesting_Route(const char* testId, const char* userId) {
    static std::string result;
    result = g_ABTesting.RouteRequest(testId, userId);
    return result.c_str();
}

void ABTesting_RecordMetric(const char* testId, const char* modelId, 
                            const char* metricName, double value) {
    g_ABTesting.RecordMetric(testId, modelId, metricName, value);
}

bool ABTesting_HasSignificance(const char* testId, const char* metricName) {
    return g_ABTesting.HasReachedSignificance(testId, metricName);
}

const char* ABTesting_EndTest(const char* testId, const char* metricName) {
    static std::string winner;
    winner = g_ABTesting.EndTest(testId, metricName);
    return winner.c_str();
}

void ABTesting_PrintStatus(const char* testId) {
    g_ABTesting.PrintStatus(testId);
}

} // extern "C"
