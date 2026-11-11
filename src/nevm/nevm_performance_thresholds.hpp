//============================================================================
// nevm_performance_thresholds.hpp
// RawrXD N-EVM - Performance Regression Thresholds
// CI-ready pass/fail criteria
//============================================================================

#pragma once

#include <string>
#include <json/json.h>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Performance Budget Structure
//============================================================================

struct PerformanceBudget {
    // Throughput requirements
    float tok_s_min;
    float tok_s_max;  // Optional: catch unexpected speedups too
    
    // Memory requirements
    float memory_max_mb;
    float memory_min_mb;  // Optional: catch under-utilization
    
    // Latency requirements
    float latency_p99_ms_max;
    float latency_p95_ms_max;
    float latency_mean_ms_max;
    
    // Efficiency requirements
    float memory_efficiency_min;  // tok/s per GB
    float throughput_variance_max;  // coefficient of variation
    
    // Regression tolerance
    float regression_threshold_pct;  // e.g., -5% allowed
    
    bool CheckThroughput(float tok_s) const {
        return tok_s >= tok_s_min && (tok_s_max <= 0 || tok_s <= tok_s_max);
    }
    
    bool CheckMemory(float memory_mb) const {
        return memory_mb <= memory_max_mb && 
               (memory_min_mb <= 0 || memory_mb >= memory_min_mb);
    }
    
    bool CheckLatency(float p99_ms, float p95_ms, float mean_ms) const {
        return p99_ms <= latency_p99_ms_max &&
               p95_ms <= latency_p95_ms_max &&
               mean_ms <= latency_mean_ms_max;
    }
    
    bool CheckRegression(float current, float baseline) const {
        if (baseline <= 0) return true;
        float change_pct = (current - baseline) / baseline * 100.0f;
        return change_pct >= regression_threshold_pct;
    }
    
    Json::Value ToJSON() const {
        Json::Value budget;
        budget["tok_s_min"] = tok_s_min;
        budget["tok_s_max"] = tok_s_max;
        budget["memory_max_mb"] = memory_max_mb;
        budget["memory_min_mb"] = memory_min_mb;
        budget["latency_p99_ms_max"] = latency_p99_ms_max;
        budget["latency_p95_ms_max"] = latency_p95_ms_max;
        budget["latency_mean_ms_max"] = latency_mean_ms_max;
        budget["memory_efficiency_min"] = memory_efficiency_min;
        budget["throughput_variance_max"] = throughput_variance_max;
        budget["regression_threshold_pct"] = regression_threshold_pct;
        return budget;
    }
    
    static PerformanceBudget FromJSON(const Json::Value& json) {
        PerformanceBudget budget;
        budget.tok_s_min = json.get("tok_s_min", 0.0f).asFloat();
        budget.tok_s_max = json.get("tok_s_max", 0.0f).asFloat();
        budget.memory_max_mb = json.get("memory_max_mb", 0.0f).asFloat();
        budget.memory_min_mb = json.get("memory_min_mb", 0.0f).asFloat();
        budget.latency_p99_ms_max = json.get("latency_p99_ms_max", 0.0f).asFloat();
        budget.latency_p95_ms_max = json.get("latency_p95_ms_max", 0.0f).asFloat();
        budget.latency_mean_ms_max = json.get("latency_mean_ms_max", 0.0f).asFloat();
        budget.memory_efficiency_min = json.get("memory_efficiency_min", 0.0f).asFloat();
        budget.throughput_variance_max = json.get("throughput_variance_max", 0.0f).asFloat();
        budget.regression_threshold_pct = json.get("regression_threshold_pct", -5.0f).asFloat();
        return budget;
    }
    
    // Predefined budgets for common scenarios
    static PerformanceBudget Conservative() {
        return {
            30.0f,      // tok_s_min
            0.0f,       // tok_s_max (unlimited)
            10240.0f,   // memory_max_mb
            0.0f,       // memory_min_mb
            120.0f,     // latency_p99_ms_max
            100.0f,     // latency_p95_ms_max
            80.0f,      // latency_mean_ms_max
            3.0f,       // memory_efficiency_min
            0.05f,      // throughput_variance_max
            -5.0f       // regression_threshold_pct
        };
    }
    
    static PerformanceBudget Aggressive() {
        return {
            40.0f,      // tok_s_min
            0.0f,       // tok_s_max
            8192.0f,    // memory_max_mb
            0.0f,       // memory_min_mb
            80.0f,      // latency_p99_ms_max
            60.0f,      // latency_p95_ms_max
            50.0f,      // latency_mean_ms_max
            5.0f,       // memory_efficiency_min
            0.03f,      // throughput_variance_max
            -3.0f       // regression_threshold_pct
        };
    }
};

//============================================================================
// Regression Checker
//============================================================================

class RegressionChecker {
public:
    struct CheckResult {
        bool passed;
        std::string metric;
        float current;
        float baseline;
        float change_pct;
        std::string message;
    };
    
    std::vector<CheckResult> results;
    
    void CheckThroughput(float current, float baseline, const PerformanceBudget& budget) {
        CheckResult result;
        result.metric = "throughput";
        result.current = current;
        result.baseline = baseline;
        
        // Check absolute threshold
        if (!budget.CheckThroughput(current)) {
            result.passed = false;
            result.change_pct = 0.0f;
            result.message = "Below minimum threshold: " + 
                           std::to_string(current) + " < " + 
                           std::to_string(budget.tok_s_min);
            results.push_back(result);
            return;
        }
        
        // Check regression
        if (!budget.CheckRegression(current, baseline)) {
            result.passed = false;
            result.change_pct = (current - baseline) / baseline * 100.0f;
            result.message = "Regression detected: " + 
                           std::to_string(result.change_pct) + "% (threshold: " +
                           std::to_string(budget.regression_threshold_pct) + "%)";
            results.push_back(result);
            return;
        }
        
        result.passed = true;
        result.change_pct = baseline > 0 ? (current - baseline) / baseline * 100.0f : 0.0f;
        result.message = "OK";
        results.push_back(result);
    }
    
    void CheckMemory(float current, float baseline, const PerformanceBudget& budget) {
        CheckResult result;
        result.metric = "memory";
        result.current = current;
        result.baseline = baseline;
        
        if (!budget.CheckMemory(current)) {
            result.passed = false;
            result.change_pct = 0.0f;
            result.message = "Exceeds maximum: " + 
                           std::to_string(current) + " > " + 
                           std::to_string(budget.memory_max_mb);
            results.push_back(result);
            return;
        }
        
        result.passed = true;
        result.change_pct = baseline > 0 ? (current - baseline) / baseline * 100.0f : 0.0f;
        result.message = "OK";
        results.push_back(result);
    }
    
    bool AllPassed() const {
        for (const auto& r : results) {
            if (!r.passed) return false;
        }
        return true;
    }
    
    void PrintReport() const {
        std::cout << "\n=== Performance Regression Report ===\n";
        for (const auto& r : results) {
            std::cout << r.metric << ": ";
            std::cout << (r.passed ? "PASS" : "FAIL") << " | ";
            std::cout << "Current: " << r.current << " | ";
            if (r.baseline > 0) {
                std::cout << "Baseline: " << r.baseline << " | ";
                std::cout << "Change: " << r.change_pct << "% | ";
            }
            std::cout << r.message << "\n";
        }
        std::cout << "\n";
    }
};

} // namespace NEVM
} // namespace RawrXD
