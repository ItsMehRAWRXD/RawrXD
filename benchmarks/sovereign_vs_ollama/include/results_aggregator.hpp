// Results Aggregator and Composite Scoring
// Computes SIS, SAI, and other composite metrics
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include "json_reporter.hpp"
#include <map>
#include <vector>
#include <algorithm>

namespace rawrxd::benchmark {

// ============================================================================
// Composite Score Weights
// ============================================================================
struct ScoreWeights {
    // SIS (Sovereign Intelligence Score) weights
    static constexpr double INFERENCE = 0.15;
    static constexpr double AGENT_SPEED = 0.15;
    static constexpr double PLANNING = 0.15;
    static constexpr double SEG_EFFICIENCY = 0.15;
    static constexpr double SWARM = 0.15;
    static constexpr double DECISION = 0.10;
    static constexpr double RECOVERY = 0.10;
    static constexpr double RESPONSE_QUALITY = 0.05;
    
    // Sub-score weights
    static constexpr double LATENCY_WEIGHT = 0.30;
    static constexpr double THROUGHPUT_WEIGHT = 0.40;
    static constexpr double SUCCESS_WEIGHT = 0.20;
    static constexpr double QUALITY_WEIGHT = 0.10;
};

// ============================================================================
// Category Scores
// ============================================================================
struct CategoryScore {
    std::string category_name;
    double raw_score = 0.0;           // 0-100
    double normalized_score = 0.0;    // Normalized against baseline
    double weight = 0.0;
    double weighted_score = 0.0;    // normalized * weight
    
    // Component breakdown
    double latency_score = 0.0;
    double throughput_score = 0.0;
    double success_score = 0.0;
    double quality_score = 0.0;
    
    // Comparison metrics
    double vs_baseline_delta = 0.0;   // vs reference baseline
    double vs_ollama_delta = 0.0;     // vs Ollama (if applicable)
};

// ============================================================================
// Composite Scores
// ============================================================================
struct CompositeScores {
    // Primary scores
    double sis = 0.0;                    // Sovereign Intelligence Score (0-100)
    double sai = 0.0;                    // Sovereign Advantage Index (%)
    double autonomy_delta = 0.0;         // Autonomy improvement (%)
    double swarm_efficiency_ratio = 0.0; // Swarm parallel efficiency
    double decision_quality_score = 0.0; // Decision-making quality
    double response_depth_score = 0.0;   // Response depth
    double context_fidelity_score = 0.0; // Context handling
    double recovery_success_rate = 0.0;  // Self-correction success
    
    // Sub-scores
    double inference_score = 0.0;
    double agentic_score = 0.0;
    double orchestration_score = 0.0;
    double reliability_score = 0.0;
    double quality_score = 0.0;
    double efficiency_score = 0.0;
    
    // Category breakdown
    std::map<std::string, CategoryScore> category_scores;
    
    std::string ToJson() const;
    std::string ToMarkdown() const;
};

// ============================================================================
// Results Aggregator
// ============================================================================
class ResultsAggregator {
public:
    struct AggregationConfig {
        BackendType baseline_backend = BackendType::OLLAMA;
        BackendType target_backend = BackendType::SOVEREIGN;
        bool normalize_scores = true;
        double baseline_reference_tps = 80.0; // Reference TPS for normalization
    };
    
    ResultsAggregator(const AggregationConfig& config = AggregationConfig{})
        : config_(config) {}
    
    // Aggregate results from multiple benchmarks
    CompositeScores Aggregate(const std::vector<BenchmarkResult>& results) {
        CompositeScores scores;
        
        // Group by category
        std::map<BenchmarkCategory, std::vector<BenchmarkResult>> by_category;
        for (const auto& result : results) {
            by_category[result.category].push_back(result);
        }
        
        // Calculate category scores
        for (const auto& [category, cat_results] : by_category) {
            auto cat_score = CalculateCategoryScore(category, cat_results);
            scores.category_scores[CategoryToString(category)] = cat_score;
        }
        
        // Calculate composite scores
        scores.sis = CalculateSIS(scores.category_scores);
        scores.sai = CalculateSAI(scores.category_scores);
        scores.autonomy_delta = CalculateAutonomyDelta(scores.category_scores);
        scores.swarm_efficiency_ratio = CalculateSwarmEfficiency(scores.category_scores);
        scores.decision_quality_score = GetCategoryScore(scores.category_scores, "decision_making");
        scores.response_depth_score = GetCategoryScore(scores.category_scores, "response_quality");
        scores.context_fidelity_score = GetCategoryScore(scores.category_scores, "context_handling");
        scores.recovery_success_rate = GetCategoryScore(scores.category_scores, "self_correction");
        
        // Calculate sub-scores
        scores.inference_score = GetCategoryScore(scores.category_scores, "inference");
        scores.agentic_score = CalculateAgenticScore(scores.category_scores);
        scores.orchestration_score = CalculateOrchestrationScore(scores.category_scores);
        scores.reliability_score = CalculateReliabilityScore(scores.category_scores);
        scores.quality_score = GetCategoryScore(scores.category_scores, "response_quality");
        scores.efficiency_score = CalculateEfficiencyScore(scores.category_scores);
        
        return scores;
    }
    
    // Compare two sets of results (e.g., Sovereign vs Ollama)
    std::string GenerateComparisonReport(
        const std::vector<BenchmarkResult>& sovereign_results,
        const std::vector<BenchmarkResult>& ollama_results) {
        
        auto sovereign_scores = Aggregate(sovereign_results);
        auto ollama_scores = Aggregate(ollama_results);
        
        // Calculate deltas
        sovereign_scores.sai = ((sovereign_scores.sis - ollama_scores.sis) / ollama_scores.sis) * 100.0;
        
        std::stringstream report;
        report << "# Sovereign vs Ollama Benchmark Comparison\n\n";
        report << "**Generated:** " << GetTimestamp() << "\n\n";
        
        // Executive Summary
        report << "## Executive Summary\n\n";
        report << "| Metric | Sovereign | Ollama | Delta |\n";
        report << "|--------|-----------|--------|-------|\n";
        report << "| **SIS** | " << std::fixed << std::setprecision(1) << sovereign_scores.sis;
        report << " | " << ollama_scores.sis;
        report << " | " << std::showpos << sovereign_scores.sai << std::noshowpos << "% |\n";
        report << "| Inference | " << sovereign_scores.inference_score;
        report << " | " << ollama_scores.inference_score;
        report << " | " << CalculateDelta(sovereign_scores.inference_score, ollama_scores.inference_score) << "% |\n";
        report << "| Agentic | " << sovereign_scores.agentic_score;
        report << " | " << ollama_scores.agentic_score;
        report << " | " << CalculateDelta(sovereign_scores.agentic_score, ollama_scores.agentic_score) << "% |\n";
        report << "| Orchestration | " << sovereign_scores.orchestration_score;
        report << " | " << ollama_scores.orchestration_score;
        report << " | " << CalculateDelta(sovereign_scores.orchestration_score, ollama_scores.orchestration_score) << "% |\n";
        report << "| Reliability | " << sovereign_scores.reliability_score;
        report << " | " << ollama_scores.reliability_score;
        report << " | " << CalculateDelta(sovereign_scores.reliability_score, ollama_scores.reliability_score) << "% |\n";
        report << "\n";
        
        // Category Breakdown
        report << "## Category Breakdown\n\n";
        report << "| Category | Sovereign | Ollama | Delta |\n";
        report << "|----------|-----------|--------|-------|\n";
        
        for (const auto& [name, score] : sovereign_scores.category_scores) {
            auto ollama_it = ollama_scores.category_scores.find(name);
            if (ollama_it != ollama_scores.category_scores.end()) {
                report << "| " << name;
                report << " | " << score.raw_score;
                report << " | " << ollama_it->second.raw_score;
                report << " | " << CalculateDelta(score.raw_score, ollama_it->second.raw_score) << "% |\n";
            }
        }
        report << "\n";
        
        // Final Verdict
        report << "## Final Verdict\n\n";
        report << "### Sovereign Runtime Wins In:\n";
        report << GenerateVerdictList(sovereign_scores, ollama_scores, true);
        report << "\n";
        report << "### Ollama Wins In:\n";
        report << GenerateVerdictList(sovereign_scores, ollama_scores, false);
        report << "\n";
        
        return report.str();
    }
    
    // Statistical comparison result
    struct StatisticalComparison {
        double sovereign_mean = 0.0;
        double ollama_mean = 0.0;
        double delta_percent = 0.0;
        double effect_size = 0.0;  // Cohen's d
        bool is_significant = false;
        double p_value_estimate = 0.0;
        std::string significance_marker; // "***", "**", "*", "ns"
        
        std::string ToString() const {
            std::stringstream ss;
            ss << std::fixed << std::setprecision(1);
            ss << "Sovereign: " << sovereign_mean << " vs Ollama: " << ollama_mean;
            ss << " (Δ" << std::showpos << delta_percent << std::noshowpos << "%, d=" << effect_size;
            ss << ", " << significance_marker << ")";
            return ss.str();
        }
    };
    
    // Perform statistical comparisons between backends
    std::map<std::string, StatisticalComparison> PerformStatisticalComparisons(
        const std::vector<BenchmarkResult>& sovereign_results,
        const std::vector<BenchmarkResult>& ollama_results,
        double confidence_level = 0.95) {
        
        std::map<std::string, StatisticalComparison> comparisons;
        
        // Group by category
        std::map<BenchmarkCategory, std::vector<BenchmarkResult>> sovereign_by_cat;
        std::map<BenchmarkCategory, std::vector<BenchmarkResult>> ollama_by_cat;
        
        for (const auto& r : sovereign_results) {
            sovereign_by_cat[r.category].push_back(r);
        }
        for (const auto& r : ollama_results) {
            ollama_by_cat[r.category].push_back(r);
        }
        
        // Compare each category
        for (const auto& [cat, sov_results] : sovereign_by_cat) {
            auto oll_it = ollama_by_cat.find(cat);
            if (oll_it == ollama_by_cat.end()) continue;
            
            const auto& oll_results = oll_it->second;
            
            // Extract latency samples
            std::vector<double> sov_latencies, oll_latencies;
            for (const auto& r : sov_results) {
                sov_latencies.insert(sov_latencies.end(), r.raw_latencies.begin(), r.raw_latencies.end());
            }
            for (const auto& r : oll_results) {
                oll_latencies.insert(oll_latencies.end(), r.raw_latencies.begin(), r.raw_latencies.end());
            }
            
            if (sov_latencies.empty() || oll_latencies.empty()) continue;
            
            // Calculate metrics with CIs
            auto sov_metrics = StatisticalMetrics::CalculateWithCI(sov_latencies, confidence_level);
            auto oll_metrics = StatisticalMetrics::CalculateWithCI(oll_latencies, confidence_level);
            
            StatisticalComparison comp;
            comp.sovereign_mean = sov_metrics.mean;
            comp.ollama_mean = oll_metrics.mean;
            comp.delta_percent = ((sov_metrics.mean - oll_metrics.mean) / oll_metrics.mean) * 100.0;
            comp.effect_size = sov_metrics.EffectSize(oll_metrics);
            comp.is_significant = sov_metrics.IsSignificantlyDifferent(oll_metrics, confidence_level);
            
            // Estimate p-value based on CI overlap (simplified)
            if (comp.is_significant) {
                double overlap = std::abs(comp.effect_size);
                if (overlap > 1.0) comp.p_value_estimate = 0.001;
                else if (overlap > 0.5) comp.p_value_estimate = 0.01;
                else comp.p_value_estimate = 0.05;
            } else {
                comp.p_value_estimate = 0.1;
            }
            
            // Significance markers
            if (comp.p_value_estimate < 0.001) comp.significance_marker = "***";
            else if (comp.p_value_estimate < 0.01) comp.significance_marker = "**";
            else if (comp.p_value_estimate < 0.05) comp.significance_marker = "*";
            else comp.significance_marker = "ns";
            
            comparisons[CategoryToString(cat)] = comp;
        }
        
        // Overall SIS comparison
        auto sov_overall = Aggregate(sovereign_results);
        auto oll_overall = Aggregate(ollama_results);
        
        StatisticalComparison sis_comp;
        sis_comp.sovereign_mean = sov_overall.sis;
        sis_comp.ollama_mean = oll_overall.sis;
        sis_comp.delta_percent = ((sov_overall.sis - oll_overall.sis) / oll_overall.sis) * 100.0;
        sis_comp.effect_size = 0.8; // Placeholder - would need proper calculation
        sis_comp.is_significant = sis_comp.delta_percent > 10.0; // Threshold
        sis_comp.significance_marker = sis_comp.is_significant ? "***" : "ns";
        comparisons["sis"] = sis_comp;
        
        return comparisons;
    }
    
    std::string InterpretEffectSize(double d) const {
        double abs_d = std::abs(d);
        if (abs_d < 0.2) return "negligible";
        if (abs_d < 0.5) return "small";
        if (abs_d < 0.8) return "medium";
        if (abs_d < 1.2) return "large";
        return "very large";
    }
    
private:
    AggregationConfig config_;
    
    CategoryScore CalculateCategoryScore(BenchmarkCategory category, 
                                        const std::vector<BenchmarkResult>& results) {
        CategoryScore score;
        score.category_name = CategoryToString(category);
        
        if (results.empty()) return score;
        
        // Aggregate metrics across runs
        double total_latency = 0.0;
        double total_throughput = 0.0;
        double total_success = 0.0;
        double total_quality = 0.0;
        
        for (const auto& result : results) {
            total_latency += result.latency.mean;
            total_throughput += result.throughput.mean;
            total_success += result.success_rate;
            total_quality += result.quality.overall_score;
        }
        
        double n = static_cast<double>(results.size());
        
        // Normalize each component (0-100)
        // Lower latency = higher score
        score.latency_score = std::max(0.0, 100.0 - (total_latency / n) / 10.0);
        score.throughput_score = std::min(100.0, (total_throughput / n));
        score.success_score = (total_success / n) * 100.0;
        score.quality_score = total_quality / n;
        
        // Weighted composite
        score.raw_score = 
            score.latency_score * ScoreWeights::LATENCY_WEIGHT +
            score.throughput_score * ScoreWeights::THROUGHPUT_WEIGHT +
            score.success_score * ScoreWeights::SUCCESS_WEIGHT +
            score.quality_score * ScoreWeights::QUALITY_WEIGHT;
        
        // Assign category weight
        score.weight = GetCategoryWeight(category);
        score.weighted_score = score.raw_score * score.weight;
        
        return score;
    }
    
    double GetCategoryWeight(BenchmarkCategory category) {
        switch (category) {
            case BenchmarkCategory::INFERENCE: return ScoreWeights::INFERENCE;
            case BenchmarkCategory::AGENT_SPAWN: return ScoreWeights::AGENT_SPEED;
            case BenchmarkCategory::SWARM: return ScoreWeights::SWARM;
            case BenchmarkCategory::SEG_EXECUTION: return ScoreWeights::SEG_EFFICIENCY;
            case BenchmarkCategory::DECISION_MAKING: return ScoreWeights::DECISION;
            case BenchmarkCategory::SELF_CORRECTION: return ScoreWeights::RECOVERY;
            case BenchmarkCategory::RESPONSE_QUALITY: return ScoreWeights::RESPONSE_QUALITY;
            case BenchmarkCategory::CONTEXT_HANDLING: return ScoreWeights::PLANNING;
            case BenchmarkCategory::AUTONOMOUS_RUNTIME: return ScoreWeights::PLANNING;
            case BenchmarkCategory::RESOURCE_USAGE: return 0.0; // Not in SIS
            default: return 0.0;
        }
    }
    
    double CalculateSIS(const std::map<std::string, CategoryScore>& categories) {
        double sis = 0.0;
        for (const auto& [name, score] : categories) {
            sis += score.weighted_score;
        }
        return std::min(sis, 100.0);
    }
    
    double CalculateSAI(const std::map<std::string, CategoryScore>& categories) {
        // Sovereign Advantage Index: weighted average of advantages
        // This would compare against baseline, simplified here
        double total_advantage = 0.0;
        double total_weight = 0.0;
        
        for (const auto& [name, score] : categories) {
            total_advantage += score.vs_baseline_delta * score.weight;
            total_weight += score.weight;
        }
        
        return total_weight > 0 ? total_advantage / total_weight : 0.0;
    }
    
    double CalculateAutonomyDelta(const std::map<std::string, CategoryScore>& categories) {
        // Focus on autonomous-related categories
        double autonomy_score = 0.0;
        double weight = 0.0;
        
        auto add_if_present = [&](const std::string& name, double w) {
            auto it = categories.find(name);
            if (it != categories.end()) {
                autonomy_score += it->second.raw_score * w;
                weight += w;
            }
        };
        
        add_if_present("decision_making", 0.3);
        add_if_present("self_correction", 0.3);
        add_if_present("autonomous_runtime", 0.4);
        
        return weight > 0 ? autonomy_score / weight : 0.0;
    }
    
    double CalculateSwarmEfficiency(const std::map<std::string, CategoryScore>& categories) {
        auto it = categories.find("swarm");
        if (it != categories.end()) {
            return it->second.raw_score;
        }
        return 0.0;
    }
    
    double GetCategoryScore(const std::map<std::string, CategoryScore>& categories, 
                           const std::string& name) {
        auto it = categories.find(name);
        if (it != categories.end()) {
            return it->second.raw_score;
        }
        return 0.0;
    }
    
    double CalculateAgenticScore(const std::map<std::string, CategoryScore>& categories) {
        double score = 0.0;
        double weight = 0.0;
        
        auto add_if_present = [&](const std::string& name, double w) {
            auto it = categories.find(name);
            if (it != categories.end()) {
                score += it->second.raw_score * w;
                weight += w;
            }
        };
        
        add_if_present("agent_spawn", 0.3);
        add_if_present("swarm", 0.4);
        add_if_present("autonomous_runtime", 0.3);
        
        return weight > 0 ? score / weight : 0.0;
    }
    
    double CalculateOrchestrationScore(const std::map<std::string, CategoryScore>& categories) {
        double score = 0.0;
        double weight = 0.0;
        
        auto add_if_present = [&](const std::string& name, double w) {
            auto it = categories.find(name);
            if (it != categories.end()) {
                score += it->second.raw_score * w;
                weight += w;
            }
        };
        
        add_if_present("seg_execution", 0.4);
        add_if_present("swarm", 0.3);
        add_if_present("decision_making", 0.3);
        
        return weight > 0 ? score / weight : 0.0;
    }
    
    double CalculateReliabilityScore(const std::map<std::string, CategoryScore>& categories) {
        double score = 0.0;
        double weight = 0.0;
        
        auto add_if_present = [&](const std::string& name, double w) {
            auto it = categories.find(name);
            if (it != categories.end()) {
                score += it->second.raw_score * w;
                weight += w;
            }
        };
        
        add_if_present("self_correction", 0.4);
        add_if_present("context_handling", 0.3);
        add_if_present("resource_usage", 0.3);
        
        return weight > 0 ? score / weight : 0.0;
    }
    
    double CalculateEfficiencyScore(const std::map<std::string, CategoryScore>& categories) {
        double score = 0.0;
        double weight = 0.0;
        
        auto add_if_present = [&](const std::string& name, double w) {
            auto it = categories.find(name);
            if (it != categories.end()) {
                score += it->second.raw_score * w;
                weight += w;
            }
        };
        
        add_if_present("inference", 0.3);
        add_if_present("resource_usage", 0.4);
        add_if_present("agent_spawn", 0.3);
        
        return weight > 0 ? score / weight : 0.0;
    }
    
    double CalculateDelta(double sovereign, double ollama) {
        if (ollama == 0.0) return 0.0;
        return ((sovereign - ollama) / ollama) * 100.0;
    }
    
    std::string GenerateVerdictList(const CompositeScores& sovereign, 
                                   const CompositeScores& ollama,
                                   bool sovereign_wins) {
        std::stringstream list;
        
        auto check_category = [&](const std::string& name, double s, double o) {
            if (sovereign_wins && s > o) {
                return "- " + name + " (" + std::to_string(static_cast<int>(s - o)) + " points)\n";
            } else if (!sovereign_wins && o > s) {
                return "- " + name + " (" + std::to_string(static_cast<int>(o - s)) + " points)\n";
            }
            return std::string();
        };
        
        list << check_category("Inference", sovereign.inference_score, ollama.inference_score);
        list << check_category("Agentic Behavior", sovereign.agentic_score, ollama.agentic_score);
        list << check_category("Orchestration", sovereign.orchestration_score, ollama.orchestration_score);
        list << check_category("Reliability", sovereign.reliability_score, ollama.reliability_score);
        list << check_category("Response Quality", sovereign.quality_score, ollama.quality_score);
        list << check_category("Efficiency", sovereign.efficiency_score, ollama.efficiency_score);
        
        return list.str();
    }
    
    static std::string GetTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

} // namespace rawrxd::benchmark
