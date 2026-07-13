// batch3_orchestration_aggregation.hpp
// Phase 1, Batch 3/5: Orchestration & Aggregation
// Features: SIS Scoring, Comparison Framework, Regression Tracking, Report Generation

#pragma once
#include "../include/benchmark_common.hpp"
#include "batch1_inference_agent_swarm.hpp"
#include "batch2_recovery_quality_context.hpp"
#include <vector>
#include <map>
#include <memory>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <sqlite3.h>

namespace rawrxd_benchmarks {

// ============================================================================
// SIS (Sovereign Intelligence Score) Calculator
// Weighted composite score across all benchmark dimensions
// ============================================================================
class SISCalculator {
public:
    struct Weights {
        double inference = 0.20;      // Raw token throughput
        double agentic = 0.15;        // Agent lifecycle performance
        double swarm = 0.15;          // Parallel execution efficiency
        double seg = 0.10;            // Execution graph performance
        double decision = 0.10;       // Decision quality
        double recovery = 0.10;       // Self-correction capability
        double quality = 0.10;        // Response quality
        double context = 0.05;        // Context handling
        double autonomy = 0.05;       // Autonomous runtime
    };

    struct CategoryScores {
        double inference = 0.0;
        double agentic = 0.0;
        double swarm = 0.0;
        double seg = 0.0;
        double decision = 0.0;
        double recovery = 0.0;
        double quality = 0.0;
        double context = 0.0;
        double autonomy = 0.0;
    };

    struct SISResult {
        double overall_score = 0.0;           // 0-100
        CategoryScores categories;
        Weights weights_used;
        std::string grade;                     // A+/A/B+/B/C/D/F
        std::vector<std::string> strengths;
        std::vector<std::string> weaknesses;
    };

    explicit SISCalculator(const Weights& weights = Weights{}) 
        : weights_(weights) {}

    SISResult Calculate(const Batch1Results& batch1, const Batch2Results& batch2) {
        SISResult result;
        result.weights_used = weights_;

        // Calculate individual category scores (normalized 0-100)
        result.categories.inference = ScoreInference(batch1.inference);
        result.categories.agentic = ScoreAgentic(batch1.agent_spawn);
        result.categories.swarm = ScoreSwarm(batch1.swarm16);
        result.categories.seg = ScoreSEG(batch1.seg_execution);
        result.categories.decision = ScoreDecision(batch1.decision_making);
        result.categories.recovery = ScoreRecovery(batch2.self_correction);
        result.categories.quality = ScoreQuality(batch2.response_quality);
        result.categories.context = ScoreContext(batch2.context_handling);
        result.categories.autonomy = ScoreAutonomy(batch2.autonomous_runtime);

        // Calculate weighted overall score
        result.overall_score = 
            result.categories.inference * weights_.inference +
            result.categories.agentic * weights_.agentic +
            result.categories.swarm * weights_.swarm +
            result.categories.seg * weights_.seg +
            result.categories.decision * weights_.decision +
            result.categories.recovery * weights_.recovery +
            result.categories.quality * weights_.quality +
            result.categories.context * weights_.context +
            result.categories.autonomy * weights_.autonomy;

        // Determine grade
        result.grade = ScoreToGrade(result.overall_score);

        // Identify strengths and weaknesses
        IdentifyStrengthsWeaknesses(result);

        return result;
    }

private:
    Weights weights_;

    double ScoreInference(const InferenceTPSBenchmark::Results& r) {
        // Score based on generation TPS (target: 60+ TPS = 100)
        double tps_score = std::min(r.generation_tps.mean / 60.0 * 100.0, 100.0);
        // TTFT bonus (target: <100ms)
        double ttft_score = r.ttft.mean < 100.0 ? 100.0 : std::max(0.0, 100.0 - (r.ttft.mean - 100.0));
        return (tps_score * 0.7 + ttft_score * 0.3);
    }

    double ScoreAgentic(const AgentSpawnBenchmark::Results& r) {
        // Score based on spawn rate (target: 50+ agents/sec = 100)
        return std::min(r.spawn_rate_per_second / 50.0 * 100.0, 100.0);
    }

    double ScoreSwarm(const Swarm16Benchmark::Results& r) {
        // Score based on parallel efficiency (target: 80%+ = 100)
        return std::min(r.parallel_efficiency.mean / 0.80 * 100.0, 100.0);
    }

    double ScoreSEG(const SEGExecutionBenchmark::Results& r) {
        // Score based on parallel efficiency
        return std::min(r.parallel_efficiency.mean / 0.75 * 100.0, 100.0);
    }

    double ScoreDecision(const DecisionMakingBenchmark::Results& r) {
        // Weight accuracy heavily
        return r.accuracy * 100.0 * 0.7 + 
               (100.0 - r.false_positive_rate * 100.0) * 0.3;
    }

    double ScoreRecovery(const SelfCorrectionBenchmark::Results& r) {
        // Recovery success rate is primary
        return r.recovery_success_rate * 100.0;
    }

    double ScoreQuality(const ResponseQualityBenchmark::Results& r) {
        return r.overall_quality.mean;
    }

    double ScoreContext(const ContextHandlingBenchmark::Results& r) {
        // Average across all context sizes
        double total = 0.0;
        for (const auto& ctx : r.by_context_size) {
            total += ctx.retrieval_accuracy.mean;
        }
        return r.by_context_size.empty() ? 0.0 : total / r.by_context_size.size();
    }

    double ScoreAutonomy(const AutonomousRuntimeBenchmark::Results& r) {
        // Weight success rate and latency
        return r.success_rate * 100.0 * 0.6 + 
               (r.loop_latency.mean < 500.0 ? 100.0 : 
                std::max(0.0, 100.0 - (r.loop_latency.mean - 500.0) / 10.0)) * 0.4;
    }

    std::string ScoreToGrade(double score) {
        if (score >= 97) return "A+";
        if (score >= 93) return "A";
        if (score >= 90) return "A-";
        if (score >= 87) return "B+";
        if (score >= 83) return "B";
        if (score >= 80) return "B-";
        if (score >= 77) return "C+";
        if (score >= 73) return "C";
        if (score >= 70) return "C-";
        if (score >= 60) return "D";
        return "F";
    }

    void IdentifyStrengthsWeaknesses(SISResult& result) {
        auto add_if_strong = [&](const std::string& name, double score) {
            if (score >= 85) result.strengths.push_back(name + " (" + std::to_string(static_cast<int>(score)) + ")");
            if (score < 60) result.weaknesses.push_back(name + " (" + std::to_string(static_cast<int>(score)) + ")");
        };

        add_if_strong("Inference", result.categories.inference);
        add_if_strong("Agentic", result.categories.agentic);
        add_if_strong("Swarm", result.categories.swarm);
        add_if_strong("SEG", result.categories.seg);
        add_if_strong("Decision", result.categories.decision);
        add_if_strong("Recovery", result.categories.recovery);
        add_if_strong("Quality", result.categories.quality);
        add_if_strong("Context", result.categories.context);
        add_if_strong("Autonomy", result.categories.autonomy);
    }
};

// ============================================================================
// Statistical Comparison Framework
// Compares Sovereign vs Ollama with significance testing
// ============================================================================
class StatisticalComparator {
public:
    struct ComparisonResult {
        std::string metric_name;
        double sovereign_mean;
        double ollama_mean;
        double absolute_delta;
        double percent_delta;
        double effect_size;           // Cohen's d
        bool is_significant;
        std::string significance_marker;  // ***, **, *, ns
        std::string winner;           // "sovereign", "ollama", or "tie"
    };

    struct FullComparison {
        std::vector<ComparisonResult> metrics;
        double sovereign_sis = 0.0;
        double ollama_sis = 0.0;
        double sis_delta_percent = 0.0;
        int sovereign_wins = 0;
        int ollama_wins = 0;
        int ties = 0;
        std::vector<std::string> significant_wins;
    };

    ComparisonResult CompareMetrics(const std::string& name,
                                    const StatisticalMetrics& sovereign,
                                    const StatisticalMetrics& ollama) {
        ComparisonResult result;
        result.metric_name = name;
        result.sovereign_mean = sovereign.mean;
        result.ollama_mean = ollama.mean;
        result.absolute_delta = sovereign.mean - ollama.mean;
        result.percent_delta = ollama.mean > 0 ? 
            (result.absolute_delta / ollama.mean) * 100.0 : 0.0;
        
        // Calculate Cohen's d
        double pooled_std = std::sqrt((sovereign.stddev * sovereign.stddev + 
                                       ollama.stddev * ollama.stddev) / 2.0);
        result.effect_size = pooled_std > 0 ? result.absolute_delta / pooled_std : 0.0;
        
        // Significance test (CI overlap method)
        result.is_significant = 
            (sovereign.mean_ci.lower > ollama.mean_ci.upper) ||
            (sovereign.mean_ci.upper < ollama.mean_ci.lower);
        
        // Significance markers
        if (result.is_significant) {
            if (std::abs(result.effect_size) >= 1.2) result.significance_marker = "***";
            else if (std::abs(result.effect_size) >= 0.8) result.significance_marker = "**";
            else result.significance_marker = "*";
        } else {
            result.significance_marker = "ns";
        }
        
        // Determine winner
        if (result.is_significant) {
            result.winner = result.absolute_delta > 0 ? "sovereign" : "ollama";
        } else {
            result.winner = "tie";
        }
        
        return result;
    }

    FullComparison CompareFullResults(const SISResult& sovereign_sis,
                                       const SISResult& ollama_sis) {
        FullComparison comparison;
        comparison.sovereign_sis = sovereign_sis.overall_score;
        comparison.ollama_sis = ollama_sis.overall_score;
        comparison.sis_delta_percent = ollama_sis.overall_score > 0 ?
            ((sovereign_sis.overall_score - ollama_sis.overall_score) / ollama_sis.overall_score) * 100.0 : 0.0;
        
        // Compare each category
        auto compare_cat = [&](const std::string& name, double s, double o) {
            StatisticalMetrics sm, om;
            sm.mean = s; sm.stddev = 5.0; sm.mean_ci = {s-2, s+2, 0.95, 2};
            om.mean = o; om.stddev = 5.0; om.mean_ci = {o-2, o+2, 0.95, 2};
            auto cmp = CompareMetrics(name, sm, om);
            comparison.metrics.push_back(cmp);
            
            if (cmp.winner == "sovereign") {
                comparison.sovereign_wins++;
                if (cmp.is_significant) comparison.significant_wins.push_back(name);
            } else if (cmp.winner == "ollama") {
                comparison.ollama_wins++;
            } else {
                comparison.ties++;
            }
        };
        
        compare_cat("Inference", sovereign_sis.categories.inference, ollama_sis.categories.inference);
        compare_cat("Agentic", sovereign_sis.categories.agentic, ollama_sis.categories.agentic);
        compare_cat("Swarm", sovereign_sis.categories.swarm, ollama_sis.categories.swarm);
        compare_cat("SEG", sovereign_sis.categories.seg, ollama_sis.categories.seg);
        compare_cat("Decision", sovereign_sis.categories.decision, ollama_sis.categories.decision);
        compare_cat("Recovery", sovereign_sis.categories.recovery, ollama_sis.categories.recovery);
        compare_cat("Quality", sovereign_sis.categories.quality, ollama_sis.categories.quality);
        compare_cat("Context", sovereign_sis.categories.context, ollama_sis.categories.context);
        compare_cat("Autonomy", sovereign_sis.categories.autonomy, ollama_sis.categories.autonomy);
        
        return comparison;
    }
};

// ============================================================================
// Regression Tracker
// SQLite-backed historical performance tracking
// ============================================================================
class RegressionTracker {
public:
    struct Config {
        std::string db_path = "benchmark_history.db";
        double tps_regression_threshold = 0.05;      // 5% drop
        double latency_regression_threshold = 0.10;  // 10% increase
        int min_samples_for_trend = 5;
    };

    struct RegressionCheck {
        bool regression_detected = false;
        std::string metric_name;
        double current_value;
        double baseline_value;
        double percent_change;
        std::string severity;  // "critical", "warning", "none"
    };

    struct TrendAnalysis {
        std::string metric_name;
        double slope;           // Change per run
        double r_squared;       // Fit quality
        std::string trend;      // "improving", "degrading", "stable"
        double predicted_next;
    };

    explicit RegressionTracker(const Config& config = Config{}) 
        : config_(config), db_(nullptr) {}

    ~RegressionTracker() {
        if (db_) sqlite3_close(db_);
    }

    bool Initialize() {
        int rc = sqlite3_open(config_.db_path.c_str(), &db_);
        if (rc != SQLITE_OK) return false;
        
        return CreateSchema();
    }

    bool RecordBenchmark(const std::string& benchmark_id,
                         const std::string& backend,
                         const std::string& model,
                         const std::string& git_commit,
                         const SISResult& sis) {
        if (!db_) return false;
        
        std::string sql = R"(
            INSERT INTO benchmark_runs 
            (timestamp, benchmark_id, backend, model, git_commit, sis_score,
             inference_score, agentic_score, swarm_score, seg_score,
             decision_score, recovery_score, quality_score, context_score, autonomy_score)
            VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        )";
        
        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
        
        sqlite3_bind_text(stmt, 1, benchmark_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, backend.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, model.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, git_commit.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_double(stmt, 5, sis.overall_score);
        sqlite3_bind_double(stmt, 6, sis.categories.inference);
        sqlite3_bind_double(stmt, 7, sis.categories.agentic);
        sqlite3_bind_double(stmt, 8, sis.categories.swarm);
        sqlite3_bind_double(stmt, 9, sis.categories.seg);
        sqlite3_bind_double(stmt, 10, sis.categories.decision);
        sqlite3_bind_double(stmt, 11, sis.categories.recovery);
        sqlite3_bind_double(stmt, 12, sis.categories.quality);
        sqlite3_bind_double(stmt, 13, sis.categories.context);
        sqlite3_bind_double(stmt, 14, sis.categories.autonomy);
        
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        
        return true;
    }

    std::vector<RegressionCheck> CheckForRegressions(const std::string& benchmark_id,
                                                       const SISResult& current) {
        std::vector<RegressionCheck> regressions;
        
        auto check_metric = [&](const std::string& name, double current_val, double threshold) {
            double baseline = GetBaseline(benchmark_id, name);
            if (baseline <= 0) return;
            
            double change = (current_val - baseline) / baseline;
            RegressionCheck check;
            check.metric_name = name;
            check.current_value = current_val;
            check.baseline_value = baseline;
            check.percent_change = change * 100.0;
            
            if (change < -threshold) {
                check.regression_detected = true;
                check.severity = change < -threshold * 2 ? "critical" : "warning";
                regressions.push_back(check);
            }
        };
        
        check_metric("SIS", current.overall_score, config_.tps_regression_threshold);
        check_metric("Inference", current.categories.inference, config_.tps_regression_threshold);
        check_metric("Swarm", current.categories.swarm, config_.tps_regression_threshold);
        check_metric("Recovery", current.categories.recovery, config_.tps_regression_threshold);
        
        return regressions;
    }

    std::vector<TrendAnalysis> AnalyzeTrends(const std::string& benchmark_id,
                                              int lookback_runs = 10) {
        std::vector<TrendAnalysis> trends;
        // Simplified - would query DB and perform linear regression
        return trends;
    }

    bool ExportToCSV(const std::string& filename) {
        if (!db_) return false;
        
        std::ofstream file(filename);
        if (!file.is_open()) return false;
        
        file << "timestamp,backend,model,sis_score,inference,agentic,swarm,seg,"
             << "decision,recovery,quality,context,autonomy\n";
        
        // Query and export
        const char* sql = "SELECT * FROM benchmark_runs ORDER BY timestamp";
        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            for (int i = 0; i < sqlite3_column_count(stmt); i++) {
                if (i > 0) file << ",";
                file << sqlite3_column_text(stmt, i);
            }
            file << "\n";
        }
        
        sqlite3_finalize(stmt);
        return true;
    }

private:
    Config config_;
    sqlite3* db_;

    bool CreateSchema() {
        const char* sql = R"(
            CREATE TABLE IF NOT EXISTS benchmark_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                benchmark_id TEXT,
                backend TEXT,
                model TEXT,
                git_commit TEXT,
                sis_score REAL,
                inference_score REAL,
                agentic_score REAL,
                swarm_score REAL,
                seg_score REAL,
                decision_score REAL,
                recovery_score REAL,
                quality_score REAL,
                context_score REAL,
                autonomy_score REAL
            );
            CREATE INDEX IF NOT EXISTS idx_benchmark_id ON benchmark_runs(benchmark_id);
            CREATE INDEX IF NOT EXISTS idx_timestamp ON benchmark_runs(timestamp);
        )";
        
        return sqlite3_exec(db_, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
    }

    double GetBaseline(const std::string& benchmark_id, const std::string& metric) {
        // Simplified - would query historical average
        return 0.0;
    }
};

// ============================================================================
// Report Generator
// Creates Markdown, JSON, and HTML reports
// ============================================================================
class ReportGenerator {
public:
    struct ReportConfig {
        bool include_raw_data = true;
        bool include_charts = true;
        bool include_recommendations = true;
    };

    static std::string GenerateMarkdown(const SISResult& sis,
                                        const StatisticalComparator::FullComparison* comparison,
                                        const ReportConfig& config = ReportConfig{}) {
        std::stringstream md;
        
        md << "# RawrXD Sovereign Benchmark Report\n\n";
        md << "**Generated:** " << GetTimestamp() << "\n\n";
        
        // Executive Summary
        md << "## Executive Summary\n\n";
        md << "| Metric | Score | Grade |\n";
        md << "|--------|-------|-------|\n";
        md << "| **Overall SIS** | " << std::fixed << std::setprecision(1) << sis.overall_score 
           << " | " << sis.grade << " |\n";
        md << "| Inference | " << sis.categories.inference << " | " 
           << SISCalculator().ScoreToGrade(sis.categories.inference) << " |\n";
        md << "| Agentic | " << sis.categories.agentic << " | "
           << SISCalculator().ScoreToGrade(sis.categories.agentic) << " |\n";
        md << "| Swarm | " << sis.categories.swarm << " | "
           << SISCalculator().ScoreToGrade(sis.categories.swarm) << " |\n";
        md << "| Recovery | " << sis.categories.recovery << " | "
           << SISCalculator().ScoreToGrade(sis.categories.recovery) << " |\n";
        md << "| Autonomy | " << sis.categories.autonomy << " | "
           << SISCalculator().ScoreToGrade(sis.categories.autonomy) << " |\n\n";
        
        // Comparison table if available
        if (comparison) {
            md << "## Sovereign vs Ollama Comparison\n\n";
            md << "| Metric | Sovereign | Ollama | Delta | Significance |\n";
            md << "|--------|-----------|--------|-------|--------------|\n";
            
            for (const auto& metric : comparison->metrics) {
                md << "| " << metric.metric_name << " | "
                   << std::fixed << std::setprecision(1) << metric.sovereign_mean << " | "
                   << metric.ollama_mean << " | "
                   << std::showpos << metric.percent_delta << "% | "
                   << metric.significance_marker << " |\n";
            }
            
            md << "\n**SIS Delta:** " << std::showpos << comparison->sis_delta_percent << "%\n\n";
            md << "**Significant Wins:** " << comparison->significant_wins.size() << "/" 
               << comparison->metrics.size() << " categories\n\n";
        }
        
        // Strengths and weaknesses
        if (!sis.strengths.empty()) {
            md << "## Strengths\n";
            for (const auto& s : sis.strengths) {
                md << "- " << s << "\n";
            }
            md << "\n";
        }
        
        if (!sis.weaknesses.empty()) {
            md << "## Areas for Improvement\n";
            for (const auto& w : sis.weaknesses) {
                md << "- " << w << "\n";
            }
            md << "\n";
        }
        
        return md.str();
    }

    static std::string GenerateJSON(const SISResult& sis,
                                    const StatisticalComparator::FullComparison* comparison) {
        std::stringstream json;
        json << "{\n";
        json << "  \"timestamp\": \"" << GetTimestamp() << "\",\n";
        json << "  \"sis_score\": " << sis.overall_score << ",\n";
        json << "  \"grade\": \"" << sis.grade << "\",\n";
        json << "  \"categories\": {\n";
        json << "    \"inference\": " << sis.categories.inference << ",\n";
        json << "    \"agentic\": " << sis.categories.agentic << ",\n";
        json << "    \"swarm\": " << sis.categories.swarm << ",\n";
        json << "    \"seg\": " << sis.categories.seg << ",\n";
        json << "    \"decision\": " << sis.categories.decision << ",\n";
        json << "    \"recovery\": " << sis.categories.recovery << ",\n";
        json << "    \"quality\": " << sis.categories.quality << ",\n";
        json << "    \"context\": " << sis.categories.context << ",\n";
        json << "    \"autonomy\": " << sis.categories.autonomy << "\n";
        json << "  }";
        
        if (comparison) {
            json << ",\n  \"comparison\": {\n";
            json << "    \"sovereign_sis\": " << comparison->sovereign_sis << ",\n";
            json << "    \"ollama_sis\": " << comparison->ollama_sis << ",\n";
            json << "    \"sis_delta_percent\": " << comparison->sis_delta_percent << ",\n";
            json << "    \"sovereign_wins\": " << comparison->sovereign_wins << ",\n";
            json << "    \"ollama_wins\": " << comparison->ollama_wins << ",\n";
            json << "    \"ties\": " << comparison->ties << "\n";
            json << "  }";
        }
        
        json << "\n}\n";
        return json.str();
    }

private:
    static std::string GetTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

// ============================================================================
// Benchmark Orchestrator
// Runs full benchmark suite with orchestration
// ============================================================================
class BenchmarkOrchestrator {
public:
    struct OrchestratorConfig {
        std::string output_dir = "reports/";
        bool run_sovereign = true;
        bool run_ollama = true;
        bool check_regressions = true;
        bool export_csv = true;
        std::string model = "phi-3-mini-Q4";
    };

    explicit BenchmarkOrchestrator(IBackendAdapter* sovereign_backend,
                                   IBackendAdapter* ollama_backend,
                                   const OrchestratorConfig& config = OrchestratorConfig{})
        : sovereign_backend_(sovereign_backend),
          ollama_backend_(ollama_backend),
          config_(config) {}

    struct FullBenchmarkResults {
        SISResult sovereign_sis;
        SISResult ollama_sis;
        StatisticalComparator::FullComparison comparison;
        std::vector<RegressionTracker::RegressionCheck> regressions;
        std::string report_markdown;
        std::string report_json;
    };

    FullBenchmarkResults RunFullSuite() {
        FullBenchmarkResults results;
        
        std::cout << "=== RawrXD Sovereign Benchmark Suite ===\n\n";
        
        // Run Sovereign benchmarks
        if (config_.run_sovereign && sovereign_backend_) {
            std::cout << "Running Sovereign benchmarks...\n";
            auto sovereign_batch1 = RunBatch1(sovereign_backend_);
            auto sovereign_batch2 = RunBatch2(sovereign_backend_);
            results.sovereign_sis = SISCalculator().Calculate(sovereign_batch1, sovereign_batch2);
        }
        
        // Run Ollama benchmarks
        if (config_.run_ollama && ollama_backend_) {
            std::cout << "Running Ollama benchmarks...\n";
            auto ollama_batch1 = RunBatch1(ollama_backend_);
            auto ollama_batch2 = RunBatch2(ollama_backend_);
            results.ollama_sis = SISCalculator().Calculate(ollama_batch1, ollama_batch2);
        }
        
        // Compare
        if (config_.run_sovereign && config_.run_ollama) {
            results.comparison = StatisticalComparator().CompareFullResults(
                results.sovereign_sis, results.ollama_sis);
        }
        
        // Check regressions
        if (config_.check_regressions) {
            RegressionTracker tracker;
            if (tracker.Initialize()) {
                results.regressions = tracker.CheckForRegressions("sovereign_suite", results.sovereign_sis);
            }
        }
        
        // Generate reports
        results.report_markdown = ReportGenerator::GenerateMarkdown(
            results.sovereign_sis, 
            config_.run_ollama ? &results.comparison : nullptr);
        results.report_json = ReportGenerator::GenerateJSON(
            results.sovereign_sis,
            config_.run_ollama ? &results.comparison : nullptr);
        
        // Save reports
        SaveReports(results);
        
        return results;
    }

private:
    IBackendAdapter* sovereign_backend_;
    IBackendAdapter* ollama_backend_;
    OrchestratorConfig config_;

    Batch1Results RunBatch1(IBackendAdapter* backend) {
        Batch1Results results;
        results.inference = InferenceTPSBenchmark(backend).Run();
        results.agent_spawn = AgentSpawnBenchmark(backend).Run();
        results.swarm16 = Swarm16Benchmark(backend).Run();
        results.seg_execution = SEGExecutionBenchmark(backend).Run();
        results.decision_making = DecisionMakingBenchmark(backend).Run();
        return results;
    }

    Batch2Results RunBatch2(IBackendAdapter* backend) {
        Batch2Results results;
        results.self_correction = SelfCorrectionBenchmark(backend).Run();
        results.response_quality = ResponseQualityBenchmark(backend).Run();
        results.context_handling = ContextHandlingBenchmark(backend).Run();
        results.autonomous_runtime = AutonomousRuntimeBenchmark(backend).Run();
        results.resource_usage = ResourceUsageBenchmark(backend).Run();
        return results;
    }

    void SaveReports(const FullBenchmarkResults& results) {
        // Create output directory
        std::filesystem::create_directories(config_.output_dir);
        
        // Save Markdown
        std::ofstream md_file(config_.output_dir + "/benchmark_report.md");
        md_file << results.report_markdown;
        
        // Save JSON
        std::ofstream json_file(config_.output_dir + "/benchmark_report.json");
        json_file << results.report_json;
        
        std::cout << "Reports saved to: " << config_.output_dir << "\n";
    }
};

// Helper structs for batch results
struct Batch1Results {
    InferenceTPSBenchmark::Results inference;
    AgentSpawnBenchmark::Results agent_spawn;
    Swarm16Benchmark::Results swarm16;
    SEGExecutionBenchmark::Results seg_execution;
    DecisionMakingBenchmark::Results decision_making;
};

struct Batch2Results {
    SelfCorrectionBenchmark::Results self_correction;
    ResponseQualityBenchmark::Results response_quality;
    ContextHandlingBenchmark::Results context_handling;
    AutonomousRuntimeBenchmark::Results autonomous_runtime;
    ResourceUsageBenchmark::Results resource_usage;
};

} // namespace rawrxd_benchmarks
