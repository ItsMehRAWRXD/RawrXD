// Regression Tracking and History
// Stores benchmark results over time for trend analysis
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include <sqlite3.h>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace rawrxd::benchmark {

// ============================================================================
// Regression Thresholds
// ============================================================================
struct RegressionThresholds {
    double tps_regression_percent = 5.0;      // Flag if TPS drops > 5%
    double latency_regression_percent = 10.0;   // Flag if latency increases > 10%
    double memory_growth_mb = 100.0;            // Flag if memory grows > 100MB
    double success_rate_minimum = 0.95;         // Flag if success rate < 95%
    double quality_regression_points = 5.0;   // Flag if quality drops > 5 points
};

// ============================================================================
// Historical Result
// ============================================================================
struct HistoricalResult {
    std::string run_id;
    std::string timestamp;
    std::string git_commit;
    std::string git_branch;
    BackendType backend;
    std::string benchmark_name;
    
    // Key metrics
    double mean_tps = 0.0;
    double p95_latency_ms = 0.0;
    double mean_memory_mb = 0.0;
    double success_rate = 0.0;
    double quality_score = 0.0;
    double sis_score = 0.0;
    
    // Build info
    std::string build_type;
    std::string compiler;
};

// ============================================================================
// Regression Report
// ============================================================================
struct RegressionReport {
    bool has_regressions = false;
    std::vector<std::string> regressions;
    std::vector<std::string> improvements;
    
    std::string ToMarkdown() const {
        std::stringstream ss;
        ss << "## Regression Report\n\n";
        
        if (has_regressions) {
            ss << "### ⚠️ Regressions Detected\n\n";
            for (const auto& r : regressions) {
                ss << "- " << r << "\n";
            }
        } else {
            ss << "### ✅ No Regressions\n\n";
        }
        
        if (!improvements.empty()) {
            ss << "\n### 📈 Improvements\n\n";
            for (const auto& i : improvements) {
                ss << "- " << i << "\n";
            }
        }
        
        return ss.str();
    }
};

// ============================================================================
// Regression Tracker
// ============================================================================
class RegressionTracker {
public:
    RegressionTracker(const std::string& db_path = "benchmark_history.db")
        : db_path_(db_path) {
        InitializeDatabase();
    }
    
    ~RegressionTracker() {
        if (db_) {
            sqlite3_close(db_);
        }
    }
    
    // Store a benchmark result
    bool StoreResult(const BenchmarkResult& result, const std::string& git_commit,
                    const std::string& git_branch, const std::string& build_type) {
        if (!db_) return false;
        
        std::string sql = R"(
            INSERT INTO benchmark_history 
            (run_id, timestamp, git_commit, git_branch, backend, benchmark_name,
             mean_tps, p95_latency_ms, mean_memory_mb, success_rate, quality_score,
             build_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        )";
        
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }
        
        // Bind parameters
        sqlite3_bind_text(stmt, 1, result.benchmark_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, result.timestamp.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, git_commit.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, git_branch.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, BackendTypeToString(result.backend), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, result.benchmark_name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_double(stmt, 7, result.throughput.mean);
        sqlite3_bind_double(stmt, 8, result.latency.p95);
        sqlite3_bind_double(stmt, 9, result.resources.memory_mb);
        sqlite3_bind_double(stmt, 10, result.success_rate);
        sqlite3_bind_double(stmt, 11, result.quality.overall_score);
        sqlite3_bind_text(stmt, 12, build_type.c_str(), -1, SQLITE_STATIC);
        
        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
        
        return success;
    }
    
    // Get historical results for a benchmark
    std::vector<HistoricalResult> GetHistory(const std::string& benchmark_name,
                                               BackendType backend,
                                               int limit = 100) {
        std::vector<HistoricalResult> history;
        
        if (!db_) return history;
        
        std::string sql = R"(
            SELECT run_id, timestamp, git_commit, git_branch, mean_tps,
                   p95_latency_ms, mean_memory_mb, success_rate, quality_score, build_type
            FROM benchmark_history
            WHERE benchmark_name = ? AND backend = ?
            ORDER BY timestamp DESC
            LIMIT ?
        )";
        
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            return history;
        }
        
        sqlite3_bind_text(stmt, 1, benchmark_name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, BackendTypeToString(backend), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, limit);
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            HistoricalResult hr;
            hr.run_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            hr.timestamp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            hr.git_commit = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            hr.git_branch = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            hr.mean_tps = sqlite3_column_double(stmt, 4);
            hr.p95_latency_ms = sqlite3_column_double(stmt, 5);
            hr.mean_memory_mb = sqlite3_column_double(stmt, 6);
            hr.success_rate = sqlite3_column_double(stmt, 7);
            hr.quality_score = sqlite3_column_double(stmt, 8);
            hr.build_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
            history.push_back(hr);
        }
        
        sqlite3_finalize(stmt);
        return history;
    }
    
    // Check for regressions
    RegressionReport CheckRegressions(const BenchmarkResult& current_result,
                                     const RegressionThresholds& thresholds = RegressionThresholds{}) {
        RegressionReport report;
        
        auto history = GetHistory(current_result.benchmark_name, current_result.backend, 10);
        if (history.size() < 2) {
            return report; // Not enough history
        }
        
        // Compare against previous runs (average of last 5)
        double avg_tps = 0.0, avg_latency = 0.0, avg_memory = 0.0;
        double avg_success = 0.0, avg_quality = 0.0;
        int count = std::min(5, static_cast<int>(history.size()));
        
        for (int i = 0; i < count; ++i) {
            avg_tps += history[i].mean_tps;
            avg_latency += history[i].p95_latency_ms;
            avg_memory += history[i].mean_memory_mb;
            avg_success += history[i].success_rate;
            avg_quality += history[i].quality_score;
        }
        
        avg_tps /= count;
        avg_latency /= count;
        avg_memory /= count;
        avg_success /= count;
        avg_quality /= count;
        
        // Check TPS regression
        if (avg_tps > 0) {
            double tps_change = ((current_result.throughput.mean - avg_tps) / avg_tps) * 100.0;
            if (tps_change < -thresholds.tps_regression_percent) {
                report.has_regressions = true;
                std::stringstream ss;
                ss << "TPS regression: " << std::fixed << std::setprecision(1) << tps_change << "% (was " << avg_tps << ", now " << current_result.throughput.mean << ")";
                report.regressions.push_back(ss.str());
            } else if (tps_change > thresholds.tps_regression_percent) {
                std::stringstream ss;
                ss << "TPS improvement: +" << std::fixed << std::setprecision(1) << tps_change << "%";
                report.improvements.push_back(ss.str());
            }
        }
        
        // Check latency regression
        if (avg_latency > 0) {
            double lat_change = ((current_result.latency.p95 - avg_latency) / avg_latency) * 100.0;
            if (lat_change > thresholds.latency_regression_percent) {
                report.has_regressions = true;
                std::stringstream ss;
                ss << "Latency regression: +" << std::fixed << std::setprecision(1) << lat_change << "% (was " << avg_latency << "ms, now " << current_result.latency.p95 << "ms)";
                report.regressions.push_back(ss.str());
            } else if (lat_change < -thresholds.latency_regression_percent) {
                std::stringstream ss;
                ss << "Latency improvement: " << std::fixed << std::setprecision(1) << lat_change << "%";
                report.improvements.push_back(ss.str());
            }
        }
        
        // Check success rate
        if (current_result.success_rate < thresholds.success_rate_minimum) {
            report.has_regressions = true;
            std::stringstream ss;
            ss << "Success rate below threshold: " << std::fixed << std::setprecision(1) << (current_result.success_rate * 100) << "% (minimum: " << (thresholds.success_rate_minimum * 100) << "%)";
            report.regressions.push_back(ss.str());
        }
        
        // Check quality regression
        if (avg_quality > 0) {
            double qual_change = current_result.quality.overall_score - avg_quality;
            if (qual_change < -thresholds.quality_regression_points) {
                report.has_regressions = true;
                std::stringstream ss;
                ss << "Quality regression: " << std::fixed << std::setprecision(1) << qual_change << " points";
                report.regressions.push_back(ss.str());
            } else if (qual_change > thresholds.quality_regression_points) {
                std::stringstream ss;
                ss << "Quality improvement: +" << std::fixed << std::setprecision(1) << qual_change << " points";
                report.improvements.push_back(ss.str());
            }
        }
        
        return report;
    }
    
    // Export to CSV
    bool ExportToCsv(const std::string& csv_path) {
        if (!db_) return false;
        
        std::ofstream file(csv_path);
        if (!file) return false;
        
        // Header
        file << "timestamp,git_commit,git_branch,backend,benchmark_name,";
        file << "mean_tps,p95_latency_ms,mean_memory_mb,success_rate,quality_score,build_type\n";
        
        // Query all results
        std::string sql = "SELECT * FROM benchmark_history ORDER BY timestamp";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            file << reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)) << ","; // timestamp
            file << reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)) << ","; // git_commit
            file << reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)) << ","; // git_branch
            file << reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4)) << ","; // backend
            file << reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5)) << ","; // benchmark_name
            file << sqlite3_column_double(stmt, 6) << ","; // mean_tps
            file << sqlite3_column_double(stmt, 7) << ","; // p95_latency_ms
            file << sqlite3_column_double(stmt, 8) << ","; // mean_memory_mb
            file << sqlite3_column_double(stmt, 9) << ","; // success_rate
            file << sqlite3_column_double(stmt, 10) << ","; // quality_score
            file << reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11)) << "\n"; // build_type
        }
        
        sqlite3_finalize(stmt);
        return true;
    }
    
private:
    std::string db_path_;
    sqlite3* db_ = nullptr;
    
    bool InitializeDatabase() {
        if (sqlite3_open(db_path_.c_str(), &db_) != SQLITE_OK) {
            return false;
        }
        
        // Create table
        const char* create_table_sql = R"(
            CREATE TABLE IF NOT EXISTS benchmark_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                git_commit TEXT,
                git_branch TEXT,
                backend TEXT NOT NULL,
                benchmark_name TEXT NOT NULL,
                mean_tps REAL,
                p95_latency_ms REAL,
                mean_memory_mb REAL,
                success_rate REAL,
                quality_score REAL,
                build_type TEXT
            )
        )";
        
        char* err_msg = nullptr;
        if (sqlite3_exec(db_, create_table_sql, nullptr, nullptr, &err_msg) != SQLITE_OK) {
            sqlite3_free(err_msg);
            return false;
        }
        
        // Create index
        const char* create_index_sql = R"(
            CREATE INDEX IF NOT EXISTS idx_benchmark_lookup 
            ON benchmark_history(benchmark_name, backend, timestamp)
        )";
        
        sqlite3_exec(db_, create_index_sql, nullptr, nullptr, nullptr);
        
        return true;
    }
};

} // namespace rawrxd::benchmark
