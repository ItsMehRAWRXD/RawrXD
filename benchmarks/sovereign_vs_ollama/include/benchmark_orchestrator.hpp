// Benchmark Orchestrator
// Runs all benchmarks sequentially and manages execution flow
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include "benchmark_manifest.hpp"
#include "json_reporter.hpp"
#include <iostream>
#include <vector>
#include <memory>
#include <functional>
#include <future>
#include <chrono>

namespace rawrxd::benchmark {

// ============================================================================
// Benchmark Orchestrator
// ============================================================================
class BenchmarkOrchestrator {
public:
    struct OrchestratorConfig {
        std::vector<BackendType> backends = {BackendType::SOVEREIGN, BackendType::OLLAMA};
        std::vector<std::string> benchmark_names; // Empty = all
        std::string output_directory = "reports";
        bool fail_fast = false;
        bool parallel_backends = false; // Run backends in parallel (careful!)
        int retry_count = 2; // Retry failed benchmarks
        std::function<void(const std::string&)> progress_callback;
    };
    
    struct OrchestratorResult {
        bool success = false;
        std::string run_id;
        std::string timestamp;
        std::vector<BenchmarkResult> results;
        std::vector<std::string> errors;
        double total_duration_seconds = 0.0;
        int benchmarks_run = 0;
        int benchmarks_passed = 0;
        int benchmarks_failed = 0;
    };
    
    BenchmarkOrchestrator(const OrchestratorConfig& config = OrchestratorConfig{})
        : config_(config) {}
    
    // Register a benchmark factory
    void RegisterBenchmark(const std::string& name, 
                          std::function<std::unique_ptr<Benchmark>()> factory) {
        benchmark_factories_[name] = factory;
    }
    
    // Run all configured benchmarks
    OrchestratorResult RunAll(const BenchmarkConfig& base_config) {
        OrchestratorResult result;
        result.run_id = BenchmarkManifest::GenerateRunId();
        result.timestamp = GetTimestamp();
        
        Timer total_timer;
        total_timer.Start();
        
        ReportProgress("Starting benchmark orchestration run: " + result.run_id);
        ReportProgress("Output directory: " + config_.output_directory);
        
        // Create output directory
        std::filesystem::create_directories(config_.output_directory);
        
        // Get list of benchmarks to run
        auto benchmarks_to_run = GetBenchmarksToRun();
        ReportProgress("Will run " + std::to_string(benchmarks_to_run.size()) + " benchmarks");
        
        // Run for each backend
        for (auto backend : config_.backends) {
            ReportProgress("\n========================================");
            ReportProgress("Running benchmarks for: " + std::string(BackendTypeToString(backend)));
            ReportProgress("========================================\n");
            
            auto backend_config = base_config;
            backend_config.backend = backend;
            
            // Create manifest for this run
            auto manifest = BenchmarkManifest::Create(backend_config);
            std::string manifest_path = config_.output_directory + "/manifest_" + 
                                       std::string(BackendTypeToString(backend)) + ".json";
            manifest.SaveToFile(manifest_path);
            ReportProgress("Manifest saved to: " + manifest_path);
            
            // Run each benchmark
            for (const auto& bench_name : benchmarks_to_run) {
                auto bench_result = RunBenchmark(bench_name, backend_config);
                
                if (bench_result) {
                    result.results.push_back(*bench_result);
                    result.benchmarks_run++;
                    
                    if (bench_result->success_rate > 0.5) {
                        result.benchmarks_passed++;
                    } else {
                        result.benchmarks_failed++;
                        if (config_.fail_fast) {
                            ReportProgress("FAIL_FAST enabled, stopping...");
                            break;
                        }
                    }
                } else {
                    result.errors.push_back("Failed to run benchmark: " + bench_name);
                    result.benchmarks_failed++;
                }
            }
        }
        
        total_timer.Stop();
        result.total_duration_seconds = total_timer.ElapsedMs() / 1000.0;
        result.success = (result.benchmarks_failed == 0);
        
        // Save aggregated results
        SaveOrchestratorResult(result);
        
        ReportProgress("\n========================================");
        ReportProgress("Orchestration complete!");
        ReportProgress("Total duration: " + std::to_string(result.total_duration_seconds) + "s");
        ReportProgress("Benchmarks run: " + std::to_string(result.benchmarks_run));
        ReportProgress("Passed: " + std::to_string(result.benchmarks_passed));
        ReportProgress("Failed: " + std::to_string(result.benchmarks_failed));
        ReportProgress("========================================\n");
        
        return result;
    }
    
    // Run a single benchmark with retries
    std::optional<BenchmarkResult> RunBenchmark(const std::string& name, 
                                                  const BenchmarkConfig& config) {
        auto it = benchmark_factories_.find(name);
        if (it == benchmark_factories_.end()) {
            ReportProgress("ERROR: Unknown benchmark: " + name);
            return std::nullopt;
        }
        
        ReportProgress("Running benchmark: " + name);
        
        for (int attempt = 0; attempt <= config_.retry_count; ++attempt) {
            if (attempt > 0) {
                ReportProgress("Retry attempt " + std::to_string(attempt) + "/" + 
                              std::to_string(config_.retry_count));
            }
            
            try {
                auto benchmark = it->second();
                auto result = benchmark->Run(config);
                
                // Save individual result
                std::string result_path = config_.output_directory + "/" + name + "_" + 
                                         std::string(BackendTypeToString(config.backend)) + ".json";
                std::ofstream file(result_path);
                if (file) {
                    file << result.ToJson();
                }
                
                return result;
            } catch (const std::exception& e) {
                ReportProgress("ERROR in benchmark " + name + ": " + e.what());
                if (attempt == config_.retry_count) {
                    return std::nullopt;
                }
            }
        }
        
        return std::nullopt;
    }
    
private:
    OrchestratorConfig config_;
    std::map<std::string, std::function<std::unique_ptr<Benchmark>()>> benchmark_factories_;
    
    std::vector<std::string> GetBenchmarksToRun() const {
        if (!config_.benchmark_names.empty()) {
            return config_.benchmark_names;
        }
        
        // Return all registered benchmarks
        std::vector<std::string> names;
        for (const auto& [name, _] : benchmark_factories_) {
            names.push_back(name);
        }
        return names;
    }
    
    void ReportProgress(const std::string& message) {
        std::cout << message << std::endl;
        if (config_.progress_callback) {
            config_.progress_callback(message);
        }
    }
    
    void SaveOrchestratorResult(const OrchestratorResult& result) {
        JsonWriter writer;
        writer.BeginObject();
        
        writer.WriteString("run_id", result.run_id);
        writer.WriteString("timestamp", result.timestamp);
        writer.WriteBool("success", result.success);
        writer.WriteDouble("total_duration_seconds", result.total_duration_seconds);
        writer.WriteInt("benchmarks_run", result.benchmarks_run);
        writer.WriteInt("benchmarks_passed", result.benchmarks_passed);
        writer.WriteInt("benchmarks_failed", result.benchmarks_failed);
        
        writer.BeginArray("errors");
        for (const auto& error : result.errors) {
            if (&error != &result.errors[0]) writer.ss_ << ",";
            writer.ss_ << "\"" << error << "\"";
        }
        writer.EndArray();
        
        writer.BeginArray("results");
        bool first = true;
        for (const auto& bench_result : result.results) {
            if (!first) writer.ss_ << ",";
            writer.ss_ << bench_result.ToJson();
            first = false;
        }
        writer.EndArray();
        
        writer.EndObject();
        
        std::string path = config_.output_directory + "/orchestrator_result.json";
        std::ofstream file(path);
        if (file) {
            file << writer.Str();
            ReportProgress("Orchestrator result saved to: " + path);
        }
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
