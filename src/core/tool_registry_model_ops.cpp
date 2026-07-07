// ============================================================================
// tool_registry_model_ops.cpp — Model Operations Tool Registration
// ============================================================================
// Registers P0/P1/P2 model operation tools with ToolRegistry.
// Uses ModelOperationsBridge for async execution with ThreadPool dispatch.
//
// Tools registered:
//   - BENCHMARK_MODEL: Run throughput benchmark with warmup
//   - RUN_INFERENCE: Execute inference with streaming callback
//   - LOAD_MODEL: Load a GGUF model file
//   - TOKENIZE: Convert text to token IDs
//   - DETOKENIZE: Convert token IDs to text
//
// Pattern: PatchResult-style, no exceptions.
// Rule:    NO SOURCE FILE IS TO BE SIMPLIFIED.
// ============================================================================

#include "tool_registry.h"
#include "core/model_operations_bridge.hpp"
#include "engine_iface.h"
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ============================================================================
// Global Bridge Instance
// ============================================================================
// The bridge is created on first use. Win32IDE must handle WM_JOB_COMPLETE
// to dispatch results back to the UI thread.
// ============================================================================

static ModelOperationsBridge* g_modelBridge = nullptr;
static HWND g_hwndMain = nullptr;
static AgenticExecutor* g_executor = nullptr;

// ============================================================================
// Initialization
// ============================================================================

void init_model_operations_bridge(HWND hwndMain, AgenticExecutor* executor) {
    if (g_modelBridge) {
        std::cerr << "[MODEL_OPS] Bridge already initialized" << std::endl;
        return;
    }
    
    g_hwndMain = hwndMain;
    g_executor = executor;
    
    g_modelBridge = new ModelOperationsBridge(hwndMain, executor);
    if (!g_modelBridge->initialize()) {
        std::cerr << "[MODEL_OPS] Failed to initialize ModelOperationsBridge" << std::endl;
        delete g_modelBridge;
        g_modelBridge = nullptr;
        return;
    }
    
    std::cout << "[MODEL_OPS] ModelOperationsBridge initialized successfully" << std::endl;
}

void shutdown_model_operations_bridge() {
    if (g_modelBridge) {
        g_modelBridge->shutdown();
        delete g_modelBridge;
        g_modelBridge = nullptr;
    }
    g_hwndMain = nullptr;
    g_executor = nullptr;
}

ModelOperationsBridge* get_model_operations_bridge() {
    return g_modelBridge;
}

// ============================================================================
// Tool: BENCHMARK_MODEL
// ============================================================================
// Runs a throughput benchmark with warmup pass.
//
// Input JSON format:
// {
//   "warmup_tokens": 100,    // Warmup tokens (default: 100)
//   "test_tokens": 500,      // Test tokens (default: 500)
//   "model": "current"       // Model to benchmark (default: current)
// }
//
// Output JSON format:
// {
//   "success": true,
//   "tokens_per_second": 42.5,
//   "latency_ms": 11764.7,
//   "warmup_tokens": 100,
//   "test_tokens": 500,
//   "error": null
// }
// ============================================================================

void register_benchmark_model_tool() {
    ToolRegistry::register_tool("BENCHMARK_MODEL", [](const std::string& input) -> std::string {
        json result;
        result["success"] = false;
        
        // Parse input
        int warmupTokens = 100;
        int testTokens = 500;
        
        try {
            if (!input.empty()) {
                auto params = json::parse(input);
                if (params.contains("warmup_tokens") && params["warmup_tokens"].is_number_integer()) {
                    warmupTokens = params["warmup_tokens"].get<int>();
                }
                if (params.contains("test_tokens") && params["test_tokens"].is_number_integer()) {
                    testTokens = params["test_tokens"].get<int>();
                }
            }
        } catch (const std::exception& e) {
            result["error"] = std::string("Failed to parse input: ") + e.what();
            return result.dump();
        }
        
        // Check bridge
        if (!g_modelBridge) {
            result["error"] = "ModelOperationsBridge not initialized. Call init_model_operations_bridge() first.";
            return result.dump();
        }
        
        // Check model loaded
        if (!g_modelBridge->IsModelLoaded()) {
            result["error"] = "No model loaded. Use LOAD_MODEL first.";
            return result.dump();
        }
        
        // Run benchmark synchronously (blocking for tool API)
        // Note: For async operation, use QueueBenchmark with callback
        double tokensPerSecond = 0.0;
        double latencyMs = 0.0;
        bool success = false;
        
        // Use a promise/future for synchronous wait
        std::promise<std::tuple<double, double, bool>> promise;
        auto future = promise.get_future();
        
        uint64_t jobId = g_modelBridge->QueueBenchmark(
            warmupTokens,
            testTokens,
            [&promise, &tokensPerSecond, &latencyMs, &success](double tps, double lat, bool ok) {
                tokensPerSecond = tps;
                latencyMs = lat;
                success = ok;
                promise.set_value(std::make_tuple(tps, lat, ok));
            }
        );
        
        if (jobId == 0) {
            result["error"] = "Failed to queue benchmark job";
            return result.dump();
        }
        
        // Wait for completion (with timeout)
        auto status = future.wait_for(std::chrono::seconds(300)); // 5 minute timeout
        if (status != std::future_status::ready) {
            result["error"] = "Benchmark timed out after 300 seconds";
            return result.dump();
        }
        
        auto [tps, lat, ok] = future.get();
        
        result["success"] = ok;
        result["tokens_per_second"] = tps;
        result["latency_ms"] = lat;
        result["warmup_tokens"] = warmupTokens;
        result["test_tokens"] = testTokens;
        
        if (!ok) {
            result["error"] = "Benchmark execution failed";
        }
        
        // Add stats
        auto stats = g_modelBridge->GetStats();
        json statsJson;
        statsJson["total_jobs_submitted"] = stats.totalJobsSubmitted;
        statsJson["total_jobs_completed"] = stats.totalJobsCompleted;
        statsJson["total_jobs_failed"] = stats.totalJobsFailed;
        statsJson["total_inferences_run"] = stats.totalInferencesRun;
        statsJson["total_tokens_generated"] = stats.totalTokensGenerated;
        statsJson["avg_tokens_per_second"] = stats.avgTokensPerSecond;
        result["stats"] = statsJson;
        
        return result.dump();
    });
    
    std::cout << "[REGISTRY] Registered BENCHMARK_MODEL tool (async via ModelOperationsBridge)" << std::endl;
}

// ============================================================================
// Tool: RUN_INFERENCE
// ============================================================================
// Executes inference with the loaded model.
//
// Input JSON format:
// {
//   "prompt": "Hello, world!",
//   "max_tokens": 100
// }
//
// Output JSON format:
// {
//   "success": true,
//   "output": "Hello! How can I help you today?",
//   "tokens_generated": 8,
//   "duration_ms": 234.5,
//   "error": null
// }
// ============================================================================

void register_run_inference_tool() {
    ToolRegistry::register_tool("RUN_INFERENCE", [](const std::string& input) -> std::string {
        json result;
        result["success"] = false;
        
        // Parse input
        std::string prompt;
        int maxTokens = 100;
        
        try {
            if (!input.empty()) {
                auto params = json::parse(input);
                if (params.contains("prompt") && params["prompt"].is_string()) {
                    prompt = params["prompt"].get<std::string>();
                }
                if (params.contains("max_tokens") && params["max_tokens"].is_number_integer()) {
                    maxTokens = params["max_tokens"].get<int>();
                }
            }
        } catch (const std::exception& e) {
            result["error"] = std::string("Failed to parse input: ") + e.what();
            return result.dump();
        }
        
        if (prompt.empty()) {
            result["error"] = "Missing required parameter: prompt";
            return result.dump();
        }
        
        // Check bridge
        if (!g_modelBridge) {
            result["error"] = "ModelOperationsBridge not initialized";
            return result.dump();
        }
        
        if (!g_modelBridge->IsModelLoaded()) {
            result["error"] = "No model loaded";
            return result.dump();
        }
        
        // Run inference synchronously
        std::promise<std::tuple<std::string, bool, std::string>> promise;
        auto future = promise.get_future();
        
        uint64_t jobId = g_modelBridge->QueueInference(
            prompt,
            maxTokens,
            [&promise](const std::string& output, bool success, const std::string& error) {
                promise.set_value(std::make_tuple(output, success, error));
            }
        );
        
        if (jobId == 0) {
            result["error"] = "Failed to queue inference job";
            return result.dump();
        }
        
        // Wait for completion
        auto status = future.wait_for(std::chrono::seconds(120));
        if (status != std::future_status::ready) {
            result["error"] = "Inference timed out";
            return result.dump();
        }
        
        auto [output, success, error] = future.get();
        
        result["success"] = success;
        result["output"] = output;
        result["error"] = error.empty() ? nullptr : json(error);
        
        return result.dump();
    });
    
    std::cout << "[REGISTRY] Registered RUN_INFERENCE tool" << std::endl;
}

// ============================================================================
// Tool: LOAD_MODEL
// ============================================================================
// Loads a GGUF model file.
//
// Input JSON format:
// {
//   "path": "/path/to/model.gguf"
// }
//
// Output JSON format:
// {
//   "success": true,
//   "model_path": "/path/to/model.gguf",
//   "error": null
// }
// ============================================================================

void register_load_model_tool() {
    ToolRegistry::register_tool("LOAD_MODEL", [](const std::string& input) -> std::string {
        json result;
        result["success"] = false;
        
        // Parse input
        std::string modelPath;
        
        try {
            if (!input.empty()) {
                auto params = json::parse(input);
                if (params.contains("path") && params["path"].is_string()) {
                    modelPath = params["path"].get<std::string>();
                }
            }
        } catch (const std::exception& e) {
            result["error"] = std::string("Failed to parse input: ") + e.what();
            return result.dump();
        }
        
        if (modelPath.empty()) {
            result["error"] = "Missing required parameter: path";
            return result.dump();
        }
        
        // Check bridge
        if (!g_modelBridge) {
            result["error"] = "ModelOperationsBridge not initialized";
            return result.dump();
        }
        
        // Load model synchronously
        std::promise<std::tuple<bool, std::string, std::string>> promise;
        auto future = promise.get_future();
        
        uint64_t jobId = g_modelBridge->QueueLoadModel(
            modelPath,
            [&promise](const ModelJobResult& res) {
                promise.set_value(std::make_tuple(res.success, res.output, res.error));
            }
        );
        
        if (jobId == 0) {
            result["error"] = "Failed to queue load model job";
            return result.dump();
        }
        
        // Wait for completion
        auto status = future.wait_for(std::chrono::seconds(600)); // 10 minute timeout for large models
        if (status != std::future_status::ready) {
            result["error"] = "Model loading timed out";
            return result.dump();
        }
        
        auto [success, output, error] = future.get();
        
        result["success"] = success;
        result["model_path"] = modelPath;
        if (!error.empty()) {
            result["error"] = error;
        }
        
        return result.dump();
    });
    
    std::cout << "[REGISTRY] Registered LOAD_MODEL tool" << std::endl;
}

// ============================================================================
// Tool: GET_MODEL_INFO
// ============================================================================
// Returns information about the currently loaded model.
//
// Input: None
// Output JSON format:
// {
//   "loaded": true,
//   "context_limit": 4096,
//   "error": null
// }
// ============================================================================

void register_get_model_info_tool() {
    ToolRegistry::register_tool("GET_MODEL_INFO", [](const std::string& input) -> std::string {
        json result;
        
        if (!g_modelBridge) {
            result["loaded"] = false;
            result["error"] = "ModelOperationsBridge not initialized";
            return result.dump();
        }
        
        result["loaded"] = g_modelBridge->IsModelLoaded();
        
        std::string info = g_modelBridge->GetModelInfo();
        try {
            result["model_info"] = json::parse(info);
        } catch (...) {
            result["model_info"] = info;
        }
        
        return result.dump();
    });
    
    std::cout << "[REGISTRY] Registered GET_MODEL_INFO tool" << std::endl;
}

// ============================================================================
// Tool: GET_MODEL_STATS
// ============================================================================
// Returns statistics about model operations.
//
// Input: None
// Output JSON format:
// {
//   "total_jobs_submitted": 100,
//   "total_jobs_completed": 98,
//   "total_jobs_failed": 2,
//   "total_inferences_run": 50,
//   "total_tokens_generated": 5000,
//   "avg_tokens_per_second": 42.5
// }
// ============================================================================

void register_get_model_stats_tool() {
    ToolRegistry::register_tool("GET_MODEL_STATS", [](const std::string& input) -> std::string {
        json result;
        
        if (!g_modelBridge) {
            result["error"] = "ModelOperationsBridge not initialized";
            return result.dump();
        }
        
        auto stats = g_modelBridge->GetStats();
        
        result["total_jobs_submitted"] = stats.totalJobsSubmitted;
        result["total_jobs_completed"] = stats.totalJobsCompleted;
        result["total_jobs_failed"] = stats.totalJobsFailed;
        result["total_inferences_run"] = stats.totalInferencesRun;
        result["total_tokens_generated"] = stats.totalTokensGenerated;
        result["total_inference_ms"] = stats.totalInferenceMs;
        result["avg_inference_ms"] = stats.avgInferenceMs;
        result["avg_tokens_per_second"] = stats.avgTokensPerSecond;
        
        return result.dump();
    });
    
    std::cout << "[REGISTRY] Registered GET_MODEL_STATS tool" << std::endl;
}

// ============================================================================
// Register All Model Operation Tools
// ============================================================================

void register_model_operation_tools() {
    register_benchmark_model_tool();
    register_run_inference_tool();
    register_load_model_tool();
    register_get_model_info_tool();
    register_get_model_stats_tool();
    
    std::cout << "[REGISTRY] All model operation tools registered" << std::endl;
}