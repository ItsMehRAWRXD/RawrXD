// ============================================================================
// tool_registry_model_ops.hpp — Model Operations Tool Registration Header
// ============================================================================
// Declares P0/P1/P2 model operation tool registration functions.
// These tools use ModelOperationsBridge for async execution.
//
// Pattern: PatchResult-style, no exceptions.
// Rule:    NO SOURCE FILE IS TO BE SIMPLIFIED.
// ============================================================================

#pragma once

#include <windows.h>

// Forward declarations
class AgenticExecutor;
class ModelOperationsBridge;

// ============================================================================
// Initialization / Shutdown
// ============================================================================

/// Initialize the ModelOperationsBridge with the given window handle.
/// Must be called before any model operation tools can be used.
/// The hwndMain must handle WM_JOB_COMPLETE messages to dispatch results.
void init_model_operations_bridge(HWND hwndMain, AgenticExecutor* executor);

/// Shutdown the ModelOperationsBridge and free resources.
void shutdown_model_operations_bridge();

/// Get the global ModelOperationsBridge instance.
/// Returns nullptr if not initialized.
ModelOperationsBridge* get_model_operations_bridge();

// ============================================================================
// Tool Registration
// ============================================================================

/// Register all model operation tools with ToolRegistry.
/// Tools registered:
///   - BENCHMARK_MODEL: Run throughput benchmark with warmup
///   - RUN_INFERENCE: Execute inference with streaming callback
///   - LOAD_MODEL: Load a GGUF model file
///   - GET_MODEL_INFO: Get information about loaded model
///   - GET_MODEL_STATS: Get model operation statistics
void register_model_operation_tools();

// ============================================================================
// Individual Tool Registration (for selective registration)
// ============================================================================

/// Register BENCHMARK_MODEL tool.
/// Input: {"warmup_tokens": 100, "test_tokens": 500}
/// Output: {"success": true, "tokens_per_second": 42.5, "latency_ms": 11764.7}
void register_benchmark_model_tool();

/// Register RUN_INFERENCE tool.
/// Input: {"prompt": "Hello", "max_tokens": 100}
/// Output: {"success": true, "output": "Hello! How can I help?", "tokens_generated": 8}
void register_run_inference_tool();

/// Register LOAD_MODEL tool.
/// Input: {"path": "/path/to/model.gguf"}
/// Output: {"success": true, "model_path": "/path/to/model.gguf"}
void register_load_model_tool();

/// Register GET_MODEL_INFO tool.
/// Input: None
/// Output: {"loaded": true, "context_limit": 4096}
void register_get_model_info_tool();

/// Register GET_MODEL_STATS tool.
/// Input: None
/// Output: {"total_jobs_submitted": 100, "avg_tokens_per_second": 42.5, ...}
void register_get_model_stats_tool();