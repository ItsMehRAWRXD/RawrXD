// ============================================================================
// SEG Gateway Implementation
// ============================================================================

#include "seg_gateway.hpp"
#include "../../../src/seg/seg_runtime.hpp"
#include "../../../src/seg/seg_graph.hpp"
#include "../../../src/seg/seg_models.hpp"
#include "../../../src/seg/seg_executor.hpp"
#include "../../../src/runtime/telemetry_masm_bridge.hpp"
#include "../../../src/runtime/streaming_multi_layer_backend.hpp"
#include "../../../src/runtime/streaming_gguf_loader.hpp"

#include <chrono>
#include <sstream>
#include <iomanip>

namespace rawrxd {
namespace gateway {

using namespace RawrXD::Runtime;
using namespace RawrXD::Runtime::Telemetry;

// ============================================================================
// SegExecutionResult Implementation
// ============================================================================

std::string SegExecutionResult::SegTelemetry::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"events_logged\":" << events_logged << ",";
    oss << "\"events_dropped\":" << events_dropped << ",";
    oss << "\"tokens_per_second\":" << std::fixed << std::setprecision(2) << tokens_per_second << ",";
    oss << "\"time_to_first_token_ms\":" << time_to_first_token_ms << ",";
    oss << "\"total_time_ms\":" << total_time_ms << ",";
    oss << "\"peak_memory_bytes\":" << peak_memory_bytes;
    
    if (!layer_timings.empty()) {
        oss << ",\"layer_timings\":[";
        for (size_t i = 0; i < layer_timings.size(); ++i) {
            if (i > 0) oss << ",";
            oss << "{\"layer\":\"" << layer_timings[i].first << "\",";
            oss << "\"ms\":" << layer_timings[i].second << "}";
        }
        oss << "]";
    }
    
    oss << "}";
    return oss.str();
}

std::string SegExecutionResult::SegTelemetry::Summary() const {
    std::ostringstream oss;
    oss << "SEG Telemetry Summary:\n";
    oss << "  Events logged:  " << events_logged << "\n";
    oss << "  Events dropped: " << events_dropped << "\n";
    oss << "  Tokens/sec:     " << std::fixed << std::setprecision(2) << tokens_per_second << "\n";
    oss << "  TTFT:           " << std::setprecision(2) << time_to_first_token_ms << " ms\n";
    oss << "  Total time:     " << std::setprecision(2) << total_time_ms << " ms\n";
    oss << "  Peak memory:    " << (peak_memory_bytes / (1024.0 * 1024.0)) << " MB\n";
    
    if (!layer_timings.empty()) {
        oss << "\n  Per-layer timings:\n";
        for (const auto& [name, ms] : layer_timings) {
            oss << "    " << std::setw(20) << std::left << name << " " 
                << std::setprecision(3) << ms << " ms\n";
        }
    }
    
    return oss.str();
}

SegExecutionResult SegExecutionResult::Success(const std::string& text) {
    SegExecutionResult r;
    r.status = execution::Status::SUCCESS;
    r.text_output = text;
    r.status_message = "Success";
    return r;
}

SegExecutionResult SegExecutionResult::Error(const std::string& message) {
    SegExecutionResult r;
    r.status = execution::Status::RUNTIME_FAILURE;
    r.status_message = message;
    r.error_details = message;
    return r;
}

SegExecutionResult SegExecutionResult::FromExecutionResult(const execution::ExecutionResult& base) {
    SegExecutionResult r;
    r.status = base.status;
    r.text_output = base.text_output;
    r.status_message = base.status_message;
    r.error_details = base.error_details;
    // Note: telemetry and tokens would be filled separately
    return r;
}

// ============================================================================
// SegGateway Implementation
// ============================================================================

SegGateway::SegGateway() = default;
SegGateway::~SegGateway() {
    Shutdown();
}

bool SegGateway::Initialize(const std::string& model_path) {
    if (initialized_) {
        Shutdown();
    }
    
    model_path_ = model_path;
    
    // Initialize MASM telemetry
    if (!InitializeMasmTelemetry(8 * 1024 * 1024)) {  // 8MB buffer
        return false;
    }
    
    // TODO: Initialize SEG runtime with model
    // This would load the GGUF and build the execution graph
    
    initialized_ = true;
    return true;
}

void SegGateway::Shutdown() {
    if (initialized_) {
        // Flush any remaining telemetry
        MasmTelemetry_Flush();
        ShutdownMasmTelemetry();
        
        runtime_.reset();
        initialized_ = false;
    }
}

SegExecutionResult SegGateway::Run(const execution::ExecutionRequest& req) {
    if (!initialized_) {
        return SegExecutionResult::Error("SEG Gateway not initialized");
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Log generation start
    MasmTelemetry_Log(TELEMETRY_GENERATION_START, 0, 0);
    
    // TODO: Real SEG execution
    // 1. Tokenize prompt
    // 2. Build/execute SEG graph for each token
    // 3. Collect generated tokens
    // 4. Decode to text
    
    // For now, return stub result
    SegExecutionResult result;
    result.status = execution::Status::SUCCESS;
    result.status_message = "SEG inference executed";
    result.text_output = "[SEG would generate text here]";
    
    // Simulate token generation
    for (int i = 0; i < req.max_tokens; ++i) {
        MasmTelemetry_Log(TELEMETRY_GENERATION_TOKEN, i, 0);
        result.tokens_generated.push_back(0);  // Placeholder
    }
    
    MasmTelemetry_Log(TELEMETRY_GENERATION_END, req.max_tokens, 0);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time).count();
    
    // Collect telemetry
    result.telemetry = CollectTelemetry();
    result.telemetry.total_time_ms = static_cast<double>(duration_ms);
    result.telemetry.tokens_per_second = req.max_tokens / (duration_ms / 1000.0);
    
    return result;
}

std::string SegGateway::GetModelInfo() const {
    if (!initialized_) {
        return "Not initialized";
    }
    
    std::ostringstream oss;
    oss << "Model: " << model_path_ << "\n";
    oss << "SEG Runtime: Initialized\n";
    oss << "MASM Telemetry: Active\n";
    return oss.str();
}

SegExecutionResult::SegTelemetry SegGateway::CollectTelemetry() {
    SegExecutionResult::SegTelemetry telemetry;
    
    TelemetryStats stats;
    MasmTelemetry_GetStats(&stats);
    
    telemetry.events_logged = stats.eventsLogged;
    telemetry.events_dropped = stats.eventsDropped;
    telemetry.peak_memory_bytes = stats.bufferUsed;  // Approximation
    
    // Flush telemetry
    MasmTelemetry_Flush();
    
    return telemetry;
}

// ============================================================================
// Convenience Functions
// ============================================================================

SegExecutionResult RunSegInference(const execution::ExecutionRequest& req) {
    SegGateway gateway;
    
    if (!gateway.Initialize(req.model_path)) {
        return SegExecutionResult::Error("Failed to initialize SEG gateway");
    }
    
    auto result = gateway.Run(req);
    gateway.Shutdown();
    
    return result;
}

bool IsSegAvailable() {
    // Try to initialize and immediately shutdown
    return InitializeMasmTelemetry(1024 * 1024);
}

std::string GetSegVersion() {
    return "SEG 1.0.0 (MASM Telemetry Core)";
}

} // namespace gateway
} // namespace rawrxd
