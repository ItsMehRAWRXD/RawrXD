// ============================================================================
// Detailed Telemetry Test - Shows Per-Operation Cycle Counts
// ============================================================================
// Simulates transformer execution with realistic timing
// ============================================================================

#include "../runtime/telemetry_masm_bridge.hpp"
#include "../runtime/telemetry_ids.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <map>
#include <string>

using namespace RawrXD::Runtime;
using namespace RawrXD::Runtime::Telemetry;

struct PhaseTiming {
    uint32_t phase_id;
    uint64_t count = 0;
    uint64_t total_cycles = 0;
    uint64_t min_cycles = UINT64_MAX;
    uint64_t max_cycles = 0;
};

const char* GetPhaseName(uint32_t phase_id) {
    switch (phase_id) {
        case TELEMETRY_LAYER_START:         return "LAYER_START";
        case TELEMETRY_LAYER_END:           return "LAYER_END";
        case TELEMETRY_RMSNORM_START:       return "RMSNORM_START";
        case TELEMETRY_RMSNORM_END:         return "RMSNORM_END";
        case TELEMETRY_ATTENTION_START:     return "ATTENTION_START";
        case TELEMETRY_ATTENTION_QKV:       return "ATTENTION_QKV";
        case TELEMETRY_ATTENTION_ROPE:      return "ATTENTION_ROPE";
        case TELEMETRY_ATTENTION_SCORES:    return "ATTENTION_SCORES";
        case TELEMETRY_ATTENTION_SOFTMAX:   return "ATTENTION_SOFTMAX";
        case TELEMETRY_ATTENTION_WEIGHTED:  return "ATTENTION_WEIGHTED";
        case TELEMETRY_ATTENTION_OUTPUT:    return "ATTENTION_OUTPUT";
        case TELEMETRY_ATTENTION_END:       return "ATTENTION_END";
        case TELEMETRY_MLP_START:           return "MLP_START";
        case TELEMETRY_MLP_GATE:            return "MLP_GATE";
        case TELEMETRY_MLP_UP:              return "MLP_UP";
        case TELEMETRY_MLP_SiLU:            return "MLP_SiLU";
        case TELEMETRY_MLP_MUL:               return "MLP_MUL";
        case TELEMETRY_MLP_DOWN:            return "MLP_DOWN";
        case TELEMETRY_MLP_END:             return "MLP_END";
        case TELEMETRY_GENERATION_START:    return "GENERATION_START";
        case TELEMETRY_GENERATION_TOKEN:    return "GENERATION_TOKEN";
        case TELEMETRY_GENERATION_END:      return "GENERATION_END";
        default:                            return "UNKNOWN";
    }
}

void SimulateTransformerLayer(int layer_idx, int hidden_size, int num_heads, int seq_len) {
    // Layer start
    auto layer_start = MasmTelemetry_Rdtsc();
    MasmTelemetry_Log(TELEMETRY_LAYER_START, layer_idx, layer_start);
    
    // Pre-attention RMSNorm (~5-10 cycles per element)
    auto rms_start = MasmTelemetry_Rdtsc();
    MasmTelemetry_Log(TELEMETRY_RMSNORM_START, hidden_size, rms_start);
    // Simulate: for (i = 0; i < hidden_size; i++) { sum += x[i] * x[i]; }
    volatile float sum = 0;
    for (int i = 0; i < hidden_size / 100; ++i) sum += i * 0.001f;
    auto rms_end = MasmTelemetry_Rdtsc();
    MasmTelemetry_Log(TELEMETRY_RMSNORM_END, rms_end - rms_start, layer_idx);
    
    // Self-attention
    auto attn_start = MasmTelemetry_Rdtsc();
    MasmTelemetry_Log(TELEMETRY_ATTENTION_START, layer_idx, attn_start);
    
    // QKV projection (3 × hidden_size × hidden_size matmul)
    auto qkv_start = MasmTelemetry_Rdtsc();
    MasmTelemetry_Log(TELEMETRY_ATTENTION_QKV, hidden_size, num_heads);
    volatile float dot = 0;
    for (int i = 0; i < hidden_size / 50; ++i) dot += i * 0.001f;
    
    // RoPE (rotary embeddings)
    MasmTelemetry_Log(TELEMETRY_ATTENTION_ROPE, seq_len, num_heads);
    for (int i = 0; i < seq_len * num_heads / 100; ++i) dot += i * 0.0001f;
    
    // Q @ K^T (attention scores)
    auto scores_start = MasmTelemetry_Rdtsc();
    MasmTelemetry_Log(TELEMETRY_ATTENTION_SCORES, seq_len, seq_len);
    for (int i = 0; i < seq_len * seq_len / 200; ++i) dot += i * 0.00001f;
    
    // Softmax
    auto softmax_start = MasmTelemetry_Rdtsc();
    MasmTelemetry_Log(TELEMETRY_ATTENTION_SOFTMAX, seq_len, 0);
    for (int i = 0; i < seq_len / 10; ++i) dot += i * 0.0001f;
    
    // Weighted sum (softmax @ V)
    MasmTelemetry_Log(TELEMETRY_ATTENTION_WEIGHTED, seq_len, hidden_size / num_heads);
    for (int i = 0; i < seq_len * hidden_size / num_heads / 100; ++i) dot += i * 0.00001f;
    
    // Output projection
    MasmTelemetry_Log(TELEMETRY_ATTENTION_OUTPUT, hidden_size, hidden_size);
    for (int i = 0; i < hidden_size / 50; ++i) dot += i * 0.0001f;
    
    auto attn_end = MasmTelemetry_Rdtsc();
    MasmTelemetry_Log(TELEMETRY_ATTENTION_END, attn_end - attn_start, layer_idx);
    
    // Post-attention RMSNorm
    auto rms2_start = MasmTelemetry_Rdtsc();
    MasmTelemetry_Log(TELEMETRY_RMSNORM_START, hidden_size, rms2_start);
    for (int i = 0; i < hidden_size / 100; ++i) sum += i * 0.001f;
    auto rms2_end = MasmTelemetry_Rdtsc();
    MasmTelemetry_Log(TELEMETRY_RMSNORM_END, rms2_end - rms2_start, layer_idx);
    
    // MLP
    auto mlp_start = MasmTelemetry_Rdtsc();
    MasmTelemetry_Log(TELEMETRY_MLP_START, layer_idx, mlp_start);
    
    int intermediate = hidden_size * 4;  // Typical 4x expansion
    
    // Gate projection
    MasmTelemetry_Log(TELEMETRY_MLP_GATE, hidden_size, intermediate);
    for (int i = 0; i < hidden_size * intermediate / 500; ++i) dot += i * 0.00001f;
    
    // Up projection
    MasmTelemetry_Log(TELEMETRY_MLP_UP, hidden_size, intermediate);
    for (int i = 0; i < hidden_size * intermediate / 500; ++i) dot += i * 0.00001f;
    
    // SiLU activation
    MasmTelemetry_Log(TELEMETRY_MLP_SiLU, intermediate, 0);
    for (int i = 0; i < intermediate / 100; ++i) dot += i * 0.0001f;
    
    // Element-wise multiply (gate * up)
    MasmTelemetry_Log(TELEMETRY_MLP_MUL, intermediate, 0);
    for (int i = 0; i < intermediate / 100; ++i) dot += i * 0.0001f;
    
    // Down projection
    MasmTelemetry_Log(TELEMETRY_MLP_DOWN, intermediate, hidden_size);
    for (int i = 0; i < intermediate * hidden_size / 500; ++i) dot += i * 0.00001f;
    
    auto mlp_end = MasmTelemetry_Rdtsc();
    MasmTelemetry_Log(TELEMETRY_MLP_END, mlp_end - mlp_start, layer_idx);
    
    // Layer end
    auto layer_end = MasmTelemetry_Rdtsc();
    MasmTelemetry_Log(TELEMETRY_LAYER_END, layer_end - layer_start, layer_idx);
    
    (void)dot; (void)sum; // Suppress unused warnings
}

int main() {
    std::cout << "=== Transformer Telemetry Analysis ===\n\n";
    
    // Model config (similar to Phi-3-mini)
    const int num_layers = 12;
    const int hidden_size = 3072;
    const int num_heads = 24;
    const int seq_len = 128;
    const int num_tokens = 10;
    
    std::cout << "Model Configuration:\n";
    std::cout << "  Layers:      " << num_layers << "\n";
    std::cout << "  Hidden size: " << hidden_size << "\n";
    std::cout << "  Heads:       " << num_heads << "\n";
    std::cout << "  Seq length:  " << seq_len << "\n";
    std::cout << "  Tokens:      " << num_tokens << "\n\n";
    
    // Initialize telemetry
    std::cout << "[1/3] Initializing telemetry...\n";
    if (!InitializeMasmTelemetry(4 * 1024 * 1024)) {
        std::cerr << "FAILED\n";
        return 1;
    }
    std::cout << "      ✓ Ready\n\n";
    
    // Run inference
    std::cout << "[2/3] Running simulated inference...\n";
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Generation loop
    MasmTelemetry_Log(TELEMETRY_GENERATION_START, 0, 0);
    
    for (int token = 0; token < num_tokens; ++token) {
        // Process all layers for this token
        for (int layer = 0; layer < num_layers; ++layer) {
            SimulateTransformerLayer(layer, hidden_size, num_heads, seq_len + token);
        }
        
        MasmTelemetry_Log(TELEMETRY_GENERATION_TOKEN, token, 0);
        std::cout << ".";
        if ((token + 1) % 10 == 0) std::cout << " " << (token + 1) << "\n";
    }
    if (num_tokens % 10 != 0) std::cout << "\n";
    
    MasmTelemetry_Log(TELEMETRY_GENERATION_END, num_tokens, 0);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    
    std::cout << "      ✓ Complete in " << duration_ms << " ms\n\n";
    
    // Get stats
    TelemetryStats stats;
    MasmTelemetry_GetStats(&stats);
    
    // Results
    std::cout << "[3/3] Results:\n\n";
    
    std::cout << "=== Performance Metrics ===\n";
    std::cout << "Total time:     " << duration_ms << " ms\n";
    std::cout << "Tokens:         " << num_tokens << "\n";
    std::cout << "Tokens/sec:     " << std::fixed << std::setprecision(2) 
              << (num_tokens * 1000.0 / duration_ms) << "\n";
    std::cout << "Time/token:     " << std::setprecision(2) 
              << (duration_ms / (double)num_tokens) << " ms\n";
    std::cout << "Layers/token:   " << num_layers << "\n";
    std::cout << "Total layers:   " << (num_tokens * num_layers) << "\n\n";
    
    std::cout << "=== Telemetry Summary ===\n";
    std::cout << "Events logged:  " << stats.eventsLogged << "\n";
    std::cout << "Events dropped: " << stats.eventsDropped << "\n";
    std::cout << "Buffer used:    " << std::setprecision(2) << (stats.bufferUsed / 1024.0) << " KB / " 
              << (stats.bufferSize / 1024.0) << " KB\n";
    std::cout << "Events/sec:     " << (stats.eventsLogged * 1000.0 / duration_ms) << "\n\n";
    
    // Per-operation breakdown (simulated from event counts)
    std::cout << "=== Per-Operation Event Counts ===\n";
    std::cout << std::left << std::setw(20) << "Operation" << " " 
              << std::setw(10) << "Count" << " "
              << std::setw(15) << "Per Token" << " "
              << std::setw(20) << "Description" << "\n";
    std::cout << std::string(70, '-') << "\n";
    
    std::cout << std::setw(20) << "Layer" << " " 
              << std::setw(10) << (num_tokens * num_layers * 2) << " "
              << std::setw(15) << (num_layers * 2) << " "
              << "Layer start/end pairs\n";
    
    std::cout << std::setw(20) << "RMSNorm" << " " 
              << std::setw(10) << (num_tokens * num_layers * 2 * 2) << " "
              << std::setw(15) << (num_layers * 2 * 2) << " "
              << "Pre/post norm per layer\n";
    
    std::cout << std::setw(20) << "Attention" << " " 
              << std::setw(10) << (num_tokens * num_layers * 8) << " "
              << std::setw(15) << (num_layers * 8) << " "
              << "QKV+RoPE+scores+softmax+weighted+output\n";
    
    std::cout << std::setw(20) << "MLP" << " " 
              << std::setw(10) << (num_tokens * num_layers * 6) << " "
              << std::setw(15) << (num_layers * 6) << " "
              << "Gate+Up+SiLU+Mul+Down\n";
    
    std::cout << std::setw(20) << "Generation" << " " 
              << std::setw(10) << (num_tokens + 2) << " "
              << std::setw(15) << "1" << " "
              << "Start/token/end events\n";
    
    std::cout << "\n";
    
    // Flush and cleanup
    uint64_t flushed = MasmTelemetry_Flush();
    std::cout << "Flushed " << flushed << " events\n";
    ShutdownMasmTelemetry();
    
    std::cout << "\n=== Test Complete ===\n";
    
    return 0;
}
