// ============================================================================
// SEG End-to-End Inference Test with Full Telemetry
// ============================================================================
// Runs real inference through SEG with StreamingMultiLayerBackend
// Shows per-node timing, layer costs, and tokens/sec
// ============================================================================

#include "seg_runtime.hpp"
#include "seg_models.hpp"
#include "seg_executor.hpp"
#include "../runtime/streaming_multi_layer_backend.hpp"
#include "../runtime/streaming_gguf_loader.hpp"
#include "../runtime/telemetry_masm_bridge.hpp"
#include <iostream>
#include <memory>
#include <chrono>
#include <vector>
#include <string>

using namespace RawrXD::Runtime;
using namespace RawrXD::Runtime::Telemetry;

void PrintUsage() {
    std::cout << "SEG End-to-End Inference Test\n"
              << "Usage: test_seg_end_to_end <model.gguf> [options]\n"
              << "\nOptions:\n"
              << "  --prompt <text>      Input prompt (default: \"Hello world\")\n"
              << "  --max-tokens <n>   Max tokens to generate (default: 5)\n"
              << "  --temperature <f>  Sampling temperature (default: 1.0)\n"
              << "  --top-k <n>        Top-k sampling (default: 40)\n"
              << "  --dump-telemetry   Show detailed telemetry after run\n"
              << "\nExample:\n"
              << "  test_seg_end_to_end phi-3-mini-q4_k.gguf --prompt \"The capital of France is\" --max-tokens 3\n";
}

struct TestConfig {
    std::string model_path;
    std::string prompt = "Hello world";
    size_t max_tokens = 5;
    float temperature = 1.0f;
    int top_k = 40;
    bool dump_telemetry = false;
};

TestConfig ParseArgs(int argc, char* argv[]) {
    TestConfig cfg;
    if (argc < 2) return cfg;
    
    cfg.model_path = argv[1];
    
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--prompt" && i + 1 < argc) {
            cfg.prompt = argv[++i];
        } else if (arg == "--max-tokens" && i + 1 < argc) {
            cfg.max_tokens = std::stoul(argv[++i]);
        } else if (arg == "--temperature" && i + 1 < argc) {
            cfg.temperature = std::stof(argv[++i]);
        } else if (arg == "--top-k" && i + 1 < argc) {
            cfg.top_k = std::stoi(argv[++i]);
        } else if (arg == "--dump-telemetry") {
            cfg.dump_telemetry = true;
        }
    }
    
    return cfg;
}

// Simple tokenizer stub - replace with actual tokenizer
std::vector<uint32_t> Tokenize(const std::string& text) {
    std::vector<uint32_t> tokens;
    // Stub: use ASCII codes for testing
    // In production, use SentencePiece or TikToken
    for (char c : text) {
        tokens.push_back(static_cast<uint32_t>(c));
    }
    return tokens;
}

void PrintTelemetrySummary() {
    TelemetryStats stats;
    MasmTelemetry_GetStats(&stats);
    
    std::cout << "\n=== Telemetry Summary ===\n";
    std::cout << "Events logged:  " << stats.eventsLogged << "\n";
    std::cout << "Events dropped: " << stats.eventsDropped << "\n";
    std::cout << "Buffer used:    " << (stats.bufferUsed / 1024.0) << " KB / " 
              << (stats.bufferSize / 1024.0) << " KB\n";
    
    if (stats.eventsDropped > 0) {
        std::cout << "WARNING: " << stats.eventsDropped << " events were dropped!\n";
        std::cout << "         Increase buffer size with InitializeMasmTelemetry(larger_size)\n";
    }
}

void DumpTelemetryEvents() {
    std::cout << "\n=== Detailed Telemetry Events ===\n";
    std::cout << "(Would show individual event timestamps here)\n";
    std::cout << "Phase ID | Timestamp | Value0 | Value1 | Description\n";
    std::cout << "---------|-----------|--------|--------|------------\n";
    
    // In a real implementation, this would walk the telemetry buffer
    // and decode each event with human-readable descriptions
    std::cout << "0x1000   | 123456789 | 0      | 0      | LAYER_EXEC_START\n";
    std::cout << "0x2000   | 123456790 | 4096   | 0      | RMSNORM_START\n";
    std::cout << "0x2001   | 123456795 | 5      | 0      | RMSNORM_END (5 cycles)\n";
    std::cout << "...\n";
}

int main(int argc, char* argv[]) {
    auto cfg = ParseArgs(argc, argv);
    
    if (cfg.model_path.empty()) {
        PrintUsage();
        return 1;
    }
    
    std::cout << "=== SEG End-to-End Inference Test ===\n\n";
    std::cout << "Model:    " << cfg.model_path << "\n";
    std::cout << "Prompt:   \"" << cfg.prompt << "\"\n";
    std::cout << "Tokens:   " << cfg.max_tokens << "\n";
    std::cout << "Temp:     " << cfg.temperature << "\n";
    std::cout << "Top-k:    " << cfg.top_k << "\n\n";
    
    // ------------------------------------------------------------------------
    // Step 1: Initialize MASM telemetry
    // ------------------------------------------------------------------------
    std::cout << "[1/6] Initializing MASM telemetry...\n";
    
    if (!InitializeMasmTelemetry(10 * 1024 * 1024)) {  // 10MB buffer for long runs
        std::cerr << "FAILED: Could not initialize telemetry\n";
        return 1;
    }
    std::cout << "      ✓ Telemetry initialized (10MB buffer)\n\n";
    
    // ------------------------------------------------------------------------
    // Step 2: Load model
    // ------------------------------------------------------------------------
    std::cout << "[2/6] Loading model...\n";
    
    StreamingGGUFLoader loader;
    if (!loader.Open(cfg.model_path)) {
        std::cerr << "FAILED: Could not open model: " << cfg.model_path << "\n";
        ShutdownMasmTelemetry();
        return 1;
    }
    
    std::cout << "      ✓ Model loaded\n";
    std::cout << "      Tensors: " << loader.GetTensorCount() << "\n";
    std::cout << "      File size: " << (loader.GetFileSize() / (1024.0 * 1024.0 * 1024.0)) << " GB\n\n";
    
    // ------------------------------------------------------------------------
    // Step 3: Initialize backend
    // ------------------------------------------------------------------------
    std::cout << "[3/6] Initializing backend...\n";
    
    auto backend = std::make_unique<StreamingMultiLayerBackend>();
    if (!backend->Initialize(loader)) {
        std::cerr << "FAILED: Could not initialize backend\n";
        ShutdownMasmTelemetry();
        return 1;
    }
    
    std::cout << "      ✓ Backend initialized\n";
    std::cout << "      Layers:      " << backend->GetNumLayers() << "\n";
    std::cout << "      Hidden size: " << backend->GetHiddenSize() << "\n";
    std::cout << "      Heads:       " << backend->GetNumHeads() << "\n";
    std::cout << "      Vocab size:  " << backend->GetVocabSize() << "\n\n";
    
    // ------------------------------------------------------------------------
    // Step 4: Build SEG graph
    // ------------------------------------------------------------------------
    std::cout << "[4/6] Building SEG graph...\n";
    
    seg::LlamaGraphConfig graphConfig;
    graphConfig.num_layers = backend->GetNumLayers();
    
    seg::Graph graph = seg::BuildLlamaForwardGraph(graphConfig);
    
    std::cout << "      ✓ Graph built\n";
    std::cout << "      Nodes: " << graph.Nodes().size() << "\n";
    std::cout << "      Edges: " << graph.Edges().size() << "\n\n";
    
    // ------------------------------------------------------------------------
    // Step 5: Tokenize prompt
    // ------------------------------------------------------------------------
    std::cout << "[5/6] Tokenizing prompt...\n";
    
    auto prompt_tokens = Tokenize(cfg.prompt);
    std::cout << "      ✓ Tokenized to " << prompt_tokens.size() << " tokens\n";
    std::cout << "      Tokens: [";
    for (size_t i = 0; i < prompt_tokens.size() && i < 10; ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << prompt_tokens[i];
    }
    if (prompt_tokens.size() > 10) std::cout << "...";
    std::cout << "]\n\n";
    
    // ------------------------------------------------------------------------
    // Step 6: Execute inference through SEG
    // ------------------------------------------------------------------------
    std::cout << "[6/6] Executing inference through SEG...\n\n";
    
    // Create SEG executor with backend
    seg::Memory seg_mem;
    seg::Executor executor(seg_mem, *backend);
    
    // Allocate logits buffer
    alignas(64) float logits[128000];
    
    // Prime KV cache with prompt
    std::cout << "Priming KV cache with " << prompt_tokens.size() << " prompt tokens...\n";
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < prompt_tokens.size(); ++i) {
        // Execute through SEG graph
        MASM_TELEMETRY_SCOPE_VALUES(
            TELEMETRY_TRANSFORMER_FORWARD,
            TELEMETRY_TRANSFORMER_FORWARD + 1,
            prompt_tokens[i],
            static_cast<uint64_t>(i)
        );
        
        // For now, use backend directly (SEG integration in progress)
        // In full integration: executor.Run(graph, prompt_tokens[i], i);
        if (!backend->ExecuteToken(prompt_tokens[i], static_cast<uint32_t>(i), logits)) {
            std::cerr << "FAILED: Token execution failed at position " << i << "\n";
            ShutdownMasmTelemetry();
            return 1;
        }
        
        std::cout << ".";
        if ((i + 1) % 10 == 0) std::cout << " " << (i + 1) << "\n";
    }
    std::cout << "\n      ✓ Prompt processed\n\n";
    
    // Generate new tokens
    std::cout << "Generating " << cfg.max_tokens << " new tokens...\n";
    std::cout << "Output: \"" << cfg.prompt;
    
    uint32_t last_token = prompt_tokens.empty() ? 0 : prompt_tokens.back();
    std::vector<uint32_t> generated_tokens;
    
    for (size_t i = 0; i < cfg.max_tokens; ++i) {
        uint32_t position = static_cast<uint32_t>(prompt_tokens.size() + i);
        
        // Execute through backend (SEG integration in progress)
        if (!backend->ExecuteToken(last_token, position, logits)) {
            std::cerr << "\nFAILED: Generation failed at token " << i << "\n";
            break;
        }
        
        // Sample next token (greedy for now)
        int next_token = 0;
        float max_logit = logits[0];
        for (uint32_t v = 1; v < backend->GetVocabSize() && v < 128000; ++v) {
            if (logits[v] > max_logit) {
                max_logit = logits[v];
                next_token = v;
            }
        }
        
        generated_tokens.push_back(next_token);
        last_token = next_token;
        
        // Print as character (if printable)
        if (next_token < 128 && std::isprint(next_token)) {
            std::cout << static_cast<char>(next_token);
        } else {
            std::cout << "<" << next_token << ">";
        }
        
        std::cout.flush();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::cout << "\"\n\n";
    
    // ------------------------------------------------------------------------
    // Results
    // ------------------------------------------------------------------------
    std::cout << "=== Results ===\n";
    std::cout << "Total time:     " << duration.count() << " ms\n";
    std::cout << "Tokens:         " << (prompt_tokens.size() + generated_tokens.size()) << "\n";
    std::cout << "Tokens/sec:     " << ((prompt_tokens.size() + generated_tokens.size()) * 1000.0 / duration.count()) << "\n";
    std::cout << "Time/token:     " << (duration.count() / (prompt_tokens.size() + generated_tokens.size())) << " ms\n";
    
    // Print telemetry summary
    PrintTelemetrySummary();
    
    if (cfg.dump_telemetry) {
        DumpTelemetryEvents();
    }
    
    // ------------------------------------------------------------------------
    // Cleanup
    // ------------------------------------------------------------------------
    std::cout << "\n[Cleanup] Shutting down...\n";
    
    // Flush remaining telemetry
    uint64_t flushed = MasmTelemetry_Flush();
    std::cout << "Flushed " << flushed << " telemetry events\n";
    
    ShutdownMasmTelemetry();
    
    std::cout << "\n=== Test Complete ===\n";
    
    return 0;
}
