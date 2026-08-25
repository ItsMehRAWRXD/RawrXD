// ============================================================================
// VAL-051.5-DIAG — 1-Token Diagnostic Harness for B35
//
// Purpose: Determine where generation hangs without waiting for 15 tokens.
// Uses the same Deep2Engine path as the full B35 gate.
//
// Per-stage logging:
//   [B35_DIAG] GENERATE_BEGIN
//   [B35_DIAG] TOKEN_N BEGIN
//   [B35_DIAG] TOKEN_N EMBED_DONE
//   [B35_DIAG] TOKEN_N FORWARD_BEGIN
//   [B35_DIAG] TOKEN_N FORWARD_DONE
//   [B35_DIAG] TOKEN_N LOGITS_DONE
//   [B35_DIAG] TOKEN_N SAMPLE_DONE
//   [B35_DIAG] TOKEN_N KV_ADVANCE
//   [B35_DIAG] GENERATE_END
// ============================================================================

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include "Deep2Engine.h"
#include "GGUFLoader.hpp"

namespace {

constexpr int kGeneratedTokens = 1;

static std::string JsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"':  out += "\\\""; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:   out += c;      break;
        }
    }
    return out;
}

} // namespace

int main(int argc, char** argv)
{
    const std::string modelPath =
        argc > 1 ? argv[1]
                 : "G:\\OllamaModels\\Codestral-22B-v0.1-Q4_K_M.gguf";

    const std::string evidencePath =
        argc > 2 ? argv[2]
                 : "D:\\rawrxd\\evidence\\B35_DIAG_1_TOKEN.json";

    std::cout << "============================================================\n";
    std::cout << "VAL-051.5-DIAG — 1-TOKEN DIAGNOSTIC HARNESS\n";
    std::cout << "============================================================\n";
    std::cout << "MODEL=" << modelPath << "\n";
    std::cout << "TARGET_TOKENS=" << kGeneratedTokens << "\n";
    std::cout << "[B35_DIAG] GENERATE_BEGIN\n";
    std::cout << "[B35_DIAG] MODEL=" << modelPath << "\n";
    std::cout << "[B35_DIAG] TOKENS_TARGET=" << kGeneratedTokens << "\n";

    try {
        Deep2::Deep2Engine engine;
        std::cout << "[BOOT] PASS\n";

        Deep2::EngineConfig cfg;
        cfg.hiddenDim = 6144;
        cfg.numLayers = 56;
        cfg.numHeads = 48;
        cfg.numKVHeads = 8;
        cfg.headDim = 128;
        cfg.vocabSize = 32768;
        cfg.maxSeqLen = 4096;
        cfg.useKVCache = true;
        cfg.useThreadPool = true;
        cfg.numThreads = 16;

        if (!engine.initialize(cfg)) {
            std::cerr << "[FAIL] engine initialization\n";
            return 1;
        }
        std::cout << "[ENGINE_INIT] PASS\n";

        if (!engine.loadModel(modelPath)) {
            std::cerr << "[FAIL] model load\n";
            return 1;
        }
        std::cout << "[GGUF_LOAD] PASS\n";

        const std::string prompt = "Hello";
        std::vector<int> promptTokens = engine.tokenize(prompt);
        if (promptTokens.empty()) {
            std::cerr << "[FAIL] tokenizer produced zero prompt tokens\n";
            return 1;
        }
        std::cout << "[TOKENIZER_READY] PASS\n";
        std::cout << "[PROMPT_ENCODE] tokens=";
        for (int t : promptTokens) std::cout << t << ' ';
        std::cout << "\n";

        // Generate exactly 1 token with per-stage logging
        std::cout << "[B35_DIAG] TOKEN=1 BEGIN\n";
        engine.reset();
        std::vector<int> outputTokens(kGeneratedTokens);
        
        auto start = std::chrono::steady_clock::now();
        size_t generated = engine.generate(
            promptTokens.data(), promptTokens.size(),
            outputTokens.data(), kGeneratedTokens);
        auto end = std::chrono::steady_clock::now();
        
        double totalMs = std::chrono::duration<double, std::milli>(end - start).count();

        std::cout << "[B35_DIAG] GENERATE_END\n";
        std::cout << "[B35_DIAG] GENERATED=" << generated << "\n";
        std::cout << "[B35_DIAG] TIME_MS=" << std::fixed << std::setprecision(2) << totalMs << "\n";

        if (generated != kGeneratedTokens) {
            std::cerr << "[FAIL] generated " << generated
                      << " tokens; expected " << kGeneratedTokens << "\n";
            return 1;
        }

        std::cout << "TOKEN[0] id=" << outputTokens[0] << "\n";

        std::string decoded;
        try {
            decoded = engine.detokenize(std::vector<int>{outputTokens[0]});
        } catch (...) {
            decoded = "";
        }
        std::cout << "TOKEN[0] text=\"" << decoded << "\"\n";

        std::cout << "\n============================================================\n";
        std::cout << "B35 DIAG: " << generated << "/" << kGeneratedTokens << " PASS\n";
        std::cout << "TIME: " << totalMs << " ms\n";
        std::cout << "============================================================\n";

        // Evidence JSON
        std::ofstream json(evidencePath, std::ios::trunc);
        if (json) {
            json << "{\n";
            json << "  \"batch\": \"B35_DIAG\",\n";
            json << "  \"gate\": \"1-token-diagnostic\",\n";
            json << "  \"model\": \"" << JsonEscape(modelPath) << "\",\n";
            json << "  \"generated_tokens\": " << generated << ",\n";
            json << "  \"result\": \"PASS\",\n";
            json << "  \"exit_code\": 0,\n";
            json << "  \"time_ms\": " << std::fixed << std::setprecision(2) << totalMs << ",\n";
            json << "  \"token\": " << outputTokens[0] << ",\n";
            json << "  \"text\": \"" << JsonEscape(decoded) << "\"\n";
            json << "}\n";
            json.close();
            std::cout << "[EVIDENCE_WRITE] " << evidencePath << "\n";
        } else {
            std::cerr << "[WARN] unable to write evidence file: " << evidencePath << "\n";
        }

        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "[CRASH_BOUNDARY] " << e.what() << "\n";
        return 2;
    }
    catch (...) {
        std::cerr << "[CRASH_BOUNDARY] unknown exception\n";
        return 2;
    }
}
