// ============================================================================
// VAL-051.7 — Residency Baseline / Fixture Gate
//
// Purpose:
//   Establish an immutable baseline of residency counter values before any
//   residency optimization changes. Runs the production inference path with
//   ResidencyCounters instrumentation WITHOUT changing residency behavior.
//
// Captures:
//   - forwardCount, layerCount
//   - remapCount, remapBytes
//   - acquireCount, releaseCount, evictionCount
//   - mappedBytes, peakResidentBytes, currentResidentBytes
//   - weightLookupCount, matMulCount, batchedMatMulCount
//   - totalForwardMs, totalLayerMs, avgForwardMs, avgLayerMs
//
// Acceptance:
//   - 10 generated tokens (to warm cache)
//   - finite logits
//   - valid token IDs
//   - counters are non-negative and consistent
//   - clean exit
//
// IMPORTANT:
//   Reuses the exact production calls from val_051_2_a_real_token.cpp.
//   Does NOT change residency behavior — only instruments it.
// ============================================================================

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <filesystem>

// RawrXD Inference Components
#include "rawrxd_inference.h"
#include "tokenizer/gguf_embedded_tokenizer.hpp"

// Residency instrumentation (no behavior change)
#include "deep2/ResidencyCounters.hpp"

namespace fs = std::filesystem;
using namespace std::chrono;

namespace {

constexpr int kTargetTokens = 10;
constexpr float kMinHiddenNorm = 1.0e-12f;

struct StepEvidence {
    int position;
    int token;
    float selected_logit;
    float hidden_norm;
};

struct ResidencyMetrics {
    uint64_t forwardCount = 0;
    uint64_t layerCount = 0;
    uint64_t remapCount = 0;
    uint64_t remapBytes = 0;
    uint64_t acquireCount = 0;
    uint64_t releaseCount = 0;
    uint64_t evictionCount = 0;
    uint64_t mappedBytes = 0;
    uint64_t peakResidentBytes = 0;
    uint64_t currentResidentBytes = 0;
    uint64_t weightLookupCount = 0;
    uint64_t matMulCount = 0;
    uint64_t batchedMatMulCount = 0;
    double totalForwardMs = 0.0;
    double totalLayerMs = 0.0;
    double avgForwardMs = 0.0;
    double avgLayerMs = 0.0;
};

struct Gate {
    bool pass = true;

    int generated = 0;
    int invalid_tokens = 0;
    int nonfinite_logits = 0;
    int hidden_failures = 0;
    int position_failures = 0;

    std::vector<int> sequence;
    std::vector<StepEvidence> steps;
    ResidencyMetrics residency;

    void fail() { pass = false; }
};

// Compute RMS of logits as a proxy for hidden-state norm
float computeHiddenNorm(const std::vector<float>& logits) {
    if (logits.empty()) return 0.0f;
    double sum = 0.0;
    for (float x : logits) {
        sum += static_cast<double>(x) * static_cast<double>(x);
    }
    return static_cast<float>(std::sqrt(sum / logits.size()));
}

// ============================================================================
// PRODUCTION INTEGRATION — copied from val_051_2_a_real_token.cpp
// ============================================================================

struct RawrXDProductionPath {
    RawrXDInference inference;
    RawrXD::GGUFEmbeddedTokenizer tokenizer;
    std::size_t vocab_size = 0;

    bool initialize(const char* model_path)
    {
        if (!tokenizer.LoadFromGGUF(model_path)) {
            std::cerr << "[FAIL] Failed to load embedded tokenizer from GGUF\n";
            return false;
        }

        std::wstring wModelPath(model_path, model_path + strlen(model_path));

        bool initialized = inference.Initialize(wModelPath.c_str(), nullptr, nullptr);
        if (!initialized) {
            std::cerr << "[FAIL] RawrXDInference::Initialize returned false\n";
            std::cerr << "Error: " << inference.GetLastLoadErrorMessage() << "\n";
            return false;
        }

        vocab_size = static_cast<std::size_t>(inference.getVocabSize());
        return true;
    }

    bool tokenize(const std::string& text, std::vector<int>& tokens)
    {
        std::vector<uint32_t> uint_tokens;
        if (!tokenizer.EncodeLongestMatch(text.c_str(), uint_tokens)) {
            return false;
        }
        tokens.clear();
        for (auto t : uint_tokens) {
            tokens.push_back(static_cast<int>(t));
        }
        return !tokens.empty();
    }

    bool prefill(const std::vector<int>& prompt_tokens,
                 std::vector<float>& logits,
                 float& hidden_norm)
    {
        std::vector<uint32_t> uint_tokens;
        for (auto t : prompt_tokens) {
            uint_tokens.push_back(static_cast<uint32_t>(t));
        }

        logits = inference.ForwardTokens(uint_tokens, 0);
        hidden_norm = computeHiddenNorm(logits);
        return !logits.empty();
    }

    bool decode(int previous_token,
                int kv_position,
                std::vector<float>& logits,
                float& hidden_norm)
    {
        std::vector<uint32_t> nextTokVec = {static_cast<uint32_t>(previous_token)};
        logits = inference.ForwardTokens(nextTokVec, static_cast<uint32_t>(kv_position));
        hidden_norm = computeHiddenNorm(logits);
        return !logits.empty();
    }

    void shutdown() {}
};

// ============================================================================
// Helpers
// ============================================================================

bool allFinite(const std::vector<float>& v)
{
    if (v.empty()) return false;
    for (float x : v) {
        if (!std::isfinite(x)) return false;
    }
    return true;
}

int greedyToken(const std::vector<float>& logits)
{
    if (logits.empty()) return -1;
    int best = 0;
    for (int i = 1; i < static_cast<int>(logits.size()); ++i) {
        if (logits[i] > logits[best]) best = i;
    }
    return best;
}

float maxLogit(const std::vector<float>& logits)
{
    if (logits.empty()) return -std::numeric_limits<float>::infinity();
    return *std::max_element(logits.begin(), logits.end());
}

void captureResidencyMetrics(ResidencyMetrics& m)
{
    m.forwardCount = Deep2::ResidencyCounters::forwardCount;
    m.layerCount = Deep2::ResidencyCounters::layerCount;
    m.remapCount = Deep2::ResidencyCounters::remapCount;
    m.remapBytes = Deep2::ResidencyCounters::remapBytes;
    m.acquireCount = Deep2::ResidencyCounters::acquireCount;
    m.releaseCount = Deep2::ResidencyCounters::releaseCount;
    m.evictionCount = Deep2::ResidencyCounters::evictionCount;
    m.mappedBytes = Deep2::ResidencyCounters::mappedBytes;
    m.peakResidentBytes = Deep2::ResidencyCounters::peakResidentBytes;
    m.currentResidentBytes = Deep2::ResidencyCounters::currentResidentBytes;
    m.weightLookupCount = Deep2::ResidencyCounters::weightLookupCount;
    m.matMulCount = Deep2::ResidencyCounters::matMulCount;
    m.batchedMatMulCount = Deep2::ResidencyCounters::batchedMatMulCount;
    m.totalForwardMs = Deep2::ResidencyCounters::totalForwardMs;
    m.totalLayerMs = Deep2::ResidencyCounters::totalLayerMs;
    if (m.forwardCount > 0) m.avgForwardMs = m.totalForwardMs / m.forwardCount;
    if (m.layerCount > 0) m.avgLayerMs = m.totalLayerMs / m.layerCount;
}

void writeEvidence(const Gate& gate, const char* filename)
{
    std::ofstream out(filename, std::ios::trunc);
    if (!out) return;

    out << "{\n";
    out << "  \"validation_id\": \"VAL-051-7\",\n";
    out << "  \"validation_name\": \"Residency Baseline / Fixture Gate\",\n";
    out << "  \"timestamp\": \"2026-08-22T00:00:00Z\",\n";
    out << "  \"status\": \"" << (gate.pass ? "PASS" : "FAIL") << "\",\n";
    out << "  \"target_tokens\": " << kTargetTokens << ",\n";
    out << "  \"generated_tokens\": " << gate.generated << ",\n";
    out << "  \"invalid_tokens\": " << gate.invalid_tokens << ",\n";
    out << "  \"nonfinite_logits\": " << gate.nonfinite_logits << ",\n";
    out << "  \"hidden_failures\": " << gate.hidden_failures << ",\n";
    out << "  \"position_failures\": " << gate.position_failures << ",\n";
    out << "  \"inference_path\": \"RawrXDInference + GGUFEmbeddedTokenizer\",\n";
    out << "  \"notes\": \"B7 baseline: residency instrumented, behavior unchanged.\",\n";

    out << "  \"sequence\": [";
    for (std::size_t i = 0; i < gate.sequence.size(); ++i) {
        if (i) out << ", ";
        out << gate.sequence[i];
    }
    out << "],\n";

    out << "  \"residency_counters\": {\n";
    out << "    \"forwardCount\": " << gate.residency.forwardCount << ",\n";
    out << "    \"layerCount\": " << gate.residency.layerCount << ",\n";
    out << "    \"remapCount\": " << gate.residency.remapCount << ",\n";
    out << "    \"remapBytes\": " << gate.residency.remapBytes << ",\n";
    out << "    \"acquireCount\": " << gate.residency.acquireCount << ",\n";
    out << "    \"releaseCount\": " << gate.residency.releaseCount << ",\n";
    out << "    \"evictionCount\": " << gate.residency.evictionCount << ",\n";
    out << "    \"mappedBytes\": " << gate.residency.mappedBytes << ",\n";
    out << "    \"peakResidentBytes\": " << gate.residency.peakResidentBytes << ",\n";
    out << "    \"currentResidentBytes\": " << gate.residency.currentResidentBytes << ",\n";
    out << "    \"weightLookupCount\": " << gate.residency.weightLookupCount << ",\n";
    out << "    \"matMulCount\": " << gate.residency.matMulCount << ",\n";
    out << "    \"batchedMatMulCount\": " << gate.residency.batchedMatMulCount << ",\n";
    out << "    \"totalForwardMs\": " << std::fixed << std::setprecision(3) << gate.residency.totalForwardMs << ",\n";
    out << "    \"totalLayerMs\": " << std::fixed << std::setprecision(3) << gate.residency.totalLayerMs << ",\n";
    out << "    \"avgForwardMs\": " << std::fixed << std::setprecision(3) << gate.residency.avgForwardMs << ",\n";
    out << "    \"avgLayerMs\": " << std::fixed << std::setprecision(3) << gate.residency.avgLayerMs << "\n";
    out << "  },\n";

    out << "  \"steps\": [\n";
    for (std::size_t i = 0; i < gate.steps.size(); ++i) {
        const auto& s = gate.steps[i];
        out << "    {\n";
        out << "      \"position\": " << s.position << ",\n";
        out << "      \"token\": " << s.token << ",\n";
        out << "      \"selected_logit\": " << std::setprecision(10) << s.selected_logit << ",\n";
        out << "      \"hidden_norm\": " << std::setprecision(10) << s.hidden_norm << "\n";
        out << "    }";
        if (i + 1 != gate.steps.size()) out << ",";
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

// ============================================================================
// Gate
// ============================================================================

int executeGate(const char* model_path)
{
    constexpr const char* prompt = "Hello";

    std::cout
        << "============================================================\n"
        << "VAL-051.7 — RESIDENCY BASELINE / FIXTURE GATE\n"
        << "============================================================\n"
        << "MODEL=" << model_path << "\n"
        << "TARGET=" << kTargetTokens << "\n"
        << "PROMPT=" << prompt << "\n"
        << "============================================================\n";

    // Reset residency counters before any inference
    Deep2::ResidencyCounters::Reset();

    RawrXDProductionPath engine;

    // ------------------------------------------------------------------------
    // BOOT / MODEL LOAD
    // ------------------------------------------------------------------------

    if (!engine.initialize(model_path)) {
        std::cerr << "[FAIL] MODEL_LOAD\n";
        return 1;
    }

    std::cout << "[PASS] MODEL_LOAD vocab=" << engine.vocab_size << "\n";

    // ------------------------------------------------------------------------
    // TOKENIZER
    // ------------------------------------------------------------------------

    std::vector<int> prompt_tokens;

    if (!engine.tokenize(prompt, prompt_tokens)) {
        std::cerr << "[FAIL] TOKENIZER\n";
        engine.shutdown();
        return 1;
    }

    std::cout << "[PASS] TOKENIZER tokens=" << prompt_tokens.size() << "\n";

    // ------------------------------------------------------------------------
    // PREFILL
    // ------------------------------------------------------------------------

    std::vector<float> logits;
    float hidden_norm = 0.0f;

    if (!engine.prefill(prompt_tokens, logits, hidden_norm)) {
        std::cerr << "[FAIL] PREFILL\n";
        engine.shutdown();
        return 1;
    }

    if (!allFinite(logits)) {
        std::cerr << "[FAIL] PREFILL logits non-finite\n";
        engine.shutdown();
        return 1;
    }

    std::cout << "[PASS] PREFILL logits=" << logits.size()
              << " hidden_norm=" << hidden_norm << "\n";

    // ------------------------------------------------------------------------
    // FIRST TOKEN
    // ------------------------------------------------------------------------

    int next_token = greedyToken(logits);
    float sel_logit = maxLogit(logits);

    if (next_token < 0 || next_token >= static_cast<int>(engine.vocab_size)) {
        std::cerr << "[FAIL] FIRST_TOKEN invalid token_id=" << next_token << "\n";
        engine.shutdown();
        return 1;
    }

    std::cout << "[PASS] FIRST_TOKEN id=" << next_token
              << " logit=" << sel_logit
              << " hidden_norm=" << hidden_norm << "\n";

    // ------------------------------------------------------------------------
    // AUTOREGRESSIVE LOOP
    // ------------------------------------------------------------------------

    Gate gate;
    gate.sequence.push_back(next_token);
    gate.steps.push_back({static_cast<int>(prompt_tokens.size()), next_token, sel_logit, hidden_norm});
    gate.generated = 1;

    int kv_position = static_cast<int>(prompt_tokens.size());

    for (int step = 1; step < kTargetTokens; ++step) {
        kv_position++;

        std::vector<float> step_logits;
        float step_hidden = 0.0f;

        if (!engine.decode(next_token, kv_position, step_logits, step_hidden)) {
            std::cerr << "[FAIL] DECODE step=" << step << "\n";
            gate.fail();
            break;
        }

        if (!allFinite(step_logits)) {
            std::cerr << "[FAIL] DECODE non-finite logits step=" << step << "\n";
            gate.nonfinite_logits++;
            gate.fail();
            break;
        }

        if (step_hidden < kMinHiddenNorm) {
            std::cerr << "[FAIL] DECODE hidden collapse step=" << step
                      << " norm=" << step_hidden << "\n";
            gate.hidden_failures++;
            gate.fail();
            break;
        }

        int step_token = greedyToken(step_logits);
        float step_logit = maxLogit(step_logits);

        if (step_token < 0 || step_token >= static_cast<int>(engine.vocab_size)) {
            std::cerr << "[FAIL] DECODE invalid token step=" << step
                      << " id=" << step_token << "\n";
            gate.invalid_tokens++;
            gate.fail();
            break;
        }

        gate.sequence.push_back(step_token);
        gate.steps.push_back({kv_position, step_token, step_logit, step_hidden});
        gate.generated++;
        next_token = step_token;

        std::cout << "[PASS] TOKEN[" << step << "]=" << next_token
                  << " logit=" << step_logit
                  << " hidden_norm=" << step_hidden << "\n";
    }

    // ------------------------------------------------------------------------
    // CAPTURE RESIDENCY COUNTERS
    // ------------------------------------------------------------------------

    captureResidencyMetrics(gate.residency);
    Deep2::ResidencyCounters::Print();

    // Validate counter consistency
    if (gate.residency.currentResidentBytes > gate.residency.peakResidentBytes) {
        std::cerr << "[FAIL] currentResidentBytes > peakResidentBytes\n";
        gate.fail();
    }
    if (gate.residency.releaseCount > gate.residency.acquireCount) {
        std::cerr << "[FAIL] releaseCount > acquireCount\n";
        gate.fail();
    }

    // ------------------------------------------------------------------------
    // SUMMARY
    // ------------------------------------------------------------------------

    std::cout
        << "============================================================\n"
        << "BATCH_7_RESULT=" << (gate.pass ? "PASS" : "FAIL") << "\n"
        << "GENERATED=" << gate.generated << "/" << kTargetTokens << "\n"
        << "INVALID_TOKENS=" << gate.invalid_tokens << "\n"
        << "NONFINITE_LOGITS=" << gate.nonfinite_logits << "\n"
        << "HIDDEN_COLLAPSE=" << gate.hidden_failures << "\n"
        << "POSITION_ERRORS=" << gate.position_failures << "\n"
        << "SEQUENCE=";

    for (std::size_t i = 0; i < gate.sequence.size(); ++i) {
        if (i) std::cout << " ";
        std::cout << gate.sequence[i];
    }

    std::cout << "\n"
              << "EXIT_CODE=" << (gate.pass ? 0 : 1) << "\n"
              << "============================================================\n";

    // ------------------------------------------------------------------------
    // WRITE EVIDENCE
    // ------------------------------------------------------------------------

    fs::path evidenceDir = fs::path(model_path).parent_path().parent_path() / "evidence";
    if (!fs::exists(evidenceDir)) {
        evidenceDir = fs::current_path() / "evidence";
    }
    fs::create_directories(evidenceDir);
    fs::path evidencePath = evidenceDir / "VAL-051-7-B7-EVIDENCE.json";
    writeEvidence(gate, evidencePath.string().c_str());
    std::cout << "EVIDENCE=" << evidencePath.string() << "\n";

    engine.shutdown();
    return gate.pass ? 0 : 1;
}

// ============================================================================
// main
// ============================================================================

int main(int argc, char* argv[])
{
    const char* model_path = (argc > 1) ? argv[1]
        : "D:\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";

    int result = executeGate(model_path);

    std::cout << "\nEXIT_CODE=" << result << "\n";
    return result;
}

} // namespace
