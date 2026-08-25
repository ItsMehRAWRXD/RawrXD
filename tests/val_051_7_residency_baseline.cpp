// ============================================================================
// VAL-051.7 — Residency Baseline / Fixture Gate
//
// Purpose:
//   Establish an immutable baseline of residency counter values before any
//   residency optimization changes. This initial version runs the proven
//   production inference path WITHOUT residency instrumentation to establish
//   a clean execution baseline.
//
// IMPORTANT:
//   Reuses the exact production calls from val_051_2_a_real_token.cpp.
//   Does NOT change residency behavior.
// ============================================================================

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>
#include <vector>
#include <chrono>
#include <filesystem>

// RawrXD Inference Components
#include "rawrxd_inference.h"
#include "tokenizer/gguf_embedded_tokenizer.hpp"

namespace fs = std::filesystem;
using namespace std::chrono;

namespace {

constexpr int kTargetTokens = 15;
constexpr float kMinHiddenNorm = 1.0e-12f;

struct StepEvidence {
    int position;
    int token;
    float selected_logit;
    float hidden_norm;
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
        // Load embedded tokenizer from GGUF
        if (!tokenizer.LoadFromGGUF(model_path)) {
            std::cerr << "[FAIL] Failed to load embedded tokenizer from GGUF\n";
            return false;
        }

        // Convert model path to wchar_t for RawrXDInference
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

    bool tokenize(
        const std::string& text,
        std::vector<int>& tokens)
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

    bool prefill(
        const std::vector<int>& prompt_tokens,
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

    bool decode(
        int previous_token,
        int kv_position,
        std::vector<float>& logits,
        float& hidden_norm)
    {
        std::vector<uint32_t> nextTokVec = {static_cast<uint32_t>(previous_token)};
        logits = inference.ForwardTokens(nextTokVec, static_cast<uint32_t>(kv_position));
        hidden_norm = computeHiddenNorm(logits);
        return !logits.empty();
    }

    void shutdown()
    {
        // RawrXDInference cleanup is automatic on destruction
    }
};

// ============================================================================
// Helpers
// ============================================================================

bool allFinite(const std::vector<float>& v)
{
    if (v.empty())
        return false;

    for (float x : v) {
        if (!std::isfinite(x))
            return false;
    }

    return true;
}

int greedyToken(const std::vector<float>& logits)
{
    if (logits.empty())
        return -1;

    int best = 0;

    for (int i = 1;
         i < static_cast<int>(logits.size());
         ++i)
    {
        if (logits[i] > logits[best])
            best = i;
    }

    return best;
}

float maxLogit(const std::vector<float>& logits)
{
    if (logits.empty())
        return -std::numeric_limits<float>::infinity();

    return *std::max_element(logits.begin(), logits.end());
}

void writeEvidence(
    const Gate& gate,
    const char* filename)
{
    std::ofstream out(filename, std::ios::trunc);

    if (!out)
        return;

    out << "{\n";
    out << "  \"gate\": \"VAL-051.7\",\n";
    out << "  \"target_tokens\": " << kTargetTokens << ",\n";
    out << "  \"generated_tokens\": " << gate.generated << ",\n";
    out << "  \"invalid_tokens\": " << gate.invalid_tokens << ",\n";
    out << "  \"nonfinite_logits\": "
        << gate.nonfinite_logits << ",\n";
    out << "  \"hidden_failures\": "
        << gate.hidden_failures << ",\n";
    out << "  \"position_failures\": "
        << gate.position_failures << ",\n";
    out << "  \"pass\": "
        << (gate.pass ? "true" : "false") << ",\n";

    out << "  \"sequence\": [";

    for (std::size_t i = 0; i < gate.sequence.size(); ++i) {
        if (i)
            out << ", ";

        out << gate.sequence[i];
    }

    out << "],\n";

    out << "  \"steps\": [\n";

    for (std::size_t i = 0; i < gate.steps.size(); ++i) {
        const auto& s = gate.steps[i];

        out << "    {\n";
        out << "      \"position\": " << s.position << ",\n";
        out << "      \"token\": " << s.token << ",\n";
        out << "      \"selected_logit\": "
            << std::setprecision(10)
            << s.selected_logit << ",\n";
        out << "      \"hidden_norm\": "
            << std::setprecision(10)
            << s.hidden_norm << "\n";
        out << "    }";

        if (i + 1 != gate.steps.size())
            out << ",";

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
        << "TARGET=15\n"
        << "PROMPT=" << prompt << "\n"
        << "============================================================\n";

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

    if (prompt_tokens.empty()) {
        std::cerr << "[FAIL] EMPTY_TOKENIZATION\n";
        engine.shutdown();
        return 1;
    }

    std::cout
        << "[PASS] TOKENIZER count="
        << prompt_tokens.size()
        << "\n";

    // ------------------------------------------------------------------------
    // PREFILL
    // ------------------------------------------------------------------------

    std::vector<float> logits;
    float hidden_norm = 0.0f;

    if (!engine.prefill(
            prompt_tokens,
            logits,
            hidden_norm))
    {
        std::cerr << "[FAIL] PREFILL\n";
        engine.shutdown();
        return 1;
    }

    if (!allFinite(logits)) {
        std::cerr << "[FAIL] PREFILL_NONFINITE_LOGITS\n";
        engine.shutdown();
        return 1;
    }

    if (!std::isfinite(hidden_norm) ||
        hidden_norm <= kMinHiddenNorm)
    {
        std::cerr
            << "[FAIL] PREFILL_HIDDEN_COLLAPSE norm="
            << hidden_norm
            << "\n";

        engine.shutdown();
        return 1;
    }

    std::cout
        << "[PASS] PREFILL logits="
        << logits.size()
        << " hidden_norm="
        << std::setprecision(9)
        << hidden_norm
        << "\n";

    Gate gate;

    // ------------------------------------------------------------------------
    // FIRST TOKEN
    //
    // First token comes from the final prefill logits.
    // ------------------------------------------------------------------------

    int next_token = greedyToken(logits);

    if (next_token < 0) {
        std::cerr << "[FAIL] PREFILL_ARGMAX\n";
        engine.shutdown();
        return 1;
    }

    if (engine.vocab_size != 0 &&
        static_cast<std::size_t>(next_token) >=
            engine.vocab_size)
    {
        std::cerr
            << "[FAIL] TOKEN_RANGE position=0 token="
            << next_token
            << "\n";

        gate.invalid_tokens++;
        gate.fail();

        engine.shutdown();
        return 1;
    }

    gate.sequence.push_back(next_token);
    gate.generated = 1;

    gate.steps.push_back({
        0,
        next_token,
        logits[next_token],
        hidden_norm
    });

    std::cout
        << "TOKEN[0]="
        << next_token
        << " LOGIT="
        << logits[next_token]
        << " HIDDEN_NORM="
        << hidden_norm
        << "\n";

    // ------------------------------------------------------------------------
    // 14 KV-CACHE DECODE STEPS
    //
    // Total generated tokens = 15.
    //
    // Positions:
    //   0 = prefill result
    //   1..14 = autoregressive KV decode
    // ------------------------------------------------------------------------

    for (int position = 1;
         position < kTargetTokens;
         ++position)
    {
        logits.clear();
        hidden_norm = 0.0f;

        if (!engine.decode(
                next_token,
                position,
                logits,
                hidden_norm))
        {
            std::cerr
                << "[FAIL] DECODE position="
                << position
                << "\n";

            gate.position_failures++;
            gate.fail();
            break;
        }

        // --------------------------------------------------------------------
        // LOGIT FINITENESS
        // --------------------------------------------------------------------

        if (!allFinite(logits)) {
            std::cerr
                << "[FAIL] NONFINITE_LOGITS position="
                << position
                << "\n";

            gate.nonfinite_logits++;
            gate.fail();
            break;
        }

        // --------------------------------------------------------------------
        // HIDDEN STATE
        // --------------------------------------------------------------------

        if (!std::isfinite(hidden_norm) ||
            hidden_norm <= kMinHiddenNorm)
        {
            std::cerr
                << "[FAIL] HIDDEN_COLLAPSE position="
                << position
                << " norm="
                << hidden_norm
                << "\n";

            gate.hidden_failures++;
            gate.fail();
            break;
        }

        // --------------------------------------------------------------------
        // GREEDY NEXT TOKEN
        // --------------------------------------------------------------------

        next_token = greedyToken(logits);

        if (next_token < 0) {
            std::cerr
                << "[FAIL] ARGMAX position="
                << position
                << "\n";

            gate.fail();
            break;
        }

        if (engine.vocab_size != 0 &&
            static_cast<std::size_t>(next_token) >=
                engine.vocab_size)
        {
            std::cerr
                << "[FAIL] TOKEN_RANGE position="
                << position
                << " token="
                << next_token
                << "\n";

            gate.invalid_tokens++;
            gate.fail();
            break;
        }

        const float selected_logit =
            logits[next_token];

        if (!std::isfinite(selected_logit)) {
            std::cerr
                << "[FAIL] SELECTED_LOGIT position="
                << position
                << "\n";

            gate.nonfinite_logits++;
            gate.fail();
            break;
        }

        gate.sequence.push_back(next_token);
        gate.generated++;

        gate.steps.push_back({
            position,
            next_token,
            selected_logit,
            hidden_norm
        });

        std::cout
            << "TOKEN["
            << position
            << "]="
            << next_token
            << " LOGIT="
            << std::setprecision(9)
            << selected_logit
            << " HIDDEN_NORM="
            << hidden_norm
            << "\n";
    }

    // ------------------------------------------------------------------------
    // FINAL CERTIFICATION
    // ------------------------------------------------------------------------

    if (gate.generated != kTargetTokens)
        gate.fail();

    fs::create_directories("evidence");
    writeEvidence(
        gate,
        "evidence/VAL-051-7-B7-EVIDENCE.json");

    std::cout
        << "\n============================================================\n"
        << "VAL-051.7 EVIDENCE\n"
        << "============================================================\n";

    std::cout
        << "GENERATED="
        << gate.generated
        << "/"
        << kTargetTokens
        << "\n";

    std::cout
        << "INVALID_TOKENS="
        << gate.invalid_tokens
        << "\n";

    std::cout
        << "NONFINITE_LOGITS="
        << gate.nonfinite_logits
        << "\n";

    std::cout
        << "HIDDEN_FAILURES="
        << gate.hidden_failures
        << "\n";

    std::cout
        << "POSITION_FAILURES="
        << gate.position_failures
        << "\n";

    std::cout << "SEQUENCE=";

    for (std::size_t i = 0;
         i < gate.sequence.size();
         ++i)
    {
        if (i)
            std::cout << ' ';

        std::cout << gate.sequence[i];
    }

    std::cout << "\n";

    std::cout
        << "EVIDENCE="
        << "evidence/VAL-051-7-B7-EVIDENCE.json"
        << "\n";

    if (gate.pass) {
        std::cout
            << "\nBATCH_7_RESULT=PASS\n"
            << "EXIT_CODE=0\n";
    } else {
        std::cout
            << "\nBATCH_7_RESULT=FAIL\n"
            << "EXIT_CODE=1\n";
    }

    std::cout
        << "============================================================\n";

    engine.shutdown();

    return gate.pass ? 0 : 1;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr
            << "Usage: val_051_6_15_token_kv.exe "
               "<model.gguf>\n";
        return 2;
    }

    return executeGate(argv[1]);
}
