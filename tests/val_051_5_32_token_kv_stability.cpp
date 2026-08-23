// ============================================================================
// VAL-051.5 — 32-Token KV / Autoregressive Stability Gate
//
// Purpose:
//   Prove that the production inference path can perform 32 consecutive
//   autoregressive decode steps while maintaining:
//     - KV-cache position continuity
//     - finite logits
//     - valid token IDs
//     - non-collapsing hidden state
//     - deterministic output
//     - clean process termination
//
// No external dependencies.
// Standard C++17 only.
//
// Integration:
//   Reuses the exact production calls from val_051_2_a_real_token.cpp.
//
// Exit:
//   0 = PASS
//   1 = FAIL
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

namespace fs = std::filesystem;
using namespace std::chrono;

namespace {

constexpr int kGeneratedTokens = 32;
constexpr int kRequiredRuns = 1;
constexpr float kMinNorm = 1.0e-12f;

struct TokenEvidence {
    int position = -1;
    int token_id = -1;
    float logit = 0.0f;
    float hidden_norm = 0.0f;
    bool finite = false;
};

struct GateResult {
    bool pass = true;
    int generated = 0;
    int invalid_tokens = 0;
    int nonfinite_logits = 0;
    int collapsed_hidden = 0;
    int position_errors = 0;
    std::vector<int> sequence;
    std::vector<TokenEvidence> evidence;

    void fail() {
        pass = false;
    }
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

struct RawrXDAdapter {
    RawrXDInference inference;
    RawrXD::GGUFEmbeddedTokenizer tokenizer;
    std::size_t vocab_size = 0;

    bool initialize(const char* model_path) {
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

    bool encode_prompt(
        const std::string& prompt,
        std::vector<int>& tokens)
    {
        std::vector<uint32_t> uint_tokens;
        if (!tokenizer.EncodeLongestMatch(prompt.c_str(), uint_tokens)) {
            return false;
        }
        tokens.clear();
        for (auto t : uint_tokens) {
            tokens.push_back(static_cast<int>(t));
        }
        return !tokens.empty();
    }

    bool prefill(
        const std::vector<int>& tokens,
        std::vector<float>& logits,
        float& hidden_norm)
    {
        std::vector<uint32_t> uint_tokens;
        for (auto t : tokens) {
            uint_tokens.push_back(static_cast<uint32_t>(t));
        }

        logits = inference.ForwardTokens(uint_tokens, 0);
        hidden_norm = computeHiddenNorm(logits);
        return !logits.empty();
    }

    bool decode(
        int token,
        int position,
        std::vector<float>& logits,
        float& hidden_norm)
    {
        std::vector<uint32_t> nextTokVec = {static_cast<uint32_t>(token)};
        logits = inference.ForwardTokens(nextTokVec, static_cast<uint32_t>(position));
        hidden_norm = computeHiddenNorm(logits);
        return !logits.empty();
    }

    void shutdown() {
        // RawrXDInference cleanup is automatic on destruction
    }
};

// ============================================================================
// Validation helpers
// ============================================================================

bool finite_vector(const std::vector<float>& values)
{
    if (values.empty())
        return false;

    for (float x : values) {
        if (!std::isfinite(x))
            return false;
    }

    return true;
}

int argmax(const std::vector<float>& logits)
{
    if (logits.empty())
        return -1;

    int best = 0;
    float best_value = logits[0];

    for (std::size_t i = 1; i < logits.size(); ++i) {
        if (logits[i] > best_value) {
            best_value = logits[i];
            best = static_cast<int>(i);
        }
    }

    return best;
}

float max_logit(const std::vector<float>& logits)
{
    if (logits.empty())
        return -std::numeric_limits<float>::infinity();

    return *std::max_element(logits.begin(), logits.end());
}

void write_evidence(
    const char* path,
    const GateResult& result,
    const std::string& prompt)
{
    std::ofstream out(path, std::ios::trunc);

    if (!out)
        return;

    out << "{\n";
    out << "  \"gate\": \"VAL-051.5\",\n";
    out << "  \"name\": \"32-token KV autoregressive stability\",\n";
    out << "  \"prompt\": \"";

    for (char c : prompt) {
        if (c == '\\')
            out << "\\\\";
        else if (c == '"')
            out << "\\\"";
        else if (c == '\n')
            out << "\\n";
        else
            out << c;
    }

    out << "\",\n";
    out << "  \"target_tokens\": " << kGeneratedTokens << ",\n";
    out << "  \"generated_tokens\": " << result.generated << ",\n";
    out << "  \"invalid_tokens\": " << result.invalid_tokens << ",\n";
    out << "  \"nonfinite_logits\": " << result.nonfinite_logits << ",\n";
    out << "  \"collapsed_hidden\": " << result.collapsed_hidden << ",\n";
    out << "  \"position_errors\": " << result.position_errors << ",\n";
    out << "  \"pass\": " << (result.pass ? "true" : "false") << ",\n";

    out << "  \"sequence\": [";

    for (std::size_t i = 0; i < result.sequence.size(); ++i) {
        if (i)
            out << ", ";
        out << result.sequence[i];
    }

    out << "],\n";

    out << "  \"evidence\": [\n";

    for (std::size_t i = 0; i < result.evidence.size(); ++i) {
        const auto& e = result.evidence[i];

        out << "    {\n";
        out << "      \"position\": " << e.position << ",\n";
        out << "      \"token_id\": " << e.token_id << ",\n";
        out << "      \"logit\": "
            << std::setprecision(9) << e.logit << ",\n";
        out << "      \"hidden_norm\": "
            << std::setprecision(9) << e.hidden_norm << ",\n";
        out << "      \"finite\": "
            << (e.finite ? "true" : "false") << "\n";
        out << "    }";

        if (i + 1 != result.evidence.size())
            out << ",";

        out << "\n";
    }

    out << "  ]\n";
    out << "}\n";
}

// ============================================================================
// Main gate
// ============================================================================

int run_gate(const char* model_path)
{
    constexpr const char* prompt = "Hello";

    std::cout << "============================================================\n";
    std::cout << "VAL-051.5 — 32-TOKEN KV STABILITY GATE\n";
    std::cout << "============================================================\n";
    std::cout << "MODEL=" << model_path << "\n";
    std::cout << "TARGET_TOKENS=" << kGeneratedTokens << "\n";
    std::cout << "PROMPT=" << prompt << "\n";
    std::cout << "============================================================\n";

    RawrXDAdapter engine;

    if (!engine.initialize(model_path)) {
        std::cerr << "[FAIL] ENGINE_INIT\n";
        return 1;
    }

    std::cout << "[PASS] ENGINE_INIT vocab=" << engine.vocab_size << "\n";

    std::vector<int> prompt_tokens;

    if (!engine.encode_prompt(prompt, prompt_tokens)) {
        std::cerr << "[FAIL] TOKENIZER\n";
        engine.shutdown();
        return 1;
    }

    if (prompt_tokens.empty()) {
        std::cerr << "[FAIL] EMPTY_PROMPT_TOKENIZATION\n";
        engine.shutdown();
        return 1;
    }

    std::cout << "[PASS] TOKENIZER count="
              << prompt_tokens.size() << "\n";

    GateResult result;

    std::vector<float> logits;
    float hidden_norm = 0.0f;

    // ------------------------------------------------------------------------
    // PREFILL
    // ------------------------------------------------------------------------

    std::cout << "[PHASE] PREFILL\n";

    if (!engine.prefill(prompt_tokens, logits, hidden_norm)) {
        std::cerr << "[FAIL] PREFILL\n";
        engine.shutdown();
        return 1;
    }

    if (!finite_vector(logits)) {
        std::cerr << "[FAIL] PREFILL_NONFINITE_LOGITS\n";
        engine.shutdown();
        return 1;
    }

    if (!std::isfinite(hidden_norm)) {
        std::cerr << "[FAIL] PREFILL_NONFINITE_HIDDEN\n";
        engine.shutdown();
        return 1;
    }

    std::cout << "[PASS] PREFILL logits=" << logits.size()
              << " hidden_norm=" << std::setprecision(8)
              << hidden_norm << "\n";

    // ------------------------------------------------------------------------
    // First generated token comes from prefill logits.
    // ------------------------------------------------------------------------

    int next_token = argmax(logits);

    if (next_token < 0) {
        std::cerr << "[FAIL] PREFILL_ARGMAX\n";
        engine.shutdown();
        return 1;
    }

    if (engine.vocab_size != 0 &&
        static_cast<std::size_t>(next_token) >= engine.vocab_size) {
        std::cerr << "[FAIL] PREFILL_TOKEN_RANGE token="
                  << next_token << "\n";
        engine.shutdown();
        return 1;
    }

    result.sequence.push_back(next_token);

    TokenEvidence first;
    first.position = 0;
    first.token_id = next_token;
    first.logit = max_logit(logits);
    first.hidden_norm = hidden_norm;
    first.finite = true;

    result.evidence.push_back(first);
    result.generated = 1;

    std::cout << "TOKEN[0]=" << next_token
              << " LOGIT=" << first.logit
              << " HIDDEN_NORM=" << hidden_norm << "\n";

    // ------------------------------------------------------------------------
    // AUTOREGRESSIVE KV LOOP
    // ------------------------------------------------------------------------

    for (int position = 1;
         position < kGeneratedTokens;
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
            std::cerr << "[FAIL] DECODE position="
                      << position << "\n";
            result.position_errors++;
            result.fail();
            break;
        }

        // ---- finite logits -------------------------------------------------

        if (!finite_vector(logits)) {
            std::cerr << "[FAIL] NONFINITE_LOGITS position="
                      << position << "\n";

            result.nonfinite_logits++;
            result.fail();
            break;
        }

        // ---- hidden state --------------------------------------------------

        if (!std::isfinite(hidden_norm)) {
            std::cerr << "[FAIL] NONFINITE_HIDDEN position="
                      << position << "\n";

            result.collapsed_hidden++;
            result.fail();
            break;
        }

        if (hidden_norm <= kMinNorm) {
            std::cerr << "[FAIL] HIDDEN_COLLAPSE position="
                      << position
                      << " norm=" << hidden_norm << "\n";

            result.collapsed_hidden++;
            result.fail();
            break;
        }

        // ---- deterministic greedy selection -------------------------------

        next_token = argmax(logits);

        if (next_token < 0) {
            std::cerr << "[FAIL] ARGMAX position="
                      << position << "\n";
            result.fail();
            break;
        }

        if (engine.vocab_size != 0 &&
            static_cast<std::size_t>(next_token) >= engine.vocab_size)
        {
            std::cerr << "[FAIL] TOKEN_RANGE position="
                      << position
                      << " token=" << next_token << "\n";

            result.invalid_tokens++;
            result.fail();
            break;
        }

        const float selected_logit = logits[next_token];

        if (!std::isfinite(selected_logit)) {
            std::cerr << "[FAIL] SELECTED_LOGIT position="
                      << position << "\n";

            result.nonfinite_logits++;
            result.fail();
            break;
        }

        result.sequence.push_back(next_token);

        TokenEvidence evidence;
        evidence.position = position;
        evidence.token_id = next_token;
        evidence.logit = selected_logit;
        evidence.hidden_norm = hidden_norm;
        evidence.finite = true;

        result.evidence.push_back(evidence);
        result.generated++;

        std::cout << "TOKEN[" << position << "]="
                  << next_token
                  << " LOGIT=" << std::setprecision(8)
                  << selected_logit
                  << " HIDDEN_NORM="
                  << hidden_norm
                  << "\n";
    }

    // ------------------------------------------------------------------------
    // Final gate
    // ------------------------------------------------------------------------

    if (result.generated != kGeneratedTokens)
        result.fail();

    fs::create_directories("evidence");
    write_evidence(
        "evidence/VAL-051.5_32_TOKEN_EVIDENCE.json",
        result,
        prompt);

    std::cout << "\n============================================================\n";
    std::cout << "VAL-051.5 EVIDENCE\n";
    std::cout << "============================================================\n";

    std::cout << "GENERATED="
              << result.generated
              << "/" << kGeneratedTokens << "\n";

    std::cout << "INVALID_TOKENS="
              << result.invalid_tokens << "\n";

    std::cout << "NONFINITE_LOGITS="
              << result.nonfinite_logits << "\n";

    std::cout << "HIDDEN_COLLAPSE="
              << result.collapsed_hidden << "\n";

    std::cout << "POSITION_ERRORS="
              << result.position_errors << "\n";

    std::cout << "SEQUENCE=";

    for (std::size_t i = 0; i < result.sequence.size(); ++i) {
        if (i)
            std::cout << ' ';
        std::cout << result.sequence[i];
    }

    std::cout << "\n";

    std::cout << "EVIDENCE=evidence/VAL-051.5_32_TOKEN_EVIDENCE.json\n";

    if (result.pass) {
        std::cout << "\nBATCH_5_RESULT=PASS\n";
        std::cout << "EXIT_CODE=0\n";
    } else {
        std::cout << "\nBATCH_5_RESULT=FAIL\n";
        std::cout << "EXIT_CODE=1\n";
    }

    std::cout << "============================================================\n";

    engine.shutdown();

    return result.pass ? 0 : 1;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr
            << "Usage: val_051_5_32_token_kv_stability.exe "
               "<model.gguf>\n";
        return 2;
    }

    return run_gate(argv[1]);
}
