// ============================================================================
// decode_step_instrument.cpp
//   CANONICAL_REAL_INFERENCE_CERTIFICATION — decisive instrumentation.
//
// The failure being localised:
//     prompt  : What is the capital of France? Answer in one word.
//     output  : friquefriquefrique...
//     24 identical positions, finish_reason=stop despite max_tokens=24
//
// One run answers which failure class this is, by measuring per step:
//
//   STEP / INPUT_TOKEN_ID / KV_POS_BEFORE / KV_POS_AFTER / LOGITS_PTR /
//   LOGITS_HASH / ARGMAX_TOKEN_ID / ARGMAX_LOGIT / ARGMAX_FINITE /
//   ARGMAX_NAN / ARGMAX_INF / DECODED_PIECE / EOS
//
// Case A  identical LOGITS_HASH every step      -> stale forward / no token feedback / no KV advance
// Case B  LOGITS_HASH changes, argmax constant  -> forward is live; the defect is numerical
// Case C  token ids differ, text identical      -> detokenisation defect
// Case D  KV_POS_AFTER == KV_POS_BEFORE         -> KV position is not advancing
//
// Usage: decode_step_instrument <model.gguf> [steps] [prompt]
// ============================================================================
#include <cstdio>
#include <cmath>
#include <cstring>
#include <string>
#include <vector>
#include <limits>
#include <algorithm>

#include "deep2/Deep2Engine.h"

using Deep2::Deep2Engine;

namespace {

// FNV-1a over the raw float bits: changes if ANY logit changes, and does not
// depend on float formatting.
uint64_t hashFloats(const std::vector<float>& v) {
    uint64_t h = 1469598103934665603ull;
    for (float f : v) {
        uint32_t bits;
        std::memcpy(&bits, &f, 4);
        for (int b = 0; b < 4; ++b) {
            h ^= (bits >> (b * 8)) & 0xFF;
            h *= 1099511628211ull;
        }
    }
    return h;
}

void PrintArgmaxRow(int step, const std::vector<float>& logits) {
    if (logits.empty()) {
        std::printf("STEP=%d LOGITS_EMPTY=1\n", step);
        return;
    }
    int arg = 0;
    float best = -std::numeric_limits<float>::infinity();
    int nan = 0, inf = 0;
    double sum = 0.0;
    for (std::size_t i = 0; i < logits.size(); ++i) {
        const float f = logits[i];
        if (std::isnan(f)) { ++nan; continue; }
        if (std::isinf(f)) { ++inf; continue; }
        sum += f;
        if (f > best) { best = f; arg = static_cast<int>(i); }
    }
    std::printf("STEP=%d LOGITS_PTR=%p LOGITS_SIZE=%zu LOGITS_HASH=%016llX "
                "ARGMAX_TOKEN_ID=%d ARGMAX_LOGIT=%.6f ARGMAX_FINITE=%d "
                "ARGMAX_NAN=%d ARGMAX_INF=%d LOGITS_MEAN=%.6f\n",
                step, static_cast<const void*>(logits.data()), logits.size(),
                static_cast<unsigned long long>(hashFloats(logits)), arg, best,
                (std::isfinite(best) ? 1 : 0), nan, inf,
                sum / static_cast<double>(logits.size()));

    // Top 5, so a dominant-but-not-argmax vocabulary entry is visible.
    std::vector<int> idx(logits.size());
    for (std::size_t i = 0; i < logits.size(); ++i) idx[i] = static_cast<int>(i);
    std::partial_sort(idx.begin(), idx.begin() + std::min<std::size_t>(5, idx.size()), idx.end(),
                      [&](int a, int b) { return logits[a] > logits[b]; });
    std::printf("STEP=%d TOP5=", step);
    for (std::size_t k = 0; k < std::min<std::size_t>(5, idx.size()); ++k) {
        std::printf("%d:%.4f,", idx[k], logits[idx[k]]);
    }
    std::printf("\n");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
                     "usage: decode_step_instrument <model.gguf> [steps] [prompt]\n");
        return 2;
    }
    const std::string modelPath = argv[1];
    const int steps = (argc > 2) ? std::atoi(argv[2]) : 4;
    const std::string prompt =
        (argc > 3) ? argv[3] : "What is the capital of France? Answer in one word.";

    Deep2Engine engine;
    // CPU only for this localisation: a GPU-only defect would not reproduce
    // here, which is itself informative, and CPU removes a variable.
    engine.enableVulkan(false);

    Deep2::EngineConfig cfg;
    if (!engine.initialize(cfg)) {
        std::printf("INIT_OK=0\n");
        return 3;
    }
    Deep2::ModelLoadDiag diag;
    if (!engine.loadModel(modelPath, &diag)) {
        std::printf("LOAD_OK=0 STAGE=%s MSG=%s\n",
                    diag.stageName.c_str(), diag.message.c_str());
        return 4;
    }
    std::printf("LOAD_OK=1\n");

    const std::vector<int> promptIds = engine.tokenize(prompt);
    std::printf("PROMPT_ID_COUNT=%zu\n", promptIds.size());
    std::printf("PROMPT_IDS=");
    for (int t : promptIds) std::printf("%d,", t);
    std::printf("\n");
    std::printf("PROMPT_TEXT=%s\n", prompt.c_str());
    std::printf("STEPS_REQUESTED=%d\n", steps);
    std::fflush(stdout);

    Deep2Engine::DecodeCursor cursor;
    if (!engine.initializeDecodeCursor(cursor)) {
        std::printf("CURSOR_INIT_OK=0\n");
        return 5;
    }
    std::printf("CURSOR_INIT_OK=1 pendingToken=%d\n", cursor.pendingToken);

    // Seed the prompt PROPERLY. Setting cursor.pendingToken in a loop only
    // leaves the LAST token pending and runs no forward at all -- KV position
    // stayed 0, which is why the first run of this instrument produced nonsense.
    // Each prompt token is really decoded so the cache position advances.
    for (std::size_t i = 0; i < promptIds.size(); ++i) {
        cursor.pendingToken = promptIds[i];
        const Deep2Engine::DecodeOneResult pr = engine.decodeContinuousOne(cursor);
        if (pr.kind == Deep2Engine::DecodeOneResult::Kind::Error) {
            std::printf("PREFILL_ERROR at token %zu: %s\n", i, pr.error.c_str());
            return 6;
        }
    }
    std::printf("PREFILL_TOKENS_FED=%zu KV_POS_AFTER_PREFILL=%zu\n",
                promptIds.size(), engine.kvCacheLength());
    std::printf("KV_POS_EXPECTED_AFTER_PREFILL=%zu PREFILL_CORRECT=%d\n",
                promptIds.size(),
                engine.kvCacheLength() == promptIds.size() ? 1 : 0);
    std::fflush(stdout);

    std::vector<uint64_t> hashes;
    std::vector<int> argmaxes;
    std::string accented;
    int eosAt = -1;

    for (int step = 0; step < steps; ++step) {
        const int inputToken = cursor.pendingToken;
        const std::size_t posBefore = engine.kvCacheLength();
        const std::vector<float> logitsBefore = cursor.logits;

        PrintArgmaxRow(step, logitsBefore);

        const Deep2Engine::DecodeOneResult r = engine.decodeContinuousOne(cursor);
        const std::size_t posAfter = engine.kvCacheLength();

        const std::string piece =
            (r.kind == Deep2Engine::DecodeOneResult::Kind::Eos)
                ? std::string()
                : engine.detokenize({r.token});

        std::printf("STEP=%d INPUT_TOKEN_ID=%d KV_POS_BEFORE=%zu KV_POS_AFTER=%zu "
                    "RESULT_KIND=%d TOKEN_ID=%d EOS=%d DECODED_PIECE=%s ERROR=%s\n",
                    step, inputToken, posBefore, posAfter,
                    static_cast<int>(r.kind), r.token,
                    (r.kind == Deep2Engine::DecodeOneResult::Kind::Eos) ? 1 : 0,
                    piece.c_str(), r.error.c_str());
        std::fflush(stdout);

        hashes.push_back(hashFloats(r.kind == Deep2Engine::DecodeOneResult::Kind::Error
                                        ? logitsBefore
                                        : cursor.logits));
        if (!logitsBefore.empty()) {
            int arg = 0;
            for (std::size_t i = 1; i < logitsBefore.size(); ++i) {
                if (logitsBefore[i] > logitsBefore[arg]) arg = static_cast<int>(i);
            }
            argmaxes.push_back(arg);
        }

        if (r.kind == Deep2Engine::DecodeOneResult::Kind::Eos) {
            eosAt = step;
            break;
        }
        if (r.kind == Deep2Engine::DecodeOneResult::Kind::Error) {
            std::printf("ABORT_AT_STEP=%d\n", step);
            break;
        }
        accented += piece;
    }

    std::printf("\nACCENTED_TEXT=%s\n", accented.c_str());

    // Classification, derived from the measurements above.
    bool allHashesEqual = !hashes.empty();
    for (std::size_t i = 1; i < hashes.size(); ++i) {
        if (hashes[i] != hashes[0]) { allHashesEqual = false; break; }
    }
    bool allArgmaxEqual = !argmaxes.empty();
    for (std::size_t i = 1; i < argmaxes.size(); ++i) {
        if (argmaxes[i] != argmaxes[0]) { allArgmaxEqual = false; break; }
    }
    std::printf("ALL_LOGITS_HASHES_EQUAL=%d\n", allHashesEqual ? 1 : 0);
    std::printf("ALL_ARGMAX_IDS_EQUAL=%d\n", allArgmaxEqual ? 1 : 0);
    if (allHashesEqual && allArgmaxEqual) {
        std::printf("FAILURE_CLASS=STALE_FORWARD_STATE\n");
    } else if (!allHashesEqual && allArgmaxEqual) {
        std::printf("FAILURE_CLASS=FORWARD_LIVE_ARGMAX_CONSTANT_INVESTIGATE_NUMERICS\n");
    } else {
        std::printf("FAILURE_CLASS=STATE_ADVANCING_NOISE_INVESTIGATE_SAMPLING\n");
    }
    std::printf("EOS_STEP=%d\n", eosAt);
    return 0;
}