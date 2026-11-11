// Session 03 — independent multi-token decode parity.
//
// H11 proves serial vs batched prefill parity. This test independently checks
// that incremental autoregressive decode produces the same token sequence as
// full-context recomputation through the public prefill API.
//
// Reference:
//   For each step, rebuild the full prefix (prompt + previously selected tokens),
//   run prefillSerial(), take argmax(logits), and append that token.
//
// Actual:
//   Run Deep2Engine::generate() once with persistent KV and greedy sampling.
//
// Also checks serial vs batched prefill logits for the prompt and reports the
// top-1/top-2 logit margin at each reference step so token matches are not
// mistaken for numerical equivalence when the distribution is nearly tied.

#include "Deep2Engine.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <limits>
#include <string>
#include <vector>

using namespace Deep2;

static int g_failures = 0;

static void check(bool condition, const char *message)
{
    if (!condition)
    {
        std::printf("FAIL: %s\n", message);
        ++g_failures;
    }
}

static int argmaxTop2(const std::vector<float> &logits, float &top1, float &top2)
{
    int best = -1;
    top1 = -std::numeric_limits<float>::infinity();
    top2 = -std::numeric_limits<float>::infinity();
    for (size_t i = 0; i < logits.size(); ++i)
    {
        const float v = logits[i];
        if (v > top1)
        {
            top2 = top1;
            top1 = v;
            best = static_cast<int>(i);
        }
        else if (v > top2)
        {
            top2 = v;
        }
    }
    return best;
}

int main(int argc, char **argv)
{
    const char *modelPath = argc > 1
                                ? argv[1]
                                : "F:/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";

    Deep2Engine engine;
    EngineConfig cfg;
    cfg.useKVCache = true;
    cfg.useRoPE = true;
    cfg.useThreadPool = false;
    cfg.numThreads = 1;
    cfg.maxSeqLen = 1024;

    if (!engine.initialize(cfg))
    {
        std::printf("FAIL: engine initialize\n");
        return 20;
    }
    if (!engine.loadModel(modelPath))
    {
        std::printf("FAIL: engine loadModel %s\n", modelPath);
        return 21;
    }

    // Use the authoritative FP32 KV for both prefill legs.
    engine.enableCompressedKV(false);

    const std::string promptText = "The capital of France is";
    std::vector<int> prompt = engine.tokenize(promptText);
    check(!prompt.empty(), "prompt tokenization empty");
    if (prompt.empty())
        return 22;

    const size_t vocab = engine.getModelMetadata().vocabSize;
    const size_t hiddenDim = engine.getModelWeights().hiddenDim;
    check(vocab > 0, "vocab size is zero");
    check(hiddenDim > 0, "hidden size is zero");
    if (vocab == 0 || hiddenDim == 0)
        return 23;

    // ---- Serial vs batched prefill logits ----
    std::vector<float> serialHidden(prompt.size() * hiddenDim, 0.0f);
    std::vector<float> batchedHidden(prompt.size() * hiddenDim, 0.0f);
    std::vector<float> serialLogits(vocab, 0.0f);
    std::vector<float> batchedLogits(vocab, 0.0f);

    engine.resetInferenceState();
    const size_t serialDone = engine.prefillSerial(
        prompt.data(), prompt.size(), serialHidden.data());
    check(serialDone == prompt.size(), "prefillSerial did not process full prompt");
    check(engine.getKVCache() && engine.getKVCache()->currentLength() == prompt.size(),
          "prefillSerial KV length mismatch");
    check(serialDone > 0, "prefillSerial produced no hidden state");
    if (serialDone > 0)
        engine.computeLogits(serialHidden.data() + (serialDone - 1) * hiddenDim,
                             serialLogits.data());

    engine.resetInferenceState();
    const size_t batchedDone = engine.prefillBatched(
        prompt.data(), prompt.size(), batchedHidden.data());
    check(batchedDone == prompt.size(), "prefillBatched did not process full prompt");
    check(batchedDone > 0, "prefillBatched produced no hidden state");
    if (batchedDone > 0)
        engine.computeLogits(batchedHidden.data() + (batchedDone - 1) * hiddenDim,
                             batchedLogits.data());

    double maxAbsDiff = 0.0;
    double maxRelDiff = 0.0;
    size_t nonFinite = 0;
    for (size_t i = 0; i < vocab; ++i)
    {
        const float a = serialLogits[i];
        const float b = batchedLogits[i];
        if (!std::isfinite(a) || !std::isfinite(b))
        {
            ++nonFinite;
            continue;
        }
        const double absDiff = std::fabs(static_cast<double>(a) - static_cast<double>(b));
        const double denom = std::max(1e-6, std::fabs(static_cast<double>(a)));
        const double relDiff = absDiff / denom;
        maxAbsDiff = std::max(maxAbsDiff, absDiff);
        maxRelDiff = std::max(maxRelDiff, relDiff);
    }
    check(nonFinite == 0, "non-finite logits in prefill parity");
    check(maxAbsDiff <= 1e-3, "serial vs batched prefill max abs diff exceeds 1e-3");
    std::printf("S03_PREFILL_PARITY maxAbs=%.9e maxRel=%.9e nonFinite=%zu\n",
                maxAbsDiff, maxRelDiff, nonFinite);

    // ---- Reference: full-context recomputation at every step ----
    const size_t steps = 8;
    std::vector<int> reference;
    std::vector<int> referencePrefix = prompt;
    std::vector<float> margins;
    std::vector<std::vector<float>> referenceLogits;
    reference.reserve(steps);
    margins.reserve(steps);
    referenceLogits.reserve(steps);

    for (size_t step = 0; step < steps; ++step)
    {
        engine.resetInferenceState();
        std::vector<float> hidden(referencePrefix.size() * hiddenDim, 0.0f);
        std::vector<float> logits(vocab, 0.0f);
        const size_t done = engine.prefillSerial(
            referencePrefix.data(), referencePrefix.size(), hidden.data());
        check(done == referencePrefix.size(),
              "reference prefillSerial did not process full prefix");
        if (done != referencePrefix.size())
            return 30;
        engine.computeLogits(hidden.data() + (done - 1) * hiddenDim, logits.data());

        float top1 = 0.0f;
        float top2 = 0.0f;
        const int nextToken = argmaxTop2(logits, top1, top2);
        check(nextToken >= 0, "reference argmax failed");
        if (nextToken < 0)
            return 31;

        reference.push_back(nextToken);
        margins.push_back(top1 - top2);
        referenceLogits.push_back(logits);
        referencePrefix.push_back(nextToken);
        std::printf("S03_REF_STEP step=%zu prefixLen=%zu nextToken=%d margin=%.9e\n",
                    step, referencePrefix.size() - 1, nextToken, top1 - top2);
    }

    // ---- Actual: incremental decode through generate() ----
    GenerationOptions opts;
    opts.maxTokens = steps;
    opts.temperature = 0.0f;
    opts.topK = 1;
    opts.topP = 1.0f;
    opts.seed = 1;
    engine.configureGeneration(opts);

    std::vector<int> out(prompt.size() + steps + 8, 0);
    InferenceStats actualStats{};
    const size_t generated = engine.generate(
        prompt.data(), prompt.size(), out.data(), steps, &actualStats, nullptr);
    std::vector<int> actual(out.begin(), out.begin() + generated);

    check(generated == steps, "generate did not produce the requested token count");
    check(actual.size() == reference.size(), "actual/reference token count mismatch");

    size_t mismatches = 0;
    const size_t compareCount = std::min(actual.size(), reference.size());
    for (size_t i = 0; i < compareCount; ++i)
    {
        if (actual[i] != reference[i])
            ++mismatches;
    }
    check(mismatches == 0, "incremental decode diverged from full-context reference");

    // ---- Logit-level decode parity ----
    // After generate(k) tokens, the last hidden state predicts token k.
    // Compare its logits to the full-context reference at the same prefix.
    double maxDecodeAbs = 0.0;
    double maxDecodeRel = 0.0;
    size_t decodeNonFinite = 0;
    for (size_t k = 1; k <= steps; ++k)
    {
        engine.resetInferenceState();
        std::vector<int> outK(prompt.size() + k + 8, 0);
        InferenceStats statsK{};
        const size_t generatedK = engine.generate(
            prompt.data(), prompt.size(), outK.data(), k, &statsK, nullptr);
        check(generatedK == k, "decode logit run did not generate k tokens");
        if (generatedK != k)
            return 40;

        const float *hidden = engine.getHiddenStates();
        check(hidden != nullptr, "hidden state buffer missing after decode");
        if (!hidden)
            return 41;

        const size_t hiddenIndex = prompt.size() + k - 2;
        std::vector<float> decodeLogits(vocab, 0.0f);
        engine.computeLogits(hidden + hiddenIndex * hiddenDim, decodeLogits.data());

        const std::vector<float> &ref = referenceLogits[k - 1];
        for (size_t i = 0; i < vocab; ++i)
        {
            const float a = decodeLogits[i];
            const float b = ref[i];
            if (!std::isfinite(a) || !std::isfinite(b))
            {
                ++decodeNonFinite;
                continue;
            }
            const double absDiff =
                std::fabs(static_cast<double>(a) - static_cast<double>(b));
            const double denom = std::max(1e-6, std::fabs(static_cast<double>(b)));
            maxDecodeAbs = std::max(maxDecodeAbs, absDiff);
            maxDecodeRel = std::max(maxDecodeRel, absDiff / denom);
        }
    }
    check(decodeNonFinite == 0, "non-finite decode logits");
    check(maxDecodeAbs <= 1e-3, "decode logits diverged from full-context reference");
    std::printf("S03_DECODE_LOGIT_PARITY maxAbs=%.9e maxRel=%.9e nonFinite=%zu steps=%zu\n",
                maxDecodeAbs, maxDecodeRel, decodeNonFinite, steps);

    double minMargin = std::numeric_limits<double>::infinity();
    for (double margin : margins)
        minMargin = std::min(minMargin, static_cast<double>(margin));

    std::printf("S03_ACTUAL generated=%zu\n", generated);
    std::printf("S03_TOKENS_REFERENCE");
    for (int tokenId : reference)
        std::printf(" %d", tokenId);
    std::printf("\nS03_TOKENS_ACTUAL");
    for (int tokenId : actual)
        std::printf(" %d", tokenId);
    std::printf("\n");
    std::printf("S03_TOKEN_MATCHES=%zu/%zu minTop1Margin=%.9e failures=%d\n",
                compareCount - mismatches, compareCount, minMargin, g_failures);
    std::printf("S03_SUMMARY prefill_parity=%s decode_parity=%s decode_logit_parity=%s failures=%d\n",
                (maxAbsDiff <= 1e-3 && nonFinite == 0) ? "PASS" : "FAIL",
                (mismatches == 0 && generated == steps) ? "PASS" : "FAIL",
                (maxDecodeAbs <= 1e-3 && decodeNonFinite == 0) ? "PASS" : "FAIL",
                g_failures);

    return g_failures == 0 ? 0 : 1;
}