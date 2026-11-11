// Session 02 — persistent KV autoregressive decode acceptance.
//
// Exercises the production Deep2Engine::generate() path on a real GGUF model:
//   * KV length advances by exactly one per generated token (no full-context
//     recomputation masquerading as incremental decode).
//   * Prefill ends at promptLen; the first generated token does not advance KV.
//   * Repeated identical requests reset KV and reproduce the same token IDs.
//   * Serial vs batched prefill produce identical token IDs.
//   * A different prompt does not inherit the previous request's tokens.
//   * KVCache capacity is enforced at the API boundary.
//
// Exit code 0 only when every check passes.

#include "Deep2Engine.h"
#include "KVCache.h"

#include <cstdio>
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

int main(int argc, char **argv)
{
    const char *modelPath = argc > 1
                                ? argv[1]
                                : "F:/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";

    // --- KV capacity enforcement (API boundary) ---
    {
        KVCache cache;
        KVCacheConfig cfg{};
        cfg.numLayers = 1;
        cfg.maxSeqLen = 4;
        cfg.numHeads = 1;
        cfg.headDim = 2;
        if (!cache.initialize(cfg))
        {
            std::printf("FAIL: synthetic KV cache initialize\n");
            return 10;
        }
        for (size_t i = 0; i < cfg.maxSeqLen; ++i)
        {
            if (!cache.advanceBy(1))
            {
                std::printf("FAIL: KV advance rejected at %zu\n", i);
                return 11;
            }
        }
        if (cache.advanceBy(1))
        {
            std::printf("FAIL: KV capacity not enforced\n");
            return 12;
        }
        if (cache.currentLength() != cfg.maxSeqLen)
        {
            std::printf("FAIL: KV capacity length mismatch\n");
            return 13;
        }
    }

    EngineConfig cfg;
    cfg.useKVCache = true;
    cfg.useThreadPool = false;
    cfg.maxSeqLen = 512;

    Deep2Engine engine;
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

    KVCache *kv = engine.getKVCache();
    if (!kv)
    {
        std::printf("FAIL: KV cache missing after load\n");
        return 22;
    }

    const std::string promptText = "The capital of France is";
    const std::vector<int> prompt = engine.tokenize(promptText);
    if (prompt.empty())
    {
        std::printf("FAIL: prompt tokenization empty\n");
        return 23;
    }

    GenerationOptions opts;
    opts.maxTokens = 8;
    opts.temperature = 0.0f;
    opts.topK = 1;
    opts.topP = 1.0f;
    opts.seed = 1;
    engine.configureGeneration(opts);
    engine.enableBatchedPrefill(false);

    std::vector<int> out(prompt.size() + 16, 0);
    std::vector<size_t> kvLens;
    std::vector<int> callbackTokens;
    auto callback = [&](int tokenId)
    {
        callbackTokens.push_back(tokenId);
        kvLens.push_back(kv->currentLength());
        return true;
    };

    InferenceStats stats{};
    const size_t generated =
        engine.generate(prompt.data(), prompt.size(), out.data(), opts.maxTokens, &stats, callback);

    check(generated > 0, "generate produced no tokens");
    check(generated == callbackTokens.size(), "callback count differs from generated count");
    check(kvLens.size() == generated, "KV length capture count differs from generated count");

    if (!kvLens.empty())
    {
        check(kvLens[0] == prompt.size(),
              "first generated token must observe KV length == prompt length");
        for (size_t i = 1; i < kvLens.size(); ++i)
        {
            check(kvLens[i] == prompt.size() + i,
                  "KV length must advance by exactly one per generated token");
        }
    }

    check(kv->currentLength() == prompt.size() + generated - 1,
          "final KV length after decode is not promptLen + generated - 1");

    const auto stop = engine.generationStopReason();
    check(stop == Deep2Engine::GenerationStopReason::COMPLETED ||
              stop == Deep2Engine::GenerationStopReason::NONE,
          "generation stop reason is a fault");

    std::vector<int> firstTokens(out.begin(), out.begin() + generated);
    std::printf("S02_TOKENS");
    for (int tokenId : firstTokens)
        std::printf(" %d", tokenId);
    std::printf("\n");
    std::printf("S02_RUN1 generated=%zu promptLen=%zu firstKv=%zu lastKv=%zu finalKv=%zu stop=%d\n",
                generated, prompt.size(), kvLens.empty() ? 0 : kvLens.front(),
                kvLens.empty() ? 0 : kvLens.back(), kv->currentLength(), static_cast<int>(stop));

    // --- Repeated identical request: reset + reproducible tokens ---
    std::vector<int> out2(prompt.size() + 16, 0);
    InferenceStats stats2{};
    const size_t generated2 =
        engine.generate(prompt.data(), prompt.size(), out2.data(), opts.maxTokens, &stats2, nullptr);
    std::vector<int> secondTokens(out2.begin(), out2.begin() + generated2);

    check(generated2 == generated, "second identical run changed token count");
    check(secondTokens == firstTokens, "second identical run changed token IDs");
    check(kv->currentLength() == prompt.size() + generated2 - 1,
          "second run final KV length is wrong");

    // --- Serial vs batched prefill parity ---
    engine.enableBatchedPrefill(true);
    std::vector<int> out3(prompt.size() + 16, 0);
    InferenceStats stats3{};
    const size_t generated3 =
        engine.generate(prompt.data(), prompt.size(), out3.data(), opts.maxTokens, &stats3, nullptr);
    std::vector<int> batchedTokens(out3.begin(), out3.begin() + generated3);

    check(generated3 == generated, "batched prefill changed token count");
    check(batchedTokens == firstTokens, "batched prefill changed token IDs");

    // --- Different prompt must not inherit previous request state ---
    const std::string otherText = "One plus one equals";
    const std::vector<int> otherPrompt = engine.tokenize(otherText);
    std::vector<int> out4(otherPrompt.size() + 16, 0);
    InferenceStats stats4{};
    const size_t generated4 = engine.generate(
        otherPrompt.data(), otherPrompt.size(), out4.data(), opts.maxTokens, &stats4, nullptr);
    std::vector<int> otherTokens(out4.begin(), out4.begin() + generated4);

    check(generated4 > 0, "second prompt generated nothing");
    check(otherTokens != firstTokens, "second prompt reused first prompt tokens");
    check(kv->currentLength() == otherPrompt.size() + generated4 - 1,
          "second prompt final KV length is wrong");

    std::printf("S02_SUMMARY generated=%zu kv_capacity=ENFORCED kv_advance=STRICT "
                "reset=ISOLATED batched_parity=%s prompt_isolation=%s failures=%d\n",
                generated,
                (generated3 == generated && batchedTokens == firstTokens) ? "PASS" : "FAIL",
                (generated4 > 0 && otherTokens != firstTokens) ? "PASS" : "FAIL",
                g_failures);

    return g_failures == 0 ? 0 : 1;
}