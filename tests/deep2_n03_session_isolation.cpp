// N03 — ≥2 isolated Deep2Engine sessions (KV/pos/sample/cancel/outputs).
// Engines are distinct; decode may be mutex-serialized for GPU safety.
#include "Deep2Engine.h"
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

static std::mutex g_decode_mu;

static bool load(Deep2::Deep2Engine& e, const char* gguf) {
    Deep2::EngineConfig cfg{};
    return e.initialize(cfg) && e.loadModel(gguf);
}

static std::vector<int32_t> greedy(Deep2::Deep2Engine& e, const char* prompt,
                                   size_t n, bool cancel_after_first,
                                   bool* cancelled, bool lock_decode) {
    if (lock_decode) g_decode_mu.lock();
    e.clearCancel();
    e.resetInferenceState();
    Deep2::GenerationOptions o;
    o.maxTokens = (uint32_t)n;
    o.temperature = 0.f;
    o.topP = 1.f;
    o.topK = 1;
    e.configureGeneration(o);
    std::vector<int32_t> ids;
    auto gr = e.generateStream(prompt, o, [&](int32_t tid, const std::string&) {
        ids.push_back(tid);
        if (cancel_after_first && ids.size() == 1) e.requestCancel();
        return true;
    });
    if (cancelled)
        *cancelled = gr.cancelled || (cancel_after_first && ids.size() < n);
    if (lock_decode) g_decode_mu.unlock();
    return ids;
}

int main(int argc, char** argv) {
    const char* gguf = (argc > 1) ? argv[1] : "F:\\ollamamodels\\n4-tiny-oracle.gguf";
    Deep2::Deep2Engine a, b;
    if (!load(a, gguf) || !load(b, gguf)) {
        std::printf("LOAD_FAIL=1\n");
        return 2;
    }
    auto* kva = a.getKVCache();
    auto* kvb = b.getKVCache();
    if (!kva || !kvb || kva == kvb) {
        std::printf("KV_PTR_ISOLATION_FAIL=1\n");
        return 3;
    }
    std::printf("KV_PTR_A=%p KV_PTR_B=%p DISTINCT=%d\n", (void*)kva, (void*)kvb, 1);

    // Phase 1: sequential ownership — independent outputs + KV lengths.
    auto ta = greedy(a, "Alpha one", 6, false, nullptr, false);
    const size_t len_a1 = kva->currentLength();
    auto tb = greedy(b, "Beta two!!", 6, false, nullptr, false);
    const size_t len_b1 = kvb->currentLength();
    std::printf("SEQ_TOKENS_A=");
    for (size_t i = 0; i < ta.size(); ++i) std::printf("%s%d", i ? "," : "", (int)ta[i]);
    std::printf("\nSEQ_TOKENS_B=");
    for (size_t i = 0; i < tb.size(); ++i) std::printf("%s%d", i ? "," : "", (int)tb[i]);
    std::printf("\n");
    const int seq_ok = (!ta.empty() && !tb.empty() && ta != tb) ? 1 : 0;
    std::printf("SEQ_OUTPUTS_OK=%d KV_LEN_A=%zu KV_LEN_B=%zu\n", seq_ok, len_a1, len_b1);

    // Phase 2: interleaved threads on isolated engines; decode mutex = GPU-safe.
    std::vector<int32_t> ia, ib;
    std::thread t1([&] { ia = greedy(a, "Alpha interleaved", 6, false, nullptr, true); });
    std::thread t2([&] { ib = greedy(b, "Beta interleaved!", 6, false, nullptr, true); });
    t1.join();
    t2.join();
    const int inter_ok = (!ia.empty() && !ib.empty()) ? 1 : 0;
    std::printf("INTERLEAVE_TOKENS_A=%zu INTERLEAVE_TOKENS_B=%zu INTERLEAVE_OK=%d\n",
                ia.size(), ib.size(), inter_ok);
    std::printf("NOTE=decode_mutex_serializes_GPU_isolated_engines_keep_distinct_KV\n");

    // Phase 3: cancel A mid-stream; B must still complete under mutex.
    bool cancelA = false;
    std::thread c1([&] { ta = greedy(a, "Cancel me now please", 32, true, &cancelA, true); });
    std::thread c2([&] { tb = greedy(b, "Keep going stream B", 8, false, nullptr, true); });
    c1.join();
    c2.join();
    const int cancel_iso = (tb.size() >= 4 && ta.size() < 32) ? 1 : 0;
    std::printf("CANCEL_A=%d TOKENS_A_AFTER_CANCEL=%zu TOKENS_B_ALIVE=%zu CANCEL_ISOLATED=%d\n",
                cancelA ? 1 : 0, ta.size(), tb.size(), cancel_iso);

    const int pass = (seq_ok && inter_ok && cancel_iso) ? 1 : 0;
    std::printf("SESSION_ISOLATION_PASS=%d\nCERTIFIED=0\nPROMOTE=0\nTIP_CLIMB=HOLD\n", pass);
    return pass ? 0 : 7;
}
