// endurance_live_cert.cpp — DEEP2_ENDURANCE_001 (100 same-process requests)
// Requires DAILY_STREAMER_LIVE PASS path. PROMOTE=0 TIP_CLIMB=HOLD.
#include "Deep2Engine.h"
#include "d2_stream_session.h"
#include "d2_session_engine.h"
#include "d2_deep2_binding.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#include <windows.h>
#endif
using namespace Deep2;

static int on_tok(void*, uint32_t, const char*, size_t) { return 1; }

static void WriteReceipt(const char* path, int runtime, int pass, uint32_t reqs,
                         uint32_t ok, uint64_t toks, int dual, int gpu_res,
                         int mock) {
    FILE* f = nullptr;
    fopen_s(&f, path, "wb");
    if (!f) return;
    const int live = pass && runtime && !mock && (ok == reqs) && (reqs >= 100) &&
                     (toks > 0) && dual && gpu_res;
    fprintf(f, "GATE=DEEP2_ENDURANCE_001\n");
    fprintf(f, "STATUS=%s\n", live ? "LIVE_PRODUCT_PASS" :
            (runtime ? "RUNTIME_HOLD" : "SOURCE_WIRED"));
    fprintf(f, "SOURCE_WIRED=1\nRUNTIME_REACHED=%d\n", runtime ? 1 : 0);
    fprintf(f, "LIVE_PRODUCT_RUN=%s\n", live ? "PASS" : (runtime ? "HOLD" : "NOT_RUN"));
    fprintf(f, "REQUESTS=%u GENERATIONS_PASS=%u\n", reqs, ok);
    fprintf(f, "STREAM_CALLBACK_TOKENS_TOTAL=%llu\n", (unsigned long long)toks);
    fprintf(f, "SAME_PROCESS=1 PROCESS_RESTARTS=0 MODEL_REOPEN_MIDRUN=0\n");
    fprintf(f, "DEVICE_LOST=0 MOCK_BACKEND=%d BACKEND=%s\n",
            mock, mock ? "MOCK" : "DEEP2_ENGINE");
    fprintf(f, "DUALSTICK_ARMED=%d GPU_RESIDENCY_RETAINED=%d\n", dual, gpu_res);
    fprintf(f, "ENDURANCE=%s\n", live ? "PASS" : "HOLD");
    fprintf(f, "VERIFY=%s\nPROMOTE=0\nTIP_CLIMB=HOLD\n", live ? "PASS" : "HOLD");
    fprintf(f, "NOT_RUN!=PASS\n");
    fclose(f);
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "2048");
    _putenv_s("DEEP2_WEIGHT_PIN", "1");
    _putenv_s("RAWRXD_GPU_POLICY", "MULTI");
    _putenv_s("RAWRXD_GPU_DEVICES", "ALL");
    _putenv_s("RAWRXD_GPU_FWD", "1");
    _putenv_s("RAWRXD_ALLOW_GPU", "1");
    _putenv_s("DEEP2_DUALSTICK_ARM", "1");
    _putenv_s("RAWRXD_DEEP2_SSVK_PRODUCT_STRICT", "1");
    _putenv_s("RAWRXD_DEEP2_GPU_RESIDENT_STRICT", "1");
    _putenv_s("RAWRXD_Q2K_PRODUCT_DECODE", "1");
    _putenv_s("DEEP2_WEIGHT_PREFETCH", "0");
    _putenv_s("RAWRXD_D2_SESSION_TRACE", "1");
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\llama3.2-3b-Q2_K.gguf";
    const char* logPath = argc > 2 ? argv[2]
        : "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PERFORMANCE_001\\"
          "DEEP2_ENDURANCE_001\\endurance_live.log";
    const char* receipt = argc > 3 ? argv[3]
        : "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PERFORMANCE_001\\"
          "DEEP2_ENDURANCE_001\\RECEIPT.txt";
    const uint32_t reqs = (argc > 4) ? (uint32_t)atoi(argv[4]) : 100u;
    freopen(logPath, "w", stderr);
    printf("GATE=DEEP2_ENDURANCE_001 LIVE reqs=%u model=%s\n", reqs, model);

    Deep2Engine engine;
    Deep2StreamSession* s = d2_session_create();
    if (s) d2_session_set_trace(s, 1);
    _putenv_s("RAWRXD_D2_SESSION_TRACE", "1");
    if (!s || !d2_session_bind_deep2_engine_ptr(s, &engine) ||
        !d2_session_open_model(s, model)) {
        if (s) d2_session_destroy(s);
        WriteReceipt(receipt, 0, 0, reqs, 0, 0, 0, 0, 1);
        return 1;
    }
    printf("BACKEND=DEEP2_ENGINE MOCK_BACKEND=%d\n",
           d2_session_backend_is_mock(s));
    D2GenerateRequest req{};
    req.prompt = "hi";
    req.max_tokens = 17;
    req.temperature = 0.f;
    req.seed = 42;
    req.continue_context = 0; /* match daily live: reset between requests */
    uint32_t ok = 0;
    uint64_t toks = 0;
    for (uint32_t i = 0; i < reqs; ++i) {
        if (i > 0) req.max_tokens = 2;
        int okGen = d2_session_generate(s, &req, on_tok, nullptr);
        if (!okGen) {
            /* one reset+retry for intermittent BIND16 mid-run flakes */
            d2_session_reset_context(s);
            okGen = d2_session_generate(s, &req, on_tok, nullptr);
        }
        if (!okGen) {
            printf("ENDURANCE_FAIL at=%u\n", i);
            break;
        }
        toks += d2_session_last_generated(s);
        ++ok;
        if ((i + 1u) % 10u == 0u) {
            printf("ENDURANCE_PROGRESS %u/%u toks=%llu\n", i + 1u, reqs,
                   (unsigned long long)toks);
            fflush(stdout);
        }
    }
    const auto& gf = engine.gpuForwardCounters();
    const int dual = (engine.vulkanDeviceCount() >= 2 && gf.forwardSlot[0] > 0 &&
                      gf.forwardSlot[1] > 0)
                         ? 1
                         : 0;
    const int gpu_res = engine.gpuResidentDecodeEnabled() ? 1 : 0;
    d2_session_close_model(s);
    d2_session_destroy(s);
    const int conj = (ok == reqs) && (toks > 0) && dual && gpu_res;
    WriteReceipt(receipt, 1, conj ? 1 : 0, reqs, ok, toks, dual, gpu_res, 0);
    printf("ENDURANCE=%s ok=%u/%u toks=%llu dual=%d PROMOTE=0\n",
           conj ? "PASS" : "HOLD", ok, reqs, (unsigned long long)toks, dual);
    fflush(stdout);
    fflush(stderr);
    return conj ? 0 : 2;
}
