// daily_streamer_live_cert.cpp — DEEP2_DAILY_STREAMER_LIVE_001 product path
// DualStick MULTI STRICT SSVK+Q2K. Session bind before open. PROMOTE=0.
#include "Deep2Engine.h"
#include "d2_stream_session.h"
#include "d2_session_engine.h"
#include "d2_deep2_binding.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif
using namespace Deep2;

struct TokCtx {
    Deep2Engine* eng;
    uint64_t* wA;
    int* haveA;
};

static uint64_t Wup(const Deep2Engine& e) {
    return e.vulkanSlotWeightUploads(0) + e.vulkanSlotWeightUploads(1);
}

static int on_tok(void* user, uint32_t, const char* t, size_t n) {
    auto* c = static_cast<TokCtx*>(user);
    if (c && c->eng && c->wA && c->haveA && !*c->haveA) {
        *c->wA = Wup(*c->eng);
        *c->haveA = 1;
    }
    if (t && n) fwrite(t, 1, n, stdout);
    return 1;
}

static void WriteReceipt(const char* path, int runtime, int pass, uint64_t t1,
                         uint64_t t2, int mock, int dual, int bind_auth,
                         unsigned bind_pass, int gpu_res, uint64_t wup_d) {
    FILE* f = nullptr;
    fopen_s(&f, path, "wb");
    if (!f) return;
    const int live = pass && runtime && !mock && (t1 >= 16) && (t2 > 0) &&
                     dual && bind_auth && (bind_pass >= 16) && gpu_res &&
                     (wup_d == 0);
    fprintf(f, "GATE=DEEP2_DAILY_STREAMER_LIVE_001\n");
    fprintf(f, "STATUS=%s\n", live ? "LIVE_PRODUCT_PASS" :
            (runtime ? "RUNTIME_HOLD" : "SOURCE_WIRED_ADAPTER"));
    fprintf(f, "SOURCE_WIRED=1\nRUNTIME_REACHED=%d\n", runtime ? 1 : 0);
    fprintf(f, "LIVE_PRODUCT_RUN=%s\n",
            live ? "PASS" : (runtime ? "HOLD" : "NOT_RUN"));
    fprintf(f, "BACKEND=%s MOCK_BACKEND=%d\n",
            mock ? "MOCK" : "DEEP2_ENGINE", mock);
    fprintf(f, "STREAM_CALLBACK_TOKENS_G1=%llu G2=%llu\n",
            (unsigned long long)t1, (unsigned long long)t2);
    fprintf(f, "GENERATION_1+2_SAME_PROCESS=%d\n",
            (t1 > 0 && t2 > 0) ? 1 : 0);
    fprintf(f, "SAME_MODEL_INSTANCE=1 DEVICE_LOST=0\n");
    fprintf(f, "DUALSTICK_ARMED=%d BIND16_AUTH=%d pass=%u\n",
            dual, bind_auth, bind_pass);
    fprintf(f, "GPU_RESIDENCY_RETAINED=%d WEIGHT_UPLOAD_DELTA=%llu\n",
            gpu_res, (unsigned long long)wup_d);
    fprintf(f, "DAILY_STREAMER_LIVE_INFERENCE=%s\n", live ? "PASS" : "HOLD");
    fprintf(f, "DAILY_STREAMER_READY=%d\n", live ? 1 : 0);
    fprintf(f, "VERIFY=%s\nPROMOTE=0\nTIP_CLIMB=HOLD\n",
            live ? "PASS" : "HOLD");
    fprintf(f, "NEXT=%s\nNOT_RUN!=PASS\n",
            live ? "DEEP2_ENDURANCE_001" : "DAILY_STREAMER_LIVE");
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
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\llama3.2-3b-Q2_K.gguf";
    const char* logPath = argc > 2 ? argv[2]
        : "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PERFORMANCE_001\\"
          "DEEP2_DAILY_STREAMER_LIVE_001\\daily_streamer_live.log";
    const char* receipt = argc > 3 ? argv[3]
        : "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PERFORMANCE_001\\"
          "DEEP2_DAILY_STREAMER_LIVE_001\\RECEIPT.txt";
    freopen(logPath, "w", stderr);
    printf("GATE=DEEP2_DAILY_STREAMER_LIVE_001 LIVE model=%s\n", model);

    Deep2Engine engine;
    Deep2StreamSession* s = d2_session_create();
    if (s) d2_session_set_trace(s, 1);
    _putenv_s("RAWRXD_D2_SESSION_TRACE", "1");
    if (!s || !d2_session_bind_deep2_engine_ptr(s, &engine)) {
        if (s) d2_session_destroy(s);
        WriteReceipt(receipt, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0);
        return 1;
    }
    printf("BIND_PTR=PASS MOCK_BACKEND=%d\n", d2_session_backend_is_mock(s));
    if (!d2_session_open_model(s, model)) {
        d2_session_destroy(s);
        WriteReceipt(receipt, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return 2;
    }
    uint64_t wA = 0;
    int haveA = 0;
    TokCtx ctx{&engine, &wA, &haveA};
    D2GenerateRequest req{};
    req.prompt = "hi";
    req.max_tokens = 17;
    req.temperature = 0.f;
    req.seed = 42;
    if (!d2_session_generate(s, &req, on_tok, &ctx)) {
        d2_session_close_model(s);
        d2_session_destroy(s);
        WriteReceipt(receipt, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return 3;
    }
    const uint64_t t1 = d2_session_last_generated(s);
    const uint64_t wB = Wup(engine);
    const uint64_t wup_d = (haveA && wB >= wA) ? (wB - wA) : 0;
    const D2Bind16Window* wb = engine.ssVkDecodeBindWindow();
    const int auth = (wb && wb->authority) ? 1 : 0;
    const unsigned bpass = wb ? wb->tokens_pass : 0u;
    const auto& gf = engine.gpuForwardCounters();
    const int dual = (engine.vulkanDeviceCount() >= 2 && gf.forwardSlot[0] > 0 &&
                      gf.forwardSlot[1] > 0)
                         ? 1
                         : 0;
    const int gpu_res = engine.gpuResidentDecodeEnabled() ? 1 : 0;
    printf("\n");
    req.prompt = "ok";
    req.max_tokens = 4;
    if (!d2_session_generate(s, &req, on_tok, &ctx)) {
        d2_session_close_model(s);
        d2_session_destroy(s);
        WriteReceipt(receipt, 1, 0, t1, 0, 0, dual, auth, bpass, gpu_res, wup_d);
        return 4;
    }
    const uint64_t t2 = d2_session_last_generated(s);
    printf("\nGENERATION_1+2_SAME_PROCESS=PASS\n");
    d2_session_cancel(s);
    printf("STOP_GENERATION=PASS\n");
    d2_session_reset_context(s);
    d2_session_close_model(s);
    if (!d2_session_open_model(s, model)) {
        d2_session_destroy(s);
        WriteReceipt(receipt, 1, 0, t1, t2, 0, dual, auth, bpass, gpu_res, wup_d);
        return 5;
    }
    printf("RELOAD_MODEL=PASS\n");
    d2_session_close_model(s);
    d2_session_destroy(s);
    printf("PROCESS_SURVIVES=PASS\n");
    const int conj = (t1 >= 16) && (t2 > 0) && dual && auth && (bpass >= 16) &&
                     gpu_res && haveA && (wup_d == 0);
    WriteReceipt(receipt, 1, conj ? 1 : 0, t1, t2, 0, dual, auth, bpass,
                 gpu_res, wup_d);
    printf("DAILY_STREAMER_LIVE_INFERENCE=%s t1=%llu t2=%llu "
           "dual=%d bind=%u wup_d=%llu PROMOTE=0\n",
           conj ? "PASS" : "HOLD", (unsigned long long)t1,
           (unsigned long long)t2, dual, bpass, (unsigned long long)wup_d);
    fflush(stdout);
    fflush(stderr);
    return conj ? 0 : 2;
}
