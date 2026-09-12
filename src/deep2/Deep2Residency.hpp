#pragma once
/* DEEP2_RESIDENCY_001 — model/device/weight residency across decode. PROMOTE=0. */
#include <cstdint>
#include <cstdio>

namespace Deep2 {

struct ResidencySnapshot {
    uint64_t device_creates = 0;
    uint64_t model_loads = 0;
    uint64_t weight_uploads = 0;
    uint64_t weight_hits = 0;
    uint64_t content_hits = 0;
    uint64_t reload_bytes = 0;
    uint64_t pin_evicts = 0;
    uint64_t pin_rejects = 0;
    uint64_t resident_bytes = 0;
};

inline void ResidencyEmitToken(
    FILE* f, uint64_t token, uint64_t kv_len, unsigned devices,
    int model_loaded, int gpu_resident, const ResidencySnapshot& s) noexcept
{
    if (!f) return;
    std::fprintf(f,
        "RESIDENCY_TOKEN t=%llu kv=%llu devices=%u model=%d gpu_res=%d "
        "dev_create=%llu model_load=%llu weight_up=%llu weight_hit=%llu "
        "content_hit=%llu reload_B=%llu pin_evict=%llu pin_rej=%llu "
        "res_B=%llu\n",
        (unsigned long long)token, (unsigned long long)kv_len, devices,
        model_loaded, gpu_resident,
        (unsigned long long)s.device_creates,
        (unsigned long long)s.model_loads,
        (unsigned long long)s.weight_uploads,
        (unsigned long long)s.weight_hits,
        (unsigned long long)s.content_hits,
        (unsigned long long)s.reload_bytes,
        (unsigned long long)s.pin_evicts,
        (unsigned long long)s.pin_rejects,
        (unsigned long long)s.resident_bytes);
}

inline void ResidencyWriteReceipt(
    const char* path, int runtime, int pass, uint64_t n,
    const ResidencySnapshot& a, const ResidencySnapshot& b,
    int bind_auth, unsigned bind_pass, int gpu_res, int dual) noexcept
{
    FILE* f = nullptr;
    fopen_s(&f, path, "wb");
    if (!f) return;
    const int no_dev = (b.device_creates == a.device_creates) ? 1 : 0;
    const int no_model = (b.model_loads == a.model_loads) ? 1 : 0;
    const int no_wup = (b.weight_uploads == a.weight_uploads) ? 1 : 0;
    const int no_reload = (b.reload_bytes == a.reload_bytes) ? 1 : 0;
    const int no_evict = (b.pin_evicts == a.pin_evicts) ? 1 : 0;
    const int model_res = (no_model && n >= 17) ? 1 : 0;
    const int gpu_ret =
        (gpu_res && no_wup && no_reload && no_evict) ? 1 : 0;
    const int ssvk = (bind_auth && bind_pass >= 16) ? 1 : 0;
    const int conj = pass && no_dev && no_model && no_wup && no_reload &&
                     no_evict && model_res && gpu_ret && ssvk && dual &&
                     (n >= 17) && (b.resident_bytes > 0);
    std::fprintf(f, "GATE=DEEP2_RESIDENCY_001\n");
    std::fprintf(f, "STATUS=%s\n", conj ? "LIVE_PRODUCT_PASS" :
                 (runtime ? "RUNTIME_HOLD" : "SOURCE_WIRED"));
    std::fprintf(f, "SOURCE_WIRED=1\nRUNTIME_REACHED=%d\n", runtime ? 1 : 0);
    std::fprintf(f, "LIVE_PRODUCT_RUN=%s\n",
                 conj ? "PASS" : (runtime ? "HOLD" : "NOT_RUN"));
    std::fprintf(f, "NO_PER_TOKEN_MODEL_RELOAD=%d\n", no_model);
    std::fprintf(f, "NO_PER_TOKEN_WEIGHT_REUPLOAD=%d\n",
                 (no_wup && no_reload) ? 1 : 0);
    std::fprintf(f, "NO_PER_TOKEN_DEVICE_RECREATE=%d\n", no_dev);
    std::fprintf(f, "GPU_RESIDENCY_RETAINED_ACROSS_DECODE=%d\n", gpu_ret);
    std::fprintf(f, "MODEL_RESIDENT_ACROSS_DECODE=%d\n", model_res);
    std::fprintf(f, "RESIDENCY=%s\n", conj ? "PASS" : "HOLD");
    std::fprintf(f, "TOKENS=%llu BIND16=%d pass=%u DUAL=%d\n",
                 (unsigned long long)n, bind_auth, bind_pass, dual);
    std::fprintf(f, "DEVICE_CREATE_DELTA=%llu MODEL_LOAD_DELTA=%llu\n",
                 (unsigned long long)(b.device_creates - a.device_creates),
                 (unsigned long long)(b.model_loads - a.model_loads));
    std::fprintf(f, "WEIGHT_UPLOAD_DELTA=%llu RELOAD_B_DELTA=%llu\n",
                 (unsigned long long)(b.weight_uploads - a.weight_uploads),
                 (unsigned long long)(b.reload_bytes - a.reload_bytes));
    std::fprintf(f, "PIN_EVICT_DELTA=%llu RES_B=%llu\n",
                 (unsigned long long)(b.pin_evicts - a.pin_evicts),
                 (unsigned long long)b.resident_bytes);
    std::fprintf(f, "VERIFY=%s\nPROMOTE=0\nTIP_CLIMB=HOLD\n",
                 conj ? "PASS" : "HOLD");
    std::fprintf(f, "NEXT=%s\nNOT_RUN!=PASS\n",
                 conj ? "DEEP2_ROOFLINE_LOCALITY_001" : "RESIDENCY");
    std::fclose(f);
}

} // namespace Deep2
