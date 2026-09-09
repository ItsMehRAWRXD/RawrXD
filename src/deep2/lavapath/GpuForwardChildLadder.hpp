#pragma once
/* GPU_FORWARD_CHILD_ONE_IGNORE — diagnostic only. Env: DEEP2_GPU_ISO_RUN=G0..G8
 * Host A-ladder unchanged. PROMOTE=0. One ignore per run. ≤99 lines. */
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace rawr::gpu_iso {

enum class Run : int {
    G0 = 0, G1, G2, G3, G4, G5, G6, G7, G8, N
};

inline const char* RunName(Run r) noexcept {
    static const char* n[] = {"G0","G1","G2","G3","G4","G5","G6","G7","G8"};
    int i = (int)r;
    return (i >= 0 && i < (int)Run::N) ? n[i] : "G0";
}

inline const char* IgnoredOwner(Run r) noexcept {
    switch (r) {
    case Run::G0: return "NONE";
    case Run::G1: return "GPU_QKV";
    case Run::G2: return "GPU_DEVICE_ATTN";
    case Run::G3: return "GPU_FFN";
    case Run::G4: return "GPU_GEMV";
    case Run::G5: return "GPU_OUTPUT_PROJ";
    case Run::G6: return "GPU_KV_UPDATE";
    case Run::G7: return "GPU_SYNC_WAIT";
    case Run::G8: return "GPU_READBACK";
    default: return "NONE";
    }
}

inline Run ParseRun() noexcept {
    const char* e = std::getenv("DEEP2_GPU_ISO_RUN");
    if (!e || !e[0]) return Run::G0;
    if (e[0] == 'G' || e[0] == 'g') {
        int n = std::atoi(e + 1);
        if (n >= 0 && n < (int)Run::N) return (Run)n;
    }
    return Run::G0;
}

inline Run& Cur() noexcept {
    static Run r = Run::G0;
    return r;
}

inline void Begin() noexcept { Cur() = ParseRun(); }

inline bool Ignore(Run r) noexcept { return Cur() == r; }

inline void Emit(FILE* f = stderr) noexcept {
    if (!f) return;
    std::fprintf(f,
        "GPU_FORWARD_CHILD_ONE_IGNORE\n"
        "GPU_ISO_RUN=%s\n"
        "IGNORED_GPU_OWNER=%s\n"
        "DIAGNOSTIC_ONLY=1\n"
        "PROMOTE=0\n"
        "GPU_FORWARD_CHILD_ONE_IGNORE_END=1\n",
        RunName(Cur()), IgnoredOwner(Cur()));
    std::fflush(f);
}

} // namespace rawr::gpu_iso
