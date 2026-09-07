// K2MLA_QaCritical.cpp — q_a-only wall split under MLA_Gemv
#include "K2MLA_QaCritical.hpp"
#include <cstdlib>

namespace Deep2 {
namespace {
uint64_t g_total = 0, g_fused = 0, g_compat = 0, g_disp = 0, g_kern = 0;
uint64_t g_out = 0, g_calls = 0, g_fHit = 0, g_cHit = 0, g_fb = 0, g_up = 0;
thread_local uint64_t t_setup = 0, t_kern = 0;
} // namespace

QaPathForce MLA_QaPathForce() {
    const char* e = std::getenv("DEEP2_MLA_QA_PATH");
    if (!e || !e[0] || e[0] == 'a' || e[0] == 'A') return QaPathForce::Auto;
    if (e[0] == 'f' || e[0] == 'F') return QaPathForce::Fused;
    if (e[0] == 'c' || e[0] == 'C' || e[0] == 'p' || e[0] == 'P')
        return QaPathForce::Compat;
    return QaPathForce::Auto;
}

bool MLA_QaAllowFused(bool braidPreferFused) {
    switch (MLA_QaPathForce()) {
    case QaPathForce::Fused: return true;
    case QaPathForce::Compat: return false;
    default: return braidPreferFused;
    }
}

bool MLA_QaWantFused() {
    if (MLA_QaPathForce() == QaPathForce::Compat) return false;
    if (MLA_QaPathForce() == QaPathForce::Fused) return true;
    const char* e = std::getenv("DEEP2_MLA_FUSED_Q4KT");
    if (e && e[0] == '0') return false;
    if (e && e[0] == '1') return true;
    const char* g = std::getenv("DEEP2_K2_GPU_MLA");
    return g && g[0] == '1';
}

void MLA_QaCrit_Reset() {
    g_total = g_fused = g_compat = g_disp = g_kern = g_out = 0;
    g_calls = g_fHit = g_cHit = g_fb = g_up = 0;
    t_setup = t_kern = 0;
}

void MLA_QaCrit_Begin() { t_setup = t_kern = 0; }
void MLA_QaCrit_NoteSetup(uint64_t us) { t_setup = us; }

void MLA_QaCrit_NoteFused(uint64_t us, bool ok) {
    t_kern += us;
    g_fused += us;
    if (ok) ++g_fHit;
}

void MLA_QaCrit_NoteCompat(uint64_t us, bool ok) {
    t_kern += us;
    g_compat += us;
    if (ok) ++g_cHit;
}

void MLA_QaCrit_NoteFallback() { ++g_fb; }
void MLA_QaCrit_NoteUpload() { ++g_up; }

void MLA_QaCrit_End(uint64_t totalUs) {
    ++g_calls;
    g_total += totalUs;
    g_disp += t_setup;
    g_kern += t_kern;
    if (totalUs > t_setup + t_kern)
        g_out += totalUs - t_setup - t_kern;
    t_setup = t_kern = 0;
}

uint64_t MLA_QaTotalUs() { return g_total; }
uint64_t MLA_QaFusedUs() { return g_fused; }
uint64_t MLA_QaCompatUs() { return g_compat; }
uint64_t MLA_QaDispatchUs() { return g_disp; }
uint64_t MLA_QaKernelUs() { return g_kern; }
uint64_t MLA_QaOutputUs() { return g_out; }
uint64_t MLA_QaCalls() { return g_calls; }
uint64_t MLA_QaFusedHits() { return g_fHit; }
uint64_t MLA_QaCompatHits() { return g_cHit; }
uint64_t MLA_QaFallbacks() { return g_fb; }
uint64_t MLA_QaUploads() { return g_up; }

void MLA_QaCrit_Emit(FILE* f) {
    if (!f) f = stdout;
    fprintf(f,
            "QA_TOTAL_US=%llu QA_FUSED_Q4KT_US=%llu QA_COMPAT_PACKED_US=%llu\n"
            "QA_DISPATCH_US=%llu QA_KERNEL_US=%llu QA_OUTPUT_US=%llu "
            "QA_CALLS=%llu\n"
            "QA_FUSED_HITS=%llu QA_COMPAT_HITS=%llu QA_FALLBACKS=%llu "
            "QA_UPLOADS=%llu\n",
            (unsigned long long)g_total, (unsigned long long)g_fused,
            (unsigned long long)g_compat, (unsigned long long)g_disp,
            (unsigned long long)g_kern, (unsigned long long)g_out,
            (unsigned long long)g_calls, (unsigned long long)g_fHit,
            (unsigned long long)g_cHit, (unsigned long long)g_fb,
            (unsigned long long)g_up);
    fflush(f);
}

} // namespace Deep2
