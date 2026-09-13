/* EndDeviceStep3Diag.cpp — TLS ctx + stderr classify. ≤99. */
#include "EndDeviceStep3Diag.hpp"
#include <cstdio>
#include <cstring>

namespace Deep2 {
namespace ed3 {
namespace {
thread_local Ctx g_ctx{};
uint32_t g_step = 0, g_steps = 0;
}

uint64_t HashF32(const float* p, size_t n) {
    uint64_t h = 14695981039346656037ull;
    if (!p || !n) return h;
    for (size_t i = 0; i < n; ++i) {
        uint32_t u;
        std::memcpy(&u, p + i, 4);
        h ^= (uint64_t)u + (uint64_t)i * 1315423911ull;
        h *= 1099511628211ull;
    }
    return h;
}

void SetStep(uint32_t step, uint32_t steps) {
    g_step = step;
    g_steps = steps;
}

void BeginStick(unsigned stick, uint32_t layer, const float* hidden,
                size_t H) {
    g_ctx = Ctx{};
    g_ctx.step = g_step;
    g_ctx.steps = g_steps;
    g_ctx.stick = stick;
    g_ctx.layer = layer;
    g_ctx.in_hash = HashF32(hidden, H);
}

void NoteExperts(const int* ids, uint32_t n) {
    g_ctx.nExperts = n > 16u ? 16u : n;
    for (uint32_t i = 0; i < g_ctx.nExperts; ++i)
        g_ctx.experts[i] = ids ? ids[i] : -1;
}

void NotePins(uint64_t pinClock, uint64_t pinBytes, uintptr_t buf,
              size_t bufBytes) {
    g_ctx.pin_clock = pinClock;
    g_ctx.pin_bytes = pinBytes;
    g_ctx.buf_ptr = buf;
    g_ctx.buf_bytes = bufBytes;
}

void NoteFused(int ok) { g_ctx.fused_ok = ok; }

void NoteD2h(int ok, int vk, const char* phase, const float* out, size_t H) {
    g_ctx.d2h_ok = ok;
    g_ctx.d2h_vk = vk;
    g_ctx.d2h_phase = phase ? phase : "none";
    g_ctx.pre_hash = g_ctx.in_hash;
    g_ctx.post_hash = ok ? HashF32(out, H) : 0ull;
    if (!ok) {
        if (phase && (std::strcmp(phase, "fence") == 0 ||
                      std::strcmp(phase, "submit") == 0 ||
                      std::strcmp(phase, "device_lost") == 0))
            g_ctx.fail_class = "DEVICE/SYNC_FAILURE";
        else
            g_ctx.fail_class = "ENDDEVICE_ABORT_BEFORE_RESULT";
    } else
        g_ctx.fail_class = "D2H_OK"; /* stream PARITY judges RESULT_PARITY_BAD */
}

void EmitBoundary(const char* tag) {
    std::fprintf(stderr,
                 "ENDDEVICE_STEP3 tag=%s STEP=%u/%u layer=%u stick=%u "
                 "nEx=%u pin_clock=%llu pin_bytes=%llu buf=%p bytes=%zu "
                 "fused=%d d2h=%d vk=%d phase=%s "
                 "in_hash=%016llx post_hash=%016llx CLASS=%s ex=[",
                 tag ? tag : "-", g_ctx.step, g_ctx.steps, g_ctx.layer,
                 g_ctx.stick, g_ctx.nExperts,
                 (unsigned long long)g_ctx.pin_clock,
                 (unsigned long long)g_ctx.pin_bytes,
                 (void*)g_ctx.buf_ptr, g_ctx.buf_bytes, g_ctx.fused_ok,
                 g_ctx.d2h_ok, g_ctx.d2h_vk, g_ctx.d2h_phase,
                 (unsigned long long)g_ctx.in_hash,
                 (unsigned long long)g_ctx.post_hash, g_ctx.fail_class);
    for (uint32_t i = 0; i < g_ctx.nExperts; ++i) {
        if (i) std::fputc(',', stderr);
        std::fprintf(stderr, "%d", g_ctx.experts[i]);
    }
    std::fprintf(stderr, "]\n");
    std::fflush(stderr);
}

} // namespace ed3
} // namespace Deep2
