/* EndDeviceStep3Diag — step3 isolation TLS + classify emit. ≤99. */
#pragma once
#include <cstdint>
#include <cstddef>

namespace Deep2 {
namespace ed3 {

struct Ctx {
    uint32_t step = 0, steps = 0, layer = 0;
    unsigned stick = 0;
    uint32_t nExperts = 0;
    int experts[16]{};
    uint64_t pin_clock = 0;
    uint64_t pin_bytes = 0;
    uint64_t in_hash = 0;
    uint64_t pre_hash = 0;
    uint64_t post_hash = 0;
    uintptr_t buf_ptr = 0;
    size_t buf_bytes = 0;
    int fused_ok = 0;
    int d2h_ok = 0;
    int d2h_vk = 0;
    const char* d2h_phase = "none";
    const char* fail_class = "none";
};

void SetStep(uint32_t step, uint32_t steps);
void BeginStick(unsigned stick, uint32_t layer, const float* hidden,
                size_t H);
void NoteExperts(const int* ids, uint32_t n);
void NotePins(uint64_t pinClock, uint64_t pinBytes, uintptr_t buf,
              size_t bufBytes);
void NoteFused(int ok);
void NoteD2h(int ok, int vk, const char* phase, const float* out, size_t H);
void EmitBoundary(const char* tag);
uint64_t HashF32(const float* p, size_t n);

} // namespace ed3
} // namespace Deep2
