// streamer_vram_aperture_smoke.cpp
// Physical proof for StreamRingBufferToVramAperture (host->host stand-in for mapped BAR).
// Not a numbered VAL gate.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <malloc.h>

extern "C" uint64_t StreamRingBufferToVramAperture(const void* src, void* dst, uint64_t bytes);

int main() {
    constexpr uint64_t kBytes = 4096;
    void* src = _aligned_malloc(kBytes, 64);
    void* dst = _aligned_malloc(kBytes, 64);
    if (!src || !dst) {
        std::printf("STREAMER_VRAM_APERTURE=FAIL alloc\n");
        return 1;
    }

    std::memset(src, 0xA5, kBytes);
    std::memset(dst, 0x00, kBytes);

    const uint64_t badNull = StreamRingBufferToVramAperture(nullptr, dst, kBytes);
    const uint64_t badAlign = StreamRingBufferToVramAperture(src, dst, 63);
    const uint64_t ok = StreamRingBufferToVramAperture(src, dst, kBytes);
    const int match = (std::memcmp(src, dst, kBytes) == 0) ? 1 : 0;

    std::printf("STREAMER_VRAM_APERTURE_NULL=%llu\n",
                static_cast<unsigned long long>(badNull));
    std::printf("STREAMER_VRAM_APERTURE_ALIGN=%llu\n",
                static_cast<unsigned long long>(badAlign));
    std::printf("STREAMER_VRAM_APERTURE_OK=%llu\n",
                static_cast<unsigned long long>(ok));
    std::printf("STREAMER_VRAM_APERTURE_MATCH=%d\n", match);

    const int pass = (badNull == 1 && badAlign == 2 && ok == 0 && match == 1);
    std::printf("STREAMER_VRAM_APERTURE=%s\n", pass ? "PASS" : "FAIL");

    _aligned_free(src);
    _aligned_free(dst);
    return pass ? 0 : 1;
}
