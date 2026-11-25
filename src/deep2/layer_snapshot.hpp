// =============================================================================
// layer_snapshot.hpp — shared opt-in layer capture (P0 diagnostics).
// =============================================================================
// One implementation for every forward path (inline B3, forwardTokenAllLayers,
// forwardGpuContiguousRange, CPU-native). Opt-in via RAWRXD_SNAPSHOT_LAYERS=1,
// decode-only, synchronized (call AFTER the layer's fenced forward; never a
// mid-layer readback in the hot path). Geometry-aware: the file carries a
// header (magic, model, token position, layer count, hidden dim) so stale or
// mismatched captures are detectable.
// =============================================================================
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace rawrxd::deep2::snap {

constexpr char kMagic[8] = {'R','D','X','L','S','N','A','P'};

struct CaptureHeader {
    char     magic[8];
    uint64_t tokenPosition;
    uint32_t layerCount;
    uint32_t hiddenDim;
    uint32_t reserved;
    char     model[64];
};

inline bool Enabled() {
    static const bool on = [] {
        const char* e = std::getenv("RAWRXD_SNAPSHOT_LAYERS");
        return e && e[0] == '1' && e[1] == '\0';
    }();
    return on;
}

// Write one capture file (header + floats). `data` must hold
// layerCount*hiddenDim floats. Returns false on IO failure.
inline bool Write(const std::string& path, const char* model,
                  uint64_t tokenPosition, const float* data,
                  uint32_t layerCount, uint32_t hiddenDim) {
    CaptureHeader h{};
    std::memcpy(h.magic, kMagic, 8);
    h.tokenPosition = tokenPosition;
    h.layerCount = layerCount;
    h.hiddenDim = hiddenDim;
    h.reserved = 0;
    std::snprintf(h.model, sizeof(h.model), "%s", model ? model : "");
    std::FILE* fp = std::fopen(path.c_str(), "wb");
    if (!fp) return false;
    std::fwrite(&h, sizeof(h), 1, fp);
    std::fwrite(data, sizeof(float), (size_t)layerCount * hiddenDim, fp);
    const bool ok = std::fclose(fp) == 0;
    return ok;
}

}  // namespace rawrxd::deep2::snap