// unlinked_symbols_batch_001.cpp
// Quintile A MagShutdown + perf (cathedral / perf_telemetry ABIs).
// asm_spengine_shutdown → src/spengine_bridge.cpp (patch journal rollback).
// asm_omega_shutdown → batch_005 (!RAWR_HAS_MASM) or omega_asm_native_kernel.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "../gguf_loader.h"
#include "mag_registry.hpp"
#include "quad_registry.hpp"

namespace {

constexpr uint32_t kPerfSlots = 64;

struct PerfSlot {
    std::atomic<uint64_t> beginTsc{0};
    std::atomic<uint64_t> lastNs{0};
    std::atomic<uint64_t> totalNs{0};
    std::atomic<uint64_t> samples{0};
};
std::array<PerfSlot, kPerfSlots> g_perf{};

struct LspState {
    std::mutex mtx;
    void* symbolIndex = nullptr;
    void* contextAnalyzer = nullptr;
};
LspState g_lsp;

struct GgufReg {
    std::mutex mtx;
    std::unordered_map<void*, GGUFLoader*> byCtx;
    GGUFLoader* defaultLoader = nullptr;
};
GgufReg g_gguf;

struct QuadState {
    std::mutex mtx;
    HWND hwnd = nullptr;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t flags = 0;
    std::atomic<uint32_t> renderThreadRuns{0};
    std::vector<uint8_t> frameScratch;
};
QuadState g_quad;

struct MagBag {
    std::mutex mtx;
    std::vector<void*> meshNodes;
    std::vector<void*> neuralChannels;
    std::vector<void*> hwsynthLuts;
    std::vector<void*> speciatorGenomes;
    void* watchdogRegion = nullptr;
    uint32_t watchdogBytes = 0;
    uint64_t epoch = 0;
};
MagBag g_mag;

inline uint64_t qpcNow() {
    LARGE_INTEGER qpc{};
    QueryPerformanceCounter(&qpc);
    return static_cast<uint64_t>(qpc.QuadPart);
}

} // namespace

extern "C" {

int quad_registry_bind(HWND hwnd, uint32_t width, uint32_t height, uint32_t flags) {
    std::lock_guard<std::mutex> lock(g_quad.mtx);
    g_quad.hwnd = hwnd;
    g_quad.width = width;
    g_quad.height = height;
    g_quad.flags = flags;
    return 0;
}

void quad_registry_clear(void) {
    std::lock_guard<std::mutex> lock(g_quad.mtx);
    g_quad.hwnd = nullptr;
    g_quad.width = 0;
    g_quad.height = 0;
    g_quad.flags = 0;
    g_quad.renderThreadRuns.store(0, std::memory_order_relaxed);
    g_quad.frameScratch.clear();
    g_quad.frameScratch.shrink_to_fit();
}

uint32_t quad_registry_render_tick(void) {
    return g_quad.renderThreadRuns.fetch_add(1u, std::memory_order_relaxed) + 1u;
}

uint32_t quad_registry_width(void) {
    std::lock_guard<std::mutex> lock(g_quad.mtx);
    return g_quad.width;
}

uint32_t quad_registry_height(void) {
    std::lock_guard<std::mutex> lock(g_quad.mtx);
    return g_quad.height;
}

uint32_t quad_registry_flags(void) {
    std::lock_guard<std::mutex> lock(g_quad.mtx);
    return g_quad.flags;
}

HWND quad_registry_hwnd(void) {
    std::lock_guard<std::mutex> lock(g_quad.mtx);
    return g_quad.hwnd;
}

void asm_quadbuf_shutdown(void) {
    quad_registry_clear();
}

void asm_lsp_bridge_shutdown(void) {
    std::lock_guard<std::mutex> lock(g_lsp.mtx);
    g_lsp.symbolIndex = nullptr;
    g_lsp.contextAnalyzer = nullptr;
}

void asm_gguf_loader_close(void* ctx) {
    std::lock_guard<std::mutex> lock(g_gguf.mtx);
    if (ctx != nullptr) {
        auto it = g_gguf.byCtx.find(ctx);
        if (it != g_gguf.byCtx.end() && it->second != nullptr) {
            it->second->Close();
            g_gguf.byCtx.erase(it);
            return;
        }
        static_cast<GGUFLoader*>(ctx)->Close();
        return;
    }
    if (g_gguf.defaultLoader != nullptr) {
        g_gguf.defaultLoader->Close();
        g_gguf.defaultLoader = nullptr;
    }
    for (auto& kv : g_gguf.byCtx) {
        if (kv.second != nullptr) {
            kv.second->Close();
        }
    }
    g_gguf.byCtx.clear();
}

void asm_magbuf_register_mesh(void* handle) {
    if (handle == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mag.mtx);
    g_mag.meshNodes.push_back(handle);
}

void asm_magbuf_register_neural(void* handle) {
    if (handle == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mag.mtx);
    g_mag.neuralChannels.push_back(handle);
}

void asm_magbuf_register_hwsynth(void* handle) {
    if (handle == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mag.mtx);
    g_mag.hwsynthLuts.push_back(handle);
}

void asm_magbuf_register_speciator(void* handle) {
    if (handle == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mag.mtx);
    g_mag.speciatorGenomes.push_back(handle);
}

void mag_publish_mesh_node(void* handle) {
    asm_magbuf_register_mesh(handle);
}

void mag_publish_neural_channel(void* handle) {
    asm_magbuf_register_neural(handle);
}

void mag_publish_hwsynth_lut(void* handle) {
    asm_magbuf_register_hwsynth(handle);
}

void mag_publish_speciator_genome(void* handle) {
    asm_magbuf_register_speciator(handle);
}

void mag_publish_watchdog_region(void* region, uint32_t bytes) {
    std::lock_guard<std::mutex> lock(g_mag.mtx);
    g_mag.watchdogRegion = region;
    g_mag.watchdogBytes = bytes;
    g_mag.epoch += 1;
}

void mag_watchdog_region_peek(void** outRegion, uint32_t* outBytes) {
    if (outRegion == nullptr || outBytes == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mag.mtx);
    *outRegion = g_mag.watchdogRegion;
    *outBytes = g_mag.watchdogBytes;
}

uint32_t mag_watchdog_crc32_region(void) {
    void* region = nullptr;
    uint32_t bytes = 0;
    mag_watchdog_region_peek(&region, &bytes);
    if (region == nullptr || bytes == 0) {
        return 0;
    }
    uint32_t crc = 0xFFFFFFFFu;
    const auto* data = static_cast<const uint8_t*>(region);
    for (uint32_t i = 0; i < bytes; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) {
            const uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

uint32_t asm_magbuf_count_mesh(void) {
    std::lock_guard<std::mutex> lock(g_mag.mtx);
    return static_cast<uint32_t>(g_mag.meshNodes.size());
}

uint32_t asm_magbuf_count_neural(void) {
    std::lock_guard<std::mutex> lock(g_mag.mtx);
    return static_cast<uint32_t>(g_mag.neuralChannels.size());
}

uint32_t asm_magbuf_count_hwsynth(void) {
    std::lock_guard<std::mutex> lock(g_mag.mtx);
    return static_cast<uint32_t>(g_mag.hwsynthLuts.size());
}

uint32_t asm_magbuf_count_speciator(void) {
    std::lock_guard<std::mutex> lock(g_mag.mtx);
    return static_cast<uint32_t>(g_mag.speciatorGenomes.size());
}

uint64_t asm_magbuf_epoch(void) {
    std::lock_guard<std::mutex> lock(g_mag.mtx);
    return g_mag.epoch;
}

uint64_t mag_registry_epoch(void) {
    return asm_magbuf_epoch();
}

void asm_mesh_shutdown(void) {
    std::lock_guard<std::mutex> lock(g_mag.mtx);
    for (void* p : g_mag.meshNodes) {
        ::operator delete(p);
    }
    g_mag.meshNodes.clear();
    g_mag.epoch += 1;
}

void asm_speciator_shutdown(void) {
    std::lock_guard<std::mutex> lock(g_mag.mtx);
    for (void* p : g_mag.speciatorGenomes) {
        ::operator delete(p);
    }
    g_mag.speciatorGenomes.clear();
    g_mag.epoch += 1;
}

void asm_neural_shutdown(void) {
    std::lock_guard<std::mutex> lock(g_mag.mtx);
    for (void* p : g_mag.neuralChannels) {
        ::operator delete(p);
    }
    g_mag.neuralChannels.clear();
    g_mag.epoch += 1;
}

void asm_hwsynth_shutdown(void) {
    std::lock_guard<std::mutex> lock(g_mag.mtx);
    for (void* p : g_mag.hwsynthLuts) {
        ::operator delete(p);
    }
    g_mag.hwsynthLuts.clear();
    g_mag.epoch += 1;
}

int asm_watchdog_shutdown(void) {
    std::lock_guard<std::mutex> lock(g_mag.mtx);
    if (g_mag.watchdogRegion != nullptr && g_mag.watchdogBytes > 0) {
        SecureZeroMemory(g_mag.watchdogRegion, g_mag.watchdogBytes);
    }
    g_mag.watchdogRegion = nullptr;
    g_mag.watchdogBytes = 0;
    g_mag.epoch += 1;
    return 0;
}

int asm_perf_init(void) {
    for (auto& s : g_perf) {
        s.beginTsc.store(0, std::memory_order_relaxed);
        s.lastNs.store(0, std::memory_order_relaxed);
        s.totalNs.store(0, std::memory_order_relaxed);
        s.samples.store(0, std::memory_order_relaxed);
    }
    return 0;
}

uint64_t asm_perf_begin(uint32_t slotIndex) {
    if (slotIndex >= kPerfSlots) {
        return 0;
    }
    const uint64_t t = qpcNow();
    g_perf[slotIndex].beginTsc.store(t, std::memory_order_relaxed);
    return t;
}

uint64_t asm_perf_end(uint32_t slotIndex, uint64_t startTSC) {
    if (slotIndex >= kPerfSlots) {
        return 0;
    }
    auto& s = g_perf[slotIndex];
    const uint64_t end = qpcNow();
    const uint64_t begin = (startTSC != 0) ? startTSC : s.beginTsc.load(std::memory_order_relaxed);
    if (end < begin) {
        return 0;
    }
    const uint64_t dur = end - begin;
    s.lastNs.store(dur, std::memory_order_relaxed);
    s.totalNs.fetch_add(dur, std::memory_order_relaxed);
    s.samples.fetch_add(1, std::memory_order_relaxed);
    s.beginTsc.store(0, std::memory_order_relaxed);
    return dur;
}

int asm_perf_read_slot(uint32_t slotIndex, void* buffer128) {
    if (buffer128 == nullptr || slotIndex >= kPerfSlots) {
        return -1;
    }
    auto* out = static_cast<uint64_t*>(buffer128);
    const auto& s = g_perf[slotIndex];
    out[0] = s.lastNs.load(std::memory_order_relaxed);
    out[1] = s.totalNs.load(std::memory_order_relaxed);
    out[2] = s.samples.load(std::memory_order_relaxed);
    out[3] = (out[2] > 0) ? (out[1] / out[2]) : 0;
    return 0;
}

int asm_perf_reset_slot(uint32_t slotIndex) {
    if (slotIndex >= kPerfSlots) {
        return -1;
    }
    auto& s = g_perf[slotIndex];
    s.beginTsc.store(0, std::memory_order_relaxed);
    s.lastNs.store(0, std::memory_order_relaxed);
    s.totalNs.store(0, std::memory_order_relaxed);
    s.samples.store(0, std::memory_order_relaxed);
    return 0;
}

} // extern "C"
