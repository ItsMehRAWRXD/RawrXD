// unlinked_symbols_batch_003.cpp
// Batch 3: RTP telemetry + model loader (GGUF Open path).
// V280_UI_* owned by src/win32app/v280_link_bridge.cpp (sole Win32IDE owner).

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <new>
#include <string>

#include "../gguf_loader.h"

namespace {

struct RTPDescriptor {
    uint32_t id;
    uint32_t flags;
};

struct RTPState {
    std::array<RTPDescriptor, 16> descriptors{};
    std::array<uint8_t, 1024> contextBlob{};
    std::array<uint8_t, 256> telemetry{};
    std::atomic<size_t> contextSize{0};
    std::atomic<uint64_t> packetCount{0};
    std::atomic<bool> initialized{false};
};
RTPState g_rtp;

std::mutex g_modelMtx;
GGUFLoader* g_modelLoader = nullptr;
bool g_modelInited = false;

bool hasSupportedModelExt(const char* path) {
    if (path == nullptr) {
        return false;
    }
    const std::string p(path);
    const auto pos = p.find_last_of('.');
    if (pos == std::string::npos) {
        return false;
    }
    const std::string ext = p.substr(pos);
    return ext == ".gguf" || ext == ".bin" || ext == ".model" ||
           ext == ".GGUF" || ext == ".BIN" || ext == ".MODEL";
}

} // namespace

extern "C" {

void RTP_InitDescriptorTable() {
    for (uint32_t i = 0; i < g_rtp.descriptors.size(); ++i) {
        g_rtp.descriptors[i].id = i;
        g_rtp.descriptors[i].flags = 0x100u + i;
    }
    g_rtp.contextSize.store(0, std::memory_order_relaxed);
    g_rtp.packetCount.store(0, std::memory_order_relaxed);
    g_rtp.initialized.store(true, std::memory_order_relaxed);
}

int RTP_GetDescriptorCount() {
    return static_cast<int>(g_rtp.descriptors.size());
}

void* RTP_GetDescriptorTable() {
    return g_rtp.descriptors.data();
}

bool RTP_ValidatePacket(const void* packet, size_t size) {
    return packet != nullptr && size > 0 && size <= 4096;
}

void RTP_DispatchPacket(const void* packet, size_t size) {
    if (!RTP_ValidatePacket(packet, size)) {
        return;
    }
    const size_t copySize = (size < g_rtp.contextBlob.size()) ? size : g_rtp.contextBlob.size();
    std::memcpy(g_rtp.contextBlob.data(), packet, copySize);
    g_rtp.contextSize.store(copySize, std::memory_order_relaxed);
    g_rtp.packetCount.fetch_add(1, std::memory_order_relaxed);
}

void RTP_AgentLoop_Run() {
    if (!g_rtp.initialized.load(std::memory_order_relaxed)) {
        RTP_InitDescriptorTable();
    }
    g_rtp.packetCount.fetch_add(1, std::memory_order_relaxed);
}

void* RTP_BuildContextBlob(size_t* out_size) {
    const uint64_t packets = g_rtp.packetCount.load(std::memory_order_relaxed);
    std::memcpy(g_rtp.contextBlob.data(), &packets, sizeof(packets));
    const size_t size = sizeof(packets);
    g_rtp.contextSize.store(size, std::memory_order_relaxed);
    if (out_size) {
        *out_size = size;
    }
    return g_rtp.contextBlob.data();
}

void* RTP_GetContextBlobPtr() {
    return g_rtp.contextBlob.data();
}

size_t RTP_GetContextBlobSize() {
    return g_rtp.contextSize.load(std::memory_order_relaxed);
}

void* RTP_GetTelemetrySnapshot() {
    const uint64_t packets = g_rtp.packetCount.load(std::memory_order_relaxed);
    std::memset(g_rtp.telemetry.data(), 0, g_rtp.telemetry.size());
    std::memcpy(g_rtp.telemetry.data(), &packets, sizeof(packets));
    return g_rtp.telemetry.data();
}

bool ModelLoaderInit() {
    std::lock_guard<std::mutex> lock(g_modelMtx);
    if (g_modelLoader == nullptr) {
        g_modelLoader = new (std::nothrow) GGUFLoader();
    }
    g_modelInited = (g_modelLoader != nullptr);
    return g_modelInited;
}

bool LoadModel(const char* path) {
    if (!hasSupportedModelExt(path)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(g_modelMtx);
    if (!g_modelInited || g_modelLoader == nullptr) {
        if (g_modelLoader == nullptr) {
            g_modelLoader = new (std::nothrow) GGUFLoader();
        }
        g_modelInited = (g_modelLoader != nullptr);
        if (!g_modelInited) {
            return false;
        }
    }
    if (!g_modelLoader->Open(path)) {
        return false;
    }
    return g_modelLoader->ParseHeader();
}

} // extern "C"
