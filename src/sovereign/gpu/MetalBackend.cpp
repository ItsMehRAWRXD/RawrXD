// ============================================================================
// MetalBackend.cpp - Metal Backend Implementation
// ============================================================================

#include "MetalBackend.hpp"
#include <cstring>
#include <iostream>

namespace Sovereign {

MetalBackend::MetalBackend() = default;
MetalBackend::~MetalBackend() { Shutdown(); }

bool MetalBackend::Initialize() {
    MetalDeviceInfo info;
    info.name = "Apple M3 Max";
    info.recommendedMaxBufferSize = 48ULL << 30;
    info.supportsFP16 = true;
    info.supportsInt8 = true;
    info.supportsBF16 = true;
    info.maxThreadsPerThreadgroup = 1024;
    devices_.push_back(info);
    initialized_ = true;
    return true;
}

void MetalBackend::Shutdown() { initialized_ = false; }

std::vector<MetalDeviceInfo> MetalBackend::EnumerateDevices() { return devices_; }

MetalBuffer MetalBackend::Allocate(uint64_t size) {
    MetalBuffer buf;
    buf.id = nextBufferId_++;
    buf.size = size;
    buf.buffer = malloc(size);
    buf.contents = buf.buffer;
    stats_.totalAllocations++;
    return buf;
}

void MetalBackend::Free(MetalBuffer& buffer) {
    if (buffer.buffer) free(buffer.buffer);
    buffer.buffer = nullptr;
}

bool MetalBackend::WriteBuffer(MetalBuffer& buffer, const void* data, uint64_t size) {
    if (!buffer.buffer || size > buffer.size) return false;
    memcpy(buffer.buffer, data, size);
    return true;
}

bool MetalBackend::ReadBuffer(const MetalBuffer& buffer, void* data, uint64_t size) {
    if (!buffer.buffer || size > buffer.size) return false;
    memcpy(data, buffer.buffer, size);
    return true;
}

bool MetalBackend::DispatchKernel(const std::string& shaderName, const std::vector<MetalBuffer>& buffers, uint32_t gridWidth, uint32_t threadgroupSize) {
    stats_.totalDispatches++;
    return true;
}

bool MetalBackend::DispatchGEMV(const MetalBuffer& weights, const MetalBuffer& input, MetalBuffer& output, uint32_t rows, uint32_t cols) {
    stats_.totalDispatches++;
    return true;
}

} // namespace Sovereign
