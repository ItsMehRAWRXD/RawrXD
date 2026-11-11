// ============================================================================
// DirectMLBackend.cpp - DirectML Backend Implementation
// ============================================================================

#include "DirectMLBackend.hpp"
#include <cstring>
#include <iostream>

namespace Sovereign {

DirectMLBackend::DirectMLBackend() = default;
DirectMLBackend::~DirectMLBackend() { Shutdown(); }

bool DirectMLBackend::Initialize() {
    DirectMLDeviceInfo info;
    info.name = "DirectML Adapter";
    info.dedicatedMemory = 8ULL << 30;
    info.computeUnits = 16;
    info.supportsFP16 = true;
    info.supportsINT8 = true;
    devices_.push_back(info);
    initialized_ = true;
    return true;
}

void DirectMLBackend::Shutdown() { initialized_ = false; }

std::vector<DirectMLDeviceInfo> DirectMLBackend::EnumerateDevices() { return devices_; }

DirectMLBuffer DirectMLBackend::Allocate(uint64_t size) {
    DirectMLBuffer buf;
    buf.id = nextBufferId_++;
    buf.size = size;
    buf.resource = malloc(size);
    stats_.totalAllocations++;
    return buf;
}

void DirectMLBackend::Free(DirectMLBuffer& buffer) {
    if (buffer.resource) free(buffer.resource);
    buffer.resource = nullptr;
}

bool DirectMLBackend::CopyBuffer(DirectMLBuffer& dst, const DirectMLBuffer& src, uint64_t size) {
    if (!dst.resource || !src.resource) return false;
    memcpy(dst.resource, src.resource, size);
    return true;
}

bool DirectMLBackend::DispatchOperator(const std::string& opName, const std::vector<DirectMLBuffer>& inputs, const std::vector<DirectMLBuffer>& outputs) {
    stats_.totalDispatches++;
    return true;
}

bool DirectMLBackend::DispatchGEMV(const DirectMLBuffer& weights, const DirectMLBuffer& input, DirectMLBuffer& output, uint32_t rows, uint32_t cols) {
    stats_.totalDispatches++;
    return true;
}

} // namespace Sovereign
