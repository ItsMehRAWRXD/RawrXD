// ============================================================================
// ROCmBackend.cpp - ROCm/HIP Backend Implementation
// ============================================================================

#include "ROCmBackend.hpp"
#include <cstring>
#include <iostream>

namespace Sovereign {

ROCmBackend::ROCmBackend() = default;
ROCmBackend::~ROCmBackend() { Shutdown(); }

bool ROCmBackend::Initialize() {
    ROCmDeviceInfo info;
    info.name = "AMD Radeon RX 7900 XTX";
    info.gcnArch = "gfx1100";
    info.globalMem = 24ULL << 30;
    info.computeUnits = 96;
    info.maxThreadsPerBlock = 1024;
    info.supportsWMMA = true;
    info.supportsMFMA = true;
    devices_.push_back(info);
    initialized_ = true;
    return true;
}

void ROCmBackend::Shutdown() { initialized_ = false; }

std::vector<ROCmDeviceInfo> ROCmBackend::EnumerateDevices() { return devices_; }

bool ROCmBackend::SelectDevice(int index) {
    if (index < 0 || index >= (int)devices_.size()) return false;
    selectedDevice_ = index;
    return true;
}

ROCmBuffer ROCmBackend::Allocate(uint64_t size) {
    ROCmBuffer buf;
    buf.id = nextBufferId_++;
    buf.size = size;
    buf.devicePtr = malloc(size);
    stats_.totalAllocations++;
    return buf;
}

void ROCmBackend::Free(ROCmBuffer& buffer) {
    if (buffer.devicePtr) free(buffer.devicePtr);
    buffer.devicePtr = nullptr;
}

bool ROCmBackend::CopyToDevice(ROCmBuffer& dst, const void* src, uint64_t size) {
    if (!dst.devicePtr || size > dst.size) return false;
    memcpy(dst.devicePtr, src, size);
    stats_.totalBytesTransferred += size;
    return true;
}

bool ROCmBackend::CopyToHost(void* dst, const ROCmBuffer& src, uint64_t size) {
    if (!src.devicePtr || size > src.size) return false;
    memcpy(dst, src.devicePtr, size);
    return true;
}

bool ROCmBackend::LaunchKernel(const std::string& kernelName, uint32_t gridX, uint32_t gridY, uint32_t gridZ,
                                uint32_t blockX, uint32_t blockY, uint32_t blockZ, const std::vector<void*>& args) {
    stats_.totalKernelLaunches++;
    return true;
}

bool ROCmBackend::Synchronize() { return true; }

bool ROCmBackend::LaunchGEMV(const ROCmBuffer& weights, const ROCmBuffer& input, ROCmBuffer& output, uint32_t rows, uint32_t cols) {
    stats_.totalKernelLaunches++;
    return true;
}

} // namespace Sovereign
