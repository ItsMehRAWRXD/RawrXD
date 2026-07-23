// ============================================================================
// OpenCLBackend.cpp - OpenCL Backend Implementation
// ============================================================================

#include "OpenCLBackend.hpp"
#include <cstring>
#include <iostream>

namespace Sovereign {

OpenCLBackend::OpenCLBackend() = default;
OpenCLBackend::~OpenCLBackend() { Shutdown(); }

bool OpenCLBackend::Initialize() {
    OpenCLDeviceInfo info;
    info.name = "OpenCL Device";
    info.vendor = "Generic";
    info.globalMem = 8ULL << 30;
    info.computeUnits = 16;
    info.maxWorkgroupSize = 256;
    info.supportsFP16 = true;
    info.clVersion = "OpenCL 3.0";
    devices_.push_back(info);
    initialized_ = true;
    return true;
}

void OpenCLBackend::Shutdown() { initialized_ = false; }

std::vector<OpenCLDeviceInfo> OpenCLBackend::EnumerateDevices() { return devices_; }

bool OpenCLBackend::SelectDevice(int index) {
    if (index < 0 || index >= (int)devices_.size()) return false;
    selectedDevice_ = index;
    return true;
}

OpenCLBuffer OpenCLBackend::Allocate(uint64_t size) {
    OpenCLBuffer buf;
    buf.id = nextBufferId_++;
    buf.size = size;
    buf.memObject = malloc(size);
    stats_.totalAllocations++;
    return buf;
}

void OpenCLBackend::Free(OpenCLBuffer& buffer) {
    if (buffer.memObject) free(buffer.memObject);
    buffer.memObject = nullptr;
}

bool OpenCLBackend::WriteBuffer(OpenCLBuffer& buffer, const void* data, uint64_t size, uint64_t offset) {
    if (!buffer.memObject || offset + size > buffer.size) return false;
    memcpy(static_cast<uint8_t*>(buffer.memObject) + offset, data, size);
    return true;
}

bool OpenCLBackend::ReadBuffer(const OpenCLBuffer& buffer, void* data, uint64_t size, uint64_t offset) {
    if (!buffer.memObject || offset + size > buffer.size) return false;
    memcpy(data, static_cast<uint8_t*>(buffer.memObject) + offset, size);
    return true;
}

bool OpenCLBackend::ExecuteKernel(const std::string& source, const std::string& kernelName, const std::vector<OpenCLBuffer>& args, uint32_t globalSize, uint32_t localSize) {
    stats_.totalKernelExecs++;
    return true;
}

bool OpenCLBackend::Finish() { return true; }

} // namespace Sovereign
