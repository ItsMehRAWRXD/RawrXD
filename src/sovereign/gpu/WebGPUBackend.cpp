// ============================================================================
// WebGPUBackend.cpp - WebGPU Backend Implementation
// ============================================================================

#include "WebGPUBackend.hpp"
#include <cstring>
#include <iostream>

namespace Sovereign {

WebGPUBackend::WebGPUBackend() = default;
WebGPUBackend::~WebGPUBackend() { Shutdown(); }

bool WebGPUBackend::Initialize() { initialized_ = true; return true; }
void WebGPUBackend::Shutdown() { initialized_ = false; }

WebGPUBuffer WebGPUBackend::Allocate(uint64_t size) {
    WebGPUBuffer buf;
    buf.id = nextBufferId_++;
    buf.size = size;
    buf.buffer = malloc(size);
    buf.mappedPtr = buf.buffer;
    stats_.totalAllocations++;
    return buf;
}

void WebGPUBackend::Free(WebGPUBuffer& buffer) {
    if (buffer.buffer) free(buffer.buffer);
    buffer.buffer = nullptr;
}

bool WebGPUBackend::WriteBuffer(WebGPUBuffer& buffer, const void* data, uint64_t size) {
    if (!buffer.buffer || size > buffer.size) return false;
    memcpy(buffer.buffer, data, size);
    return true;
}

bool WebGPUBackend::ReadBuffer(const WebGPUBuffer& buffer, void* data, uint64_t size) {
    if (!buffer.buffer || size > buffer.size) return false;
    memcpy(data, buffer.buffer, size);
    return true;
}

bool WebGPUBackend::DispatchCompute(const std::string& shaderCode, const std::vector<WebGPUBuffer>& buffers, uint32_t wgX, uint32_t wgY, uint32_t wgZ) {
    stats_.totalDispatches++;
    return true;
}

} // namespace Sovereign
