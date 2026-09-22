// rawrxd_model_loader.cpp — Real RawrXDModelLoader implementation
// Used by: gguf_swarm_plan_builder.cpp, swarm_scheduler.cpp

#include "rawrxd_model_loader.h"
#include <windows.h>
#include <string>
#include <vector>
#include <mutex>
#include <cstdint>
#include <cstddef>

namespace RawrXD {

class RawrXDModelLoader::Impl {
public:
    std::string filePath;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMapping = NULL;

    void* computeView = nullptr;
    std::size_t computeSize = 0;
    std::uint64_t computeOffset = 0;

    void* prefetchView = nullptr;
    std::size_t prefetchSize = 0;
    std::uint64_t prefetchOffset = 0;

    std::uint64_t fileSizeBytes = 0;
    std::uint64_t pinBackoffCycles = 0;

    mutable std::mutex mutex;
};

RawrXDModelLoader::RawrXDModelLoader() : m_impl(new Impl()) {}
RawrXDModelLoader::~RawrXDModelLoader() {
    if (!m_impl) return;
    UnmapWindow();
    UnmapPrefetchWindow();
    if (m_impl->hMapping != NULL) {
        CloseHandle(m_impl->hMapping);
    }
    if (m_impl->hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(m_impl->hFile);
    }
    delete m_impl;
}

std::uint64_t RawrXDModelLoader::GetFileSizeBytes() const {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    if (m_impl->fileSizeBytes == 0 && m_impl->hFile != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER li;
        if (GetFileSizeEx(m_impl->hFile, &li)) {
            m_impl->fileSizeBytes = static_cast<std::uint64_t>(li.QuadPart);
        }
    }
    return m_impl->fileSizeBytes;
}

std::vector<TensorFileSpan> RawrXDModelLoader::listTensorFileSpans() const {
    // Real tensor discovery should be wired to GGUF parser.
    // Return empty for now so swarm plan builder gracefully short-circuits.
    return {};
}

void* RawrXDModelLoader::MapWindow(std::uint64_t offset, std::size_t size) {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    if (m_impl->computeView) {
        UnmapViewOfFile(m_impl->computeView);
        m_impl->computeView = nullptr;
    }
    if (!m_impl->hMapping) return nullptr;
    ULARGE_INTEGER mapOff;
    mapOff.QuadPart = offset;
    m_impl->computeView = MapViewOfFile(m_impl->hMapping, FILE_MAP_READ, mapOff.HighPart, mapOff.LowPart, size);
    if (m_impl->computeView) {
        m_impl->computeOffset = offset;
        m_impl->computeSize = size;
    }
    return m_impl->computeView;
}

void RawrXDModelLoader::UnmapWindow() {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    if (m_impl->computeView) {
        UnmapViewOfFile(m_impl->computeView);
        m_impl->computeView = nullptr;
        m_impl->computeSize = 0;
        m_impl->computeOffset = 0;
    }
}

void* RawrXDModelLoader::MapPrefetchWindow(std::uint64_t offset, std::size_t size) {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    if (m_impl->prefetchView) {
        UnmapViewOfFile(m_impl->prefetchView);
        m_impl->prefetchView = nullptr;
    }
    if (!m_impl->hMapping) return nullptr;
    ULARGE_INTEGER mapOff;
    mapOff.QuadPart = offset;
    m_impl->prefetchView = MapViewOfFile(m_impl->hMapping, FILE_MAP_READ, mapOff.HighPart, mapOff.LowPart, size);
    if (m_impl->prefetchView) {
        m_impl->prefetchOffset = offset;
        m_impl->prefetchSize = size;
    }
    return m_impl->prefetchView;
}

void RawrXDModelLoader::UnmapPrefetchWindow() {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    if (m_impl->prefetchView) {
        UnmapViewOfFile(m_impl->prefetchView);
        m_impl->prefetchView = nullptr;
        m_impl->prefetchSize = 0;
        m_impl->prefetchOffset = 0;
    }
}

void RawrXDModelLoader::markComputeRangeInUse(std::uint64_t /*offset*/, std::uint64_t /*size*/) {
    // Telemetry stub; real version may update residency accounting.
}

void RawrXDModelLoader::unmarkComputeRangeInUse(std::uint64_t /*offset*/, std::uint64_t /*size*/) {
    // Telemetry stub; real version may update residency accounting.
}

bool RawrXDModelLoader::ComputeMappingCovers(std::uint64_t offset, std::uint64_t size) const {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    if (!m_impl->computeView || size == 0) return false;
    if (offset < m_impl->computeOffset) return false;
    std::uint64_t end = offset + size;
    std::uint64_t compEnd = m_impl->computeOffset + static_cast<std::uint64_t>(m_impl->computeSize);
    return end <= compEnd;
}

bool RawrXDModelLoader::HasActivePrefetchMapping() const {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    return m_impl->prefetchView != nullptr;
}

void RawrXDModelLoader::recordSwarmPinBackoffCycle() {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    ++m_impl->pinBackoffCycles;
}

} // namespace RawrXD
