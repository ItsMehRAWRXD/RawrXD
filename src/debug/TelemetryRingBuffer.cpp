//=============================================================================
// DebugBridge Lock-Free Ring Buffer Telemetry - Implementation
//=============================================================================

#include "TelemetryRingBuffer.hpp"
#include <stdio.h>

namespace RawrXD {
namespace DebugUI {

bool SharedMemoryTelemetry::InitializeProducer() {
    isProducer_ = true;
    
    // Create named shared memory
    hMapFile_ = CreateFileMappingW(
        INVALID_HANDLE_VALUE,    // Use paging file
        nullptr,                 // Default security
        PAGE_READWRITE,          // Read/write access
        0,                       // Maximum object size (high-order DWORD)
        static_cast<DWORD>(kSharedMemSize), // Maximum object size (low-order DWORD)
        kSharedMemName);         // Name of mapping object
    
    if (hMapFile_ == nullptr) {
        return false;
    }
    
    // Map view of file
    mappedView_ = MapViewOfFile(
        hMapFile_,               // Handle to map object
        FILE_MAP_ALL_ACCESS,     // Read/write permission
        0, 0,                    // Offset (entire file)
        kSharedMemSize);         // Bytes to map
    
    if (mappedView_ == nullptr) {
        CloseHandle(hMapFile_);
        hMapFile_ = nullptr;
        return false;
    }
    
    // Placement new the ring buffer
    buffer_ = new (mappedView_) TelemetryRingBuffer<kBufferCapacity>();
    
    return true;
}

bool SharedMemoryTelemetry::InitializeConsumer() {
    isProducer_ = false;
    
    // Open existing shared memory
    hMapFile_ = OpenFileMappingW(
        FILE_MAP_READ,           // Read access only
        FALSE,                   // Do not inherit
        kSharedMemName);         // Name of mapping object
    
    if (hMapFile_ == nullptr) {
        return false;
    }
    
    // Map view of file
    mappedView_ = MapViewOfFile(
        hMapFile_,               // Handle to map object
        FILE_MAP_READ,           // Read permission
        0, 0,                    // Offset (entire file)
        kSharedMemSize);         // Bytes to map
    
    if (mappedView_ == nullptr) {
        CloseHandle(hMapFile_);
        hMapFile_ = nullptr;
        return false;
    }
    
    buffer_ = static_cast<TelemetryRingBuffer<kBufferCapacity>*>(mappedView_);
    
    return true;
}

bool SharedMemoryTelemetry::Push(const TelemetryEntry& entry) {
    if (!isProducer_ || buffer_ == nullptr) {
        return false;
    }
    return buffer_->TryPush(entry);
}

std::optional<TelemetryEntry> SharedMemoryTelemetry::Pop() {
    if (isProducer_ || buffer_ == nullptr) {
        return std::nullopt;
    }
    return buffer_->TryPop();
}

void SharedMemoryTelemetry::Shutdown() {
    if (mappedView_ != nullptr) {
        UnmapViewOfFile(mappedView_);
        mappedView_ = nullptr;
    }
    
    if (hMapFile_ != nullptr) {
        CloseHandle(hMapFile_);
        hMapFile_ = nullptr;
    }
    
    buffer_ = nullptr;
}

} // namespace DebugUI
} // namespace RawrXD
