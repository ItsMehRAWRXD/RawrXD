// ============================================================================
// IOCPGGUFLoader.hpp
// Overlapped IOCP-based GGUF loader for out-of-core inference
// No memory mapping. No paging. Explicit async reads into Elastic staging.
// ============================================================================

#pragma once

#include "GGUFLoader.hpp"
#include "ElasticResidencyManager.hpp"
#include <windows.h>
#include <vector>
#include <string>
#include <atomic>

namespace Deep2 {

// ============================================================================
// IOCP-based GGUF Loader
// ============================================================================
class IOCPGGUFLoader {
public:
    struct Config {
        bool useIOCP = true;              // false = fallback to synchronous
        bool noBuffering = true;          // FILE_FLAG_NO_BUFFERING
        size_t extentSize = 64 * 1024 * 1024;  // 64 MB read extents
        size_t maxConcurrentReads = 8;
        bool registerWithElastic = true;  // auto-register tensors to Elastic
        bool verbose = false;
    };

    IOCPGGUFLoader() = default;
    ~IOCPGGUFLoader() { Close(); }

    // Open GGUF with overlapped I/O
    bool Open(const std::wstring& path, const Config& config = Config{});
    bool Open(const std::string& path, const Config& config = Config{});

    // Parse header + metadata (small, synchronous)
    bool ParseHeader(ModelMetadata& outMetadata,
                     std::vector<TensorInfo>& outTensors,
                     uint64_t& outDataOffset);

    // Load tensor data asynchronously via IOCP
    // If elastic is set, tensors are registered but NOT loaded into RAM
    // Instead, Elastic.AcquireTensor triggers async read on demand
    bool LoadTensorDataAsync(const std::vector<TensorInfo>& tensors,
                              uint64_t dataOffset);

    // Synchronous fallback for small models
    bool LoadTensorDataSync(const std::vector<TensorInfo>& tensors,
                             uint64_t dataOffset);

    // Bind to ElasticResidencyManager for out-of-core operation
    void SetElasticManager(ElasticResidencyManager* elastic) { elastic_ = elastic; }

    // Close file and cleanup
    void Close();

    // Telemetry
    struct Telemetry {
        uint64_t totalBytesRead = 0;
        uint64_t totalReads = 0;
        uint64_t totalErrors = 0;
        double avgReadLatencyMs = 0.0;
        uint32_t pendingReads = 0;
    };
    Telemetry GetTelemetry() const;

private:
    HANDLE hFile_ = INVALID_HANDLE_VALUE;
    HANDLE hIOCP_ = nullptr;
    Config config_;
    ElasticResidencyManager* elastic_ = nullptr;
    std::atomic<uint64_t> totalBytesRead_{0};
    std::atomic<uint64_t> totalReads_{0};
    std::atomic<uint64_t> totalErrors_{0};
    std::atomic<uint64_t> totalLatencyUs_{0};

    bool OpenInternal(const std::wstring& path);
    bool ReadSync(void* buffer, uint64_t offset, size_t size);
    bool ReadAsync(void* buffer, uint64_t offset, size_t size, OVERLAPPED* ov);
    bool WaitForAsync(OVERLAPPED* ov, DWORD& bytesRead);
};

} // namespace Deep2
