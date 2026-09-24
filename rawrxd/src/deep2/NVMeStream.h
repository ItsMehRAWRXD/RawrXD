#pragma once
// ============================================================================
// NVMeStream — Real async file-backed streaming path
// Bounded queues, offset/range validation, actual byte counters,
// failure/short-read handling, integrated out-of-core read test.
// ============================================================================
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <thread>
#include <functional>
#include <future>
#include <filesystem>
#include <unordered_map>

namespace Deep2 {

enum class NVMeRequestState : uint8_t {
    Pending = 0,
    Reading,
    Completed,
    Failed,
    Cancelled
};

struct NVMeRequest {
    uint64_t id = 0;
    std::string tensorName;
    uint64_t fileOffset = 0;
    size_t byteCount = 0;
    size_t bytesRead = 0;
    void* hostBuffer = nullptr;
    NVMeRequestState state = NVMeRequestState::Pending;
    int errorCode = 0;
};

struct NVMeStreamConfig {
    size_t blockSize = 4096;
    size_t queueDepth = 64;        // max concurrent async requests
    size_t maxPendingBytes = 0;    // 0 = unbounded (bounded by queueDepth)
    std::string modelPath;
    bool useAsyncIO = true;        // Windows: overlapped I/O
};

struct NVMeStreamStats {
    uint64_t requestsSubmitted = 0;
    uint64_t requestsCompleted = 0;
    uint64_t requestsFailed = 0;
    uint64_t bytesRequested = 0;
    uint64_t bytesReadActual = 0;
    uint64_t shortReads = 0;
    uint64_t cancelled = 0;
    uint64_t queueWaits = 0;
    double avgLatencyUs = 0.0;
    uint64_t maxLatencyUs = 0;
};

class NVMeStream {
public:
    NVMeStream() = default;
    explicit NVMeStream(const NVMeStreamConfig& cfg);
    ~NVMeStream();

    NVMeStream(const NVMeStream&) = delete;
    NVMeStream& operator=(const NVMeStream&) = delete;

    // Lifecycle
    bool initialize(const std::string& modelPath);
    bool isInitialized() const { return initialized_; }
    void shutdown();

    // Synchronous read (for fallback / small reads)
    bool readSync(const std::string& tensorName,
                  uint64_t fileOffset,
                  size_t byteCount,
                  void* outBuffer,
                  size_t& outBytesRead);

    // Async read enqueue — returns request id, 0 on failure
    uint64_t readAsync(const std::string& tensorName,
                       uint64_t fileOffset,
                       size_t byteCount,
                       void* outBuffer);

    // Poll completion — returns true if reqId is done (populates outBytesRead)
    bool pollCompletion(uint64_t reqId, size_t& outBytesRead, int& errorCode);

    // Blocking wait for a specific request
    bool waitForRequest(uint64_t reqId, size_t& outBytesRead, int& errorCode);

    // Cancel a pending request
    bool cancelRequest(uint64_t reqId);

    // Validation
    bool validateRange(uint64_t fileOffset, size_t byteCount) const;

    // Stats
    NVMeStreamStats stats() const;
    void resetStats();

    // Out-of-core read test: read a contiguous range and verify checksum (optional)
    bool outOfCoreReadTest(uint64_t offset, size_t bytes, uint32_t expectedCrc = 0);

private:
    NVMeStreamConfig cfg_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> shutdown_{false};
    std::atomic<uint64_t> nextReqId_{1};

    // Request ledger
    mutable std::mutex ledgerMtx_;
    std::unordered_map<uint64_t, NVMeRequest> ledger_;
    std::queue<uint64_t> completedQueue_;

    // Async worker
    std::unique_ptr<std::thread> worker_;
    std::mutex queueMtx_;
    std::condition_variable queueCv_;
    std::queue<uint64_t> pendingQueue_;

    // Stats
    mutable std::mutex statsMtx_;
    NVMeStreamStats stats_;

    // File handle (Windows overlapped)
#ifdef _WIN32
    void* fileHandle_ = nullptr; // HANDLE
#else
    int fileHandle_ = -1;
#endif

    void workerLoop();
    bool executeRead(NVMeRequest& req);
    void recordLatency(uint64_t latencyUs);
};

} // namespace Deep2
