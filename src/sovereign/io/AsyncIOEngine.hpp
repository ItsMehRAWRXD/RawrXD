// ============================================================================
// AsyncIOEngine.hpp - Async I/O Engine with IOCP
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>

namespace Sovereign {

struct AsyncIORequest {
    uint64_t id;
    std::string path;
    std::vector<uint8_t> data;
    uint64_t offset;
    uint64_t size;
    bool isRead;
    bool isComplete;
    bool success;
    uint64_t durationUs;
};

class AsyncIOEngine {
public:
    AsyncIOEngine();
    ~AsyncIOEngine();

    bool Initialize(uint32_t numWorkers = 4);
    void Shutdown();

    uint64_t ReadFile(const std::string& path, uint64_t offset, uint64_t size);
    uint64_t WriteFile(const std::string& path, const std::vector<uint8_t>& data, uint64_t offset);
    bool WaitForCompletion(uint64_t requestId, uint64_t timeoutMs = 5000);
    bool IsComplete(uint64_t requestId) const;
    AsyncIORequest GetResult(uint64_t requestId) const;

    void SetCompletionCallback(std::function<void(const AsyncIORequest&)> callback);

    struct AsyncIOStats { uint64_t totalReads; uint64_t totalWrites; uint64_t totalBytes; double avgLatencyUs; };
    AsyncIOStats GetStats() const { return stats_; }

private:
    std::atomic<bool> running_{false};
    std::unordered_map<uint64_t, AsyncIORequest> requests_;
    uint64_t nextRequestId_ = 1;
    AsyncIOStats stats_;
    std::function<void(const AsyncIORequest&)> callback_;
    mutable std::mutex mutex_;
    std::vector<std::thread> workers_;
    
    void WorkerLoop();
    void ProcessRequest(AsyncIORequest& req);
};

} // namespace Sovereign
