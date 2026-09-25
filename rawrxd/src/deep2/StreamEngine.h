#pragma once
// ============================================================================
// StreamEngine.h — Async streaming engine with VramStreamingController
// ============================================================================
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <mutex>

namespace Deep2 {

class VramStreamingController;
class NVMeStream;
struct NVMeStreamConfig;

class StreamEngine {
public:
    StreamEngine();
    ~StreamEngine();

    StreamEngine(const StreamEngine&) = delete;
    StreamEngine& operator=(const StreamEngine&) = delete;

    bool initialize(const NVMeStreamConfig& cfg,
                    VramStreamingController* controller,
                    NVMeStream* nvme);
    void shutdown();

    // Request a tensor be loaded asynchronously. Returns true if queued.
    bool requestTensor(const std::string& name,
                       uint64_t fileOffset,
                       uint64_t bytes,
                       void* hostBuffer,
                       int priority = 0);

    // Poll all pending reads for completion. Returns true if any completed.
    bool pollCompletions();

    // Block until all pending reads finish.
    bool waitForAll();

    // Cancel pending read for a specific tensor.
    bool cancelTensor(const std::string& name);

    size_t pendingCount() const;

private:
    struct PendingRead {
        uint64_t reqId = 0;
        std::string name;
        uint64_t bytes = 0;
        void* hostBuffer = nullptr;
    };

    VramStreamingController* controller_ = nullptr;
    NVMeStream*              nvme_       = nullptr;
    std::unique_ptr<NVMeStreamConfig> cfg_;

    mutable std::mutex pendingMtx_;
    std::unordered_map<uint64_t, PendingRead> pending_;
};

} // namespace Deep2
