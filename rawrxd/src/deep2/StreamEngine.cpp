// ============================================================================
// StreamEngine.cpp — Real async streaming engine with VramStreamingController
// ============================================================================
#include "StreamEngine.h"
#include "VramStreamingController.hpp"
#include "NVMeStream.h"
#include <cstdio>
#include <cstring>
#include <thread>

namespace Deep2 {

StreamEngine::StreamEngine() = default;
StreamEngine::~StreamEngine() = default;

bool StreamEngine::initialize(const NVMeStreamConfig& cfg,
                               VramStreamingController* controller,
                               NVMeStream* nvme) {
    if (!controller || !nvme) return false;
    controller_ = controller;
    nvme_     = nvme;
    cfg_      = cfg;
    return nvme_->initialize(cfg.modelPath);
}

void StreamEngine::shutdown() {
    if (nvme_) nvme_->shutdown();
    nvme_       = nullptr;
    controller_ = nullptr;
}

bool StreamEngine::requestTensor(const std::string& name,
                                  uint64_t fileOffset,
                                  uint64_t bytes,
                                  void* hostBuffer,
                                  int priority) {
    if (!controller_ || !nvme_) return false;

    controller_->registerTensor(name, bytes, priority);

    if (!controller_->requestResident(name)) return false;
    if (!controller_->requestInFlightBytes(bytes, /*timeoutMs=*/0)) return false;

    uint64_t reqId = nvme_->readAsync(name, fileOffset, static_cast<size_t>(bytes), hostBuffer);
    if (reqId == 0) {
        controller_->releaseInFlightBytes(bytes);
        return false;
    }

    controller_->recordBytesMoved(bytes);
    {
        std::lock_guard<std::mutex> lock(pendingMtx_);
        PendingRead pr;
        pr.reqId      = reqId;
        pr.name       = name;
        pr.bytes      = bytes;
        pr.hostBuffer = hostBuffer;
        pending_[reqId] = pr;
    }
    return true;
}

bool StreamEngine::pollCompletions() {
    if (!controller_ || !nvme_) return false;
    std::lock_guard<std::mutex> lock(pendingMtx_);

    bool anyDone = false;
    for (auto it = pending_.begin(); it != pending_.end(); ) {
        size_t bytesRead = 0;
        int    errorCode = 0;
        if (nvme_->pollCompletion(it->second.reqId, bytesRead, errorCode)) {
            anyDone = true;
            controller_->releaseInFlightBytes(it->second.bytes);
            if (errorCode == 0) {
                controller_->markResident(it->second.name);
            } else {
                std::fprintf(stderr,
                    "[StreamEngine] read failed for %s: error=%d bytesRead=%zu\n",
                    it->second.name.c_str(), errorCode, bytesRead);
            }
            it = pending_.erase(it);
        } else {
            ++it;
        }
    }
    return anyDone;
}

bool StreamEngine::waitForAll() {
    if (!controller_ || !nvme_) return false;
    while (true) {
        {
            std::lock_guard<std::mutex> lock(pendingMtx_);
            if (pending_.empty()) break;
        }
        pollCompletions();
        std::this_thread::yield();
    }
    return true;
}

bool StreamEngine::cancelTensor(const std::string& name) {
    std::lock_guard<std::mutex> lock(pendingMtx_);
    for (auto it = pending_.begin(); it != pending_.end(); ++it) {
        if (it->second.name == name) {
            nvme_->cancelRequest(it->second.reqId);
            controller_->releaseInFlightBytes(it->second.bytes);
            pending_.erase(it);
            return true;
        }
    }
    return false;
}

size_t StreamEngine::pendingCount() const {
    std::lock_guard<std::mutex> lock(pendingMtx_);
    return pending_.size();
}

} // namespace Deep2

