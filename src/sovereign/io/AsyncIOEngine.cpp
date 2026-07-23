// ============================================================================
// AsyncIOEngine.cpp - Async I/O Engine Implementation
// ============================================================================

#include "AsyncIOEngine.hpp"
#include <fstream>
#include <filesystem>
#include <iostream>
#include <thread>

namespace Sovereign {

AsyncIOEngine::AsyncIOEngine() = default;
AsyncIOEngine::~AsyncIOEngine() { Shutdown(); }

bool AsyncIOEngine::Initialize(uint32_t numWorkers) {
    running_ = true;
    for (uint32_t i = 0; i < numWorkers; ++i) {
        workers_.emplace_back(&AsyncIOEngine::WorkerLoop, this);
    }
    return true;
}

void AsyncIOEngine::Shutdown() {
    running_ = false;
    for (auto& w : workers_) if (w.joinable()) w.join();
    workers_.clear();
}

uint64_t AsyncIOEngine::ReadFile(const std::string& path, uint64_t offset, uint64_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t id = nextRequestId_++;
    AsyncIORequest req;
    req.id = id;
    req.path = path;
    req.offset = offset;
    req.size = size;
    req.isRead = true;
    req.isComplete = false;
    requests_[id] = req;
    stats_.totalReads++;
    return id;
}

uint64_t AsyncIOEngine::WriteFile(const std::string& path, const std::vector<uint8_t>& data, uint64_t offset) {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t id = nextRequestId_++;
    AsyncIORequest req;
    req.id = id;
    req.path = path;
    req.data = data;
    req.offset = offset;
    req.size = data.size();
    req.isRead = false;
    req.isComplete = false;
    requests_[id] = req;
    stats_.totalWrites++;
    stats_.totalBytes += data.size();
    return id;
}

bool AsyncIOEngine::WaitForCompletion(uint64_t requestId, uint64_t timeoutMs) {
    auto start = std::chrono::high_resolution_clock::now();
    while (true) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = requests_.find(requestId);
            if (it == requests_.end()) return false;
            if (it->second.isComplete) return it->second.success;
        }
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::high_resolution_clock::now() - start).count();
        if (elapsed >= timeoutMs) return false;
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
}

void AsyncIOEngine::WorkerLoop() {
    while (running_.load()) {
        uint64_t requestId = 0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& [id, req] : requests_) {
                if (!req.isComplete) { requestId = id; break; }
            }
        }
        
        if (requestId > 0) {
            std::lock_guard<std::mutex> lock(mutex_);
            ProcessRequest(requests_[requestId]);
        } else {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    }
}

void AsyncIOEngine::ProcessRequest(AsyncIORequest& req) {
    auto start = std::chrono::high_resolution_clock::now();
    
    if (req.isRead) {
        std::ifstream file(req.path, std::ios::binary);
        if (file) {
            file.seekg(req.offset);
            req.data.resize(req.size);
            file.read(reinterpret_cast<char*>(req.data.data()), req.size);
            req.success = true;
        } else {
            req.success = false;
        }
    } else {
        std::ofstream file(req.path, std::ios::binary | std::ios::app);
        if (file) {
            file.seekp(req.offset);
            file.write(reinterpret_cast<const char*>(req.data.data()), req.data.size());
            req.success = true;
        } else {
            req.success = false;
        }
    }
    
    req.isComplete = true;
    req.durationUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now() - start).count();
    
    if (callback_) callback_(req);
}

} // namespace Sovereign
