// ============================================================================
// NVMeStream.cpp — Real async file-backed streaming implementation
// ============================================================================
#include "NVMeStream.h"
#include <cstdio>
#include <chrono>
#include <numeric>

#ifdef _WIN32
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #include <windows.h>
#else
    #include <fcntl.h>
    #include <unistd.h>
    #include <errno.h>
#endif

namespace Deep2 {

NVMeStream::NVMeStream(const NVMeStreamConfig& cfg) : cfg_(cfg) {}

NVMeStream::~NVMeStream() { shutdown(); }

bool NVMeStream::initialize(const std::string& modelPath) {
    if (initialized_) return true;
    cfg_.modelPath = modelPath;

#ifdef _WIN32
    fileHandle_ = CreateFileA(
        modelPath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING,
        nullptr);
    if (fileHandle_ == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr, "[NVMeStream] failed to open %s\n", modelPath.c_str());
        return false;
    }
#else
    fileHandle_ = open(modelPath.c_str(), O_RDONLY | O_DIRECT);
    if (fileHandle_ < 0) {
        std::perror("[NVMeStream] open failed");
        return false;
    }
#endif

    shutdown_ = false;
    worker_ = std::make_unique<std::thread>(&NVMeStream::workerLoop, this);
    initialized_ = true;
    return true;
}

void NVMeStream::shutdown() {
    if (!initialized_) return;
    shutdown_ = true;
    queueCv_.notify_all();
    if (worker_ && worker_->joinable()) {
        worker_->join();
    }
    worker_.reset();

#ifdef _WIN32
    if (fileHandle_ && fileHandle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(fileHandle_);
        fileHandle_ = nullptr;
    }
#else
    if (fileHandle_ >= 0) {
        close(fileHandle_);
        fileHandle_ = -1;
    }
#endif
    initialized_ = false;
}

bool NVMeStream::validateRange(uint64_t fileOffset, size_t byteCount) const {
    if (byteCount == 0) return false;
    if (fileOffset > (std::numeric_limits<uint64_t>::max)() - byteCount)
        return false;
    if (cfg_.modelPath.empty()) return false;
    if (!std::filesystem::exists(cfg_.modelPath)) return false;
    const auto sz = std::filesystem::file_size(cfg_.modelPath);
    if (fileOffset + byteCount > sz) return false;
    return true;
}

bool NVMeStream::readSync(const std::string& tensorName,
                          uint64_t fileOffset,
                          size_t byteCount,
                          void* outBuffer,
                          size_t& outBytesRead) {
    outBytesRead = 0;
    if (!initialized_ || !outBuffer || byteCount == 0) return false;
    if (!validateRange(fileOffset, byteCount)) return false;

    auto t0 = std::chrono::high_resolution_clock::now();

#ifdef _WIN32
    OVERLAPPED ov{};
    ov.Offset = static_cast<DWORD>(fileOffset);
    ov.OffsetHigh = static_cast<DWORD>(fileOffset >> 32);
    DWORD read = 0;
    BOOL ok = ReadFile(fileHandle_, outBuffer, static_cast<DWORD>(byteCount),
                       &read, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        ok = GetOverlappedResult(fileHandle_, &ov, &read, TRUE);
    }
    if (!ok) {
        std::fprintf(stderr, "[NVMeStream] sync read failed for %s\n", tensorName.c_str());
        return false;
    }
    outBytesRead = static_cast<size_t>(read);
#else
    ssize_t n = pread(fileHandle_, outBuffer, byteCount,
                      static_cast<off_t>(fileOffset));
    if (n < 0) {
        std::perror("[NVMeStream] pread failed");
        return false;
    }
    outBytesRead = static_cast<size_t>(n);
#endif

    auto t1 = std::chrono::high_resolution_clock::now();
    recordLatency(static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count()));

    {
        std::lock_guard<std::mutex> lk(statsMtx_);
        ++stats_.requestsSubmitted;
        ++stats_.requestsCompleted;
        stats_.bytesReadActual += outBytesRead;
        if (outBytesRead < byteCount) ++stats_.shortReads;
    }
    return true;
}

uint64_t NVMeStream::readAsync(const std::string& tensorName,
                               uint64_t fileOffset,
                               size_t byteCount,
                               void* outBuffer) {
    if (!initialized_ || !outBuffer || byteCount == 0) return 0;
    if (!validateRange(fileOffset, byteCount)) return 0;

    {
        std::lock_guard<std::mutex> lk(queueMtx_);
        if (pendingQueue_.size() >= cfg_.queueDepth) {
            std::lock_guard<std::mutex> sl(statsMtx_);
            ++stats_.queueWaits;
            return 0;
        }
    }

    uint64_t reqId = nextReqId_.fetch_add(1);
    NVMeRequest req;
    req.id = reqId;
    req.tensorName = tensorName;
    req.fileOffset = fileOffset;
    req.byteCount = byteCount;
    req.hostBuffer = outBuffer;
    req.state = NVMeRequestState::Pending;

    {
        std::lock_guard<std::mutex> lk(ledgerMtx_);
        ledger_[reqId] = std::move(req);
    }
    {
        std::lock_guard<std::mutex> lk(queueMtx_);
        pendingQueue_.push(reqId);
    }
    queueCv_.notify_one();

    {
        std::lock_guard<std::mutex> lk(statsMtx_);
        ++stats_.requestsSubmitted;
        stats_.bytesRequested += byteCount;
    }
    return reqId;
}

bool NVMeStream::pollCompletion(uint64_t reqId, size_t& outBytesRead, int& errorCode) {
    outBytesRead = 0;
    errorCode = 0;
    std::lock_guard<std::mutex> lk(ledgerMtx_);
    auto it = ledger_.find(reqId);
    if (it == ledger_.end()) return false;
    if (it->second.state == NVMeRequestState::Completed ||
        it->second.state == NVMeRequestState::Failed ||
        it->second.state == NVMeRequestState::Cancelled) {
        outBytesRead = it->second.bytesRead;
        errorCode = it->second.errorCode;
        return true;
    }
    return false;
}

bool NVMeStream::waitForRequest(uint64_t reqId, size_t& outBytesRead, int& errorCode) {
    outBytesRead = 0;
    errorCode = 0;
    while (!pollCompletion(reqId, outBytesRead, errorCode)) {
        std::this_thread::yield();
    }
    return true;
}

bool NVMeStream::cancelRequest(uint64_t reqId) {
    std::lock_guard<std::mutex> lk(ledgerMtx_);
    auto it = ledger_.find(reqId);
    if (it == ledger_.end()) return false;
    if (it->second.state == NVMeRequestState::Pending) {
        it->second.state = NVMeRequestState::Cancelled;
        it->second.errorCode = -1;
        {
            std::lock_guard<std::mutex> sl(statsMtx_);
            ++stats_.cancelled;
        }
        return true;
    }
    return false;
}

NVMeStreamStats NVMeStream::stats() const {
    std::lock_guard<std::mutex> lk(statsMtx_);
    return stats_;
}

void NVMeStream::resetStats() {
    std::lock_guard<std::mutex> lk(statsMtx_);
    stats_ = NVMeStreamStats{};
}

bool NVMeStream::outOfCoreReadTest(uint64_t offset, size_t bytes, uint32_t expectedCrc) {
    if (!initialized_ || bytes == 0) return false;
    if (!validateRange(offset, bytes)) return false;

    std::vector<uint8_t> buf(bytes);
    size_t actual = 0;
    if (!readSync("__test__", offset, bytes, buf.data(), actual)) return false;
    if (actual != bytes) return false;
    if (expectedCrc != 0) {
        uint32_t crc = 0;
        for (auto b : buf) crc = crc * 31 + b;
        if (crc != expectedCrc) return false;
    }
    return true;
}

void NVMeStream::workerLoop() {
    while (!shutdown_) {
        uint64_t reqId = 0;
        {
            std::unique_lock<std::mutex> lk(queueMtx_);
            queueCv_.wait(lk, [this] { return shutdown_ || !pendingQueue_.empty(); });
            if (shutdown_ && pendingQueue_.empty()) break;
            reqId = pendingQueue_.front();
            pendingQueue_.pop();
        }
        NVMeRequest req;
        {
            std::lock_guard<std::mutex> lk(ledgerMtx_);
            auto it = ledger_.find(reqId);
            if (it == ledger_.end()) continue;
            req = it->second;
        }
        if (req.state == NVMeRequestState::Cancelled) continue;

        req.state = NVMeRequestState::Reading;
        bool ok = executeRead(req);
        req.state = ok ? NVMeRequestState::Completed : NVMeRequestState::Failed;

        {
            std::lock_guard<std::mutex> lk(ledgerMtx_);
            auto it = ledger_.find(reqId);
            if (it != ledger_.end()) {
                it->second = req;
                completedQueue_.push(reqId);
            }
        }
        {
            std::lock_guard<std::mutex> lk(statsMtx_);
            ++stats_.requestsCompleted;
            stats_.bytesReadActual += req.bytesRead;
            if (!ok) ++stats_.requestsFailed;
            else if (req.bytesRead < req.byteCount) ++stats_.shortReads;
        }
    }
}

bool NVMeStream::executeRead(NVMeRequest& req) {
    auto t0 = std::chrono::high_resolution_clock::now();

#ifdef _WIN32
    OVERLAPPED ov{};
    ov.Offset = static_cast<DWORD>(req.fileOffset);
    ov.OffsetHigh = static_cast<DWORD>(req.fileOffset >> 32);
    DWORD read = 0;
    BOOL ok = ReadFile(fileHandle_, req.hostBuffer,
                       static_cast<DWORD>(req.byteCount), &read, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        ok = GetOverlappedResult(fileHandle_, &ov, &read, TRUE);
    }
    if (!ok) {
        req.errorCode = static_cast<int>(GetLastError());
        return false;
    }
    req.bytesRead = static_cast<size_t>(read);
#else
    ssize_t n = pread(fileHandle_, req.hostBuffer, req.byteCount,
                      static_cast<off_t>(req.fileOffset));
    if (n < 0) {
        req.errorCode = errno;
        return false;
    }
    req.bytesRead = static_cast<size_t>(n);
#endif

    auto t1 = std::chrono::high_resolution_clock::now();
    recordLatency(static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count()));
    return true;
}

void NVMeStream::recordLatency(uint64_t latencyUs) {
    std::lock_guard<std::mutex> lk(statsMtx_);
    stats_.avgLatencyUs = (stats_.avgLatencyUs * stats_.requestsCompleted + latencyUs)
                          / (stats_.requestsCompleted + 1);
    if (latencyUs > stats_.maxLatencyUs) stats_.maxLatencyUs = latencyUs;
}

} // namespace Deep2
