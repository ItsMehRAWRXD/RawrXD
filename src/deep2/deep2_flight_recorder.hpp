#ifndef DEEP2_FLIGHT_RECORDER_HPP
#define DEEP2_FLIGHT_RECORDER_HPP

#include <cstddef>
#include <cstdint>
#include <chrono>
#include <cstdio>
#include <atomic>
#include <string>
#include <map>

namespace rawrxd {
namespace debug {

// Flight recorder interface — records per-layer timing/telemetry.
// No external dependencies: uses chrono + stdio only.
class Recorder {
public:
    Recorder() = default;

    bool start(const wchar_t* path, unsigned /*maxEvents*/, unsigned /*maxScopeDepth*/) {
        if (!path) return false;
        // Convert wide path to narrow for fopen
        char narrow[512];
        size_t conv = 0;
        wcstombs_s(&conv, narrow, sizeof(narrow), path, _TRUNCATE);
        logFile_ = std::fopen(narrow, "w");
        if (!logFile_) return false;
        startTime_ = std::chrono::steady_clock::now();
        eventCounter_.store(0);
        return true;
    }

    unsigned begin(const char* name) {
        unsigned id = eventCounter_.fetch_add(1, std::memory_order_relaxed);
        if (logFile_ && name) {
            auto now = std::chrono::steady_clock::now();
            auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                now - startTime_).count();
            std::fprintf(logFile_, "SCOPE_START id=%u us=%llu name=%s\n",
                         id, (unsigned long long)us, name);
            std::fflush(logFile_);
        }
        return id;
    }

    void end(unsigned scopeId) {
        if (logFile_) {
            auto now = std::chrono::steady_clock::now();
            auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                now - startTime_).count();
            std::fprintf(logFile_, "SCOPE_END id=%u us=%llu\n",
                         scopeId, (unsigned long long)us);
            std::fflush(logFile_);
        }
    }

    ~Recorder() {
        if (logFile_) std::fclose(logFile_);
    }

private:
    FILE* logFile_ = nullptr;
    std::chrono::steady_clock::time_point startTime_ = std::chrono::steady_clock::now();
    std::atomic<unsigned> eventCounter_{0};
};

} // namespace debug
} // namespace rawrxd

namespace Deep2 {

// FlightRecorder — alternative name used in some code paths.
// Records layer start/end events and arbitrary events with timestamps.
class FlightRecorder {
public:
    FlightRecorder() = default;

    void recordLayerStart(size_t layer) {
        auto id = eventCounter_.fetch_add(1, std::memory_order_relaxed);
        if (logFile_) {
            auto now = std::chrono::steady_clock::now();
            auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                now - startTime_).count();
            std::fprintf(logFile_, "LAYER_START id=%llu us=%llu layer=%zu\n",
                         (unsigned long long)id, (unsigned long long)us, layer);
            std::fflush(logFile_);
        }
        layerStartTimes_[layer] = std::chrono::steady_clock::now();
        (void)id;
    }

    void recordLayerEnd(size_t layer) {
        auto now = std::chrono::steady_clock::now();
        if (logFile_) {
            auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                now - startTime_).count();
            std::fprintf(logFile_, "LAYER_END us=%llu layer=%zu\n",
                         (unsigned long long)us, layer);
            std::fflush(logFile_);
        }
        auto it = layerStartTimes_.find(layer);
        if (it != layerStartTimes_.end()) {
            auto dur = std::chrono::duration_cast<std::chrono::microseconds>(
                now - it->second).count();
            layerDurations_[layer] = dur;
            layerStartTimes_.erase(it);
        }
    }

    void recordEvent(const char* event, size_t layer, double value) {
        if (logFile_ && event) {
            auto now = std::chrono::steady_clock::now();
            auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                now - startTime_).count();
            std::fprintf(logFile_, "EVENT us=%llu layer=%zu event=%s value=%f\n",
                         (unsigned long long)us, layer, event, value);
            std::fflush(logFile_);
        }
        (void)value;
    }

    void setLogFile(FILE* f) { logFile_ = f; }

private:
    FILE* logFile_ = nullptr;
    std::chrono::steady_clock::time_point startTime_ = std::chrono::steady_clock::now();
    std::atomic<unsigned> eventCounter_{0};
    std::map<size_t, std::chrono::steady_clock::time_point> layerStartTimes_;
    std::map<size_t, int64_t> layerDurations_;
};

} // namespace Deep2

#endif // DEEP2_FLIGHT_RECORDER_HPP
