// ============================================================================
// TelemetryInjector.cpp - Real-time Performance Telemetry Implementation
// ============================================================================

#include "TelemetryInjector.hpp"
#include <cstring>
#include <fstream>
#include <algorithm>
#include <iostream>

namespace Sovereign {

TelemetryInjector::TelemetryInjector() = default;
TelemetryInjector::~TelemetryInjector() {
    Shutdown();
}

bool TelemetryInjector::Initialize(size_t bufferSize) {
    if (initialized_) Shutdown();
    
    // Ensure power of 2
    bufferSize_ = 1;
    while (bufferSize_ < bufferSize) bufferSize_ <<= 1;
    bufferMask_ = bufferSize_ - 1;
    
    buffer_ = new TelemetryEntry[bufferSize_]();
    if (!buffer_) return false;
    
    initialized_ = true;
    return true;
}

void TelemetryInjector::Shutdown() {
    delete[] buffer_;
    buffer_ = nullptr;
    initialized_ = false;
}

void TelemetryInjector::Inject(const TelemetryEvent& event) {
    if (!initialized_) return;
    
    // Check if event type is enabled
    uint64_t typeBit = 1ULL << static_cast<int>(event.type);
    if (!(enabledTypes_ & typeBit)) return;
    
    uint64_t index = writeIndex_.fetch_add(1) & bufferMask_;
    
    TelemetryEntry& entry = buffer_[index];
    entry.event = event;
    entry.sequence = sequence_++;
    entry.valid = true;
    
    stats_.totalEvents++;
    
    ProcessEvent(event);
}

void TelemetryInjector::InjectSimple(TelemetryEventType type, uint64_t duration) {
    TelemetryEvent event;
    event.type = type;
    event.timestamp = GetTimestamp();
    event.duration = duration;
    event.threadId = GetThreadId();
    event.label = nullptr;
    Inject(event);
}

void TelemetryInjector::InjectWithData(TelemetryEventType type, uint64_t duration, 
                                        uint64_t d0, uint64_t d1, uint64_t d2) {
    TelemetryEvent event;
    event.type = type;
    event.timestamp = GetTimestamp();
    event.duration = duration;
    event.threadId = GetThreadId();
    event.data0 = d0;
    event.data1 = d1;
    event.data2 = d2;
    event.label = nullptr;
    Inject(event);
}

void TelemetryInjector::InjectBatch(const TelemetryEvent* events, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        Inject(events[i]);
    }
}

size_t TelemetryInjector::Consume(TelemetryEvent* buffer, size_t maxCount) {
    size_t count = 0;
    uint64_t readIdx = readIndex_.load();
    
    while (count < maxCount) {
        TelemetryEntry& entry = buffer_[readIdx & bufferMask_];
        if (!entry.valid) break;
        
        buffer[count] = entry.event;
        entry.valid = false;
        count++;
        readIdx++;
    }
    
    readIndex_.store(readIdx);
    return count;
}

size_t TelemetryInjector::GetAvailableCount() const {
    return writeIndex_.load() - readIndex_.load();
}

void TelemetryInjector::Clear() {
    writeIndex_.store(0);
    readIndex_.store(0);
    memset(buffer_, 0, bufferSize_ * sizeof(TelemetryEntry));
}

void TelemetryInjector::Resize(size_t newSize) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    TelemetryEntry* newBuffer = new TelemetryEntry[newSize]();
    if (buffer_) {
        size_t copySize = std::min(bufferSize_, newSize);
        memcpy(newBuffer, buffer_, copySize * sizeof(TelemetryEntry));
        delete[] buffer_;
    }
    
    buffer_ = newBuffer;
    bufferSize_ = newSize;
    bufferMask_ = newSize - 1;
}

TelemetryStats TelemetryInjector::GetStats() const {
    return stats_;
}

void TelemetryInjector::ResetStats() {
    stats_ = TelemetryStats{};
}

void TelemetryInjector::ProcessEvent(const TelemetryEvent& event) {
    if (eventCallback_) {
        eventCallback_(event);
    }
    
    // Check threshold callbacks
    for (const auto& [threshold, callback] : thresholdCallbacks_) {
        if (event.duration >= threshold) {
            callback(event);
        }
    }
}

bool TelemetryInjector::ExportToJSON(const std::string& path) {
    std::ofstream file(path);
    if (!file) return false;
    
    file << "{\n  \"events\": [\n";
    
    bool first = true;
    for (size_t i = 0; i < bufferSize_; ++i) {
        if (buffer_[i].valid) {
            if (!first) file << ",\n";
            first = false;
            
            file << "    {\n";
            file << "      \"type\": " << static_cast<int>(buffer_[i].event.type) << ",\n";
            file << "      \"timestamp\": " << buffer_[i].event.timestamp << ",\n";
            file << "      \"duration\": " << buffer_[i].event.duration << ",\n";
            file << "      \"threadId\": " << buffer_[i].event.threadId << "\n";
            file << "    }";
        }
    }
    
    file << "\n  ]\n}\n";
    return true;
}

bool TelemetryInjector::ExportToCSV(const std::string& path) {
    std::ofstream file(path);
    if (!file) return false;
    
    file << "type,timestamp,duration,threadId,data0,data1,data2\n";
    
    for (size_t i = 0; i < bufferSize_; ++i) {
        if (buffer_[i].valid) {
            file << static_cast<int>(buffer_[i].event.type) << ","
                 << buffer_[i].event.timestamp << ","
                 << buffer_[i].event.duration << ","
                 << buffer_[i].event.threadId << ","
                 << buffer_[i].event.data0 << ","
                 << buffer_[i].event.data1 << ","
                 << buffer_[i].event.data2 << "\n";
        }
    }
    
    return true;
}

uint64_t TelemetryInjector::GetTimestamp() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
}

uint64_t TelemetryInjector::GetCPUCycles() {
    return __rdtsc();
}

uint64_t TelemetryInjector::GetThreadId() {
    return static_cast<uint64_t>(GetCurrentThreadId());
}

// ============================================================
// ScopedTelemetryTimer
// ============================================================

ScopedTelemetryTimer::ScopedTelemetryTimer(TelemetryInjector& injector, TelemetryEventType type, const char* label)
    : injector_(injector), type_(type), label_(label) {
    start_ = TelemetryInjector::GetTimestamp();
}

ScopedTelemetryTimer::~ScopedTelemetryTimer() {
    if (!cancelled_) {
        uint64_t elapsed = GetElapsed();
        injector_.InjectWithData(type_, elapsed, 0, 0, 0);
    }
}

uint64_t ScopedTelemetryTimer::GetElapsed() const {
    return TelemetryInjector::GetTimestamp() - start_;
}

} // namespace Sovereign
