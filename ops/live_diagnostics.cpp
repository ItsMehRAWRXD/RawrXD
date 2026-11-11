#include "live_diagnostics.hpp"
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>

namespace RawrXD::Ops {

LiveDiagnostics::LiveDiagnostics() = default;
LiveDiagnostics::~LiveDiagnostics() {
    StopWebSocketServer();
}

LiveDiagnostics::SystemSnapshot LiveDiagnostics::Capture() {
    SystemSnapshot snap;
    
    // CPU usage (simplified - in production use PDH or WMI)
    snap.cpu_percent = 50.0; // placeholder
    
    // Memory
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    if (GlobalMemoryStatusEx(&mem_status)) {
        snap.memory_gb = static_cast<double>(mem_status.ullTotalPhys) / (1024.0 * 1024.0 * 1024.0);
    }
    
    // GPU (placeholder - would use NVML or ADL)
    snap.gpu_util_percent = 45.0;
    snap.gpu_memory_gb = 24.0;
    
    // Runtime stats
    snap.active_agents = 8;
    snap.loaded_models = 3;
    snap.avg_latency_ms = 125.0;
    snap.throughput_tps = 915.0;
    
    return snap;
}

void LiveDiagnostics::StartWebSocketServer(int port) {
    port_ = port;
    streaming_ = true;
    running_ = true;
    
    poll_thread_ = std::make_unique<std::thread>([this]() { PollingLoop(); });
    ws_thread_ = std::make_unique<std::thread>([this]() {
        // WebSocket server would be initialized here
        // For now, we just broadcast via callback
        while (running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
}

void LiveDiagnostics::StopWebSocketServer() {
    running_ = false;
    streaming_ = false;
    if (poll_thread_ && poll_thread_->joinable()) poll_thread_->join();
    if (ws_thread_ && ws_thread_->joinable()) ws_thread_->join();
}

void LiveDiagnostics::SetSnapshotCallback(SnapshotCallback cb) {
    callback_ = std::move(cb);
}

void LiveDiagnostics::SetPollIntervalMs(int ms) {
    poll_interval_ms_ = ms;
}

void LiveDiagnostics::PollingLoop() {
    while (running_) {
        auto snap = Capture();
        BroadcastSnapshot(snap);
        std::this_thread::sleep_for(std::chrono::milliseconds(poll_interval_ms_));
    }
}

void LiveDiagnostics::BroadcastSnapshot(const SystemSnapshot& snap) {
    if (callback_) {
        callback_(snap);
    }
}

} // namespace RawrXD::Ops
