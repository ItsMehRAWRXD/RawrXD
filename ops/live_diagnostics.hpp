#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <thread>
#include <atomic>

namespace RawrXD::Ops {

class LiveDiagnostics {
public:
    struct SystemSnapshot {
        double cpu_percent = 0.0;
        double memory_gb = 0.0;
        double gpu_util_percent = 0.0;
        double gpu_memory_gb = 0.0;
        size_t active_agents = 0;
        size_t loaded_models = 0;
        double avg_latency_ms = 0.0;
        double throughput_tps = 0.0;
        int64_t uptime_seconds = 0;
    };

    LiveDiagnostics();
    ~LiveDiagnostics();

    SystemSnapshot Capture();
    void StartWebSocketServer(int port = 9550);
    void StopWebSocketServer();
    bool IsStreaming() const { return streaming_; }

    using SnapshotCallback = std::function<void(const SystemSnapshot&)>;
    void SetSnapshotCallback(SnapshotCallback cb);
    void SetPollIntervalMs(int ms);

private:
    void PollingLoop();
    void BroadcastSnapshot(const SystemSnapshot& snap);

    std::atomic<bool> streaming_{false};
    std::atomic<bool> running_{false};
    int port_ = 9550;
    int poll_interval_ms_ = 1000;
    std::unique_ptr<std::thread> poll_thread_;
    std::unique_ptr<std::thread> ws_thread_;
    SnapshotCallback callback_;
};

} // namespace RawrXD::Ops
