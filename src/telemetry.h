#pragma once

#include <QString>
#include <QJsonObject>
#include <QJsonArray>
#include <QObject>
#include <cstdint>
#include <string>
#include <chrono>
#include <memory>
#include <mutex>

// Telemetry snapshot structure
struct TelemetrySnapshot {
    uint64_t timeMs = 0;
    
    // CPU metrics
    bool cpuTempValid = false;
    double cpuTempC = 0.0;
    double cpuUsagePercent = 0.0;
    
    // GPU metrics
    bool gpuTempValid = false;
    double gpuTempC = 0.0;
    double gpuUsagePercent = 0.0;
    std::string gpuVendor;
    
    // Memory metrics
    bool memValid = false;
    uint64_t totalMemoryBytes = 0;
    uint64_t usedMemoryBytes = 0;
    double memUsagePercent = 0.0;
    
    // Disk I/O
    bool diskValid = false;
    uint64_t diskReadBytes = 0;
    uint64_t diskWriteBytes = 0;
    
    // Network
    bool netValid = false;
    uint64_t netSentBytes = 0;
    uint64_t netRecvBytes = 0;
    
    // Custom metrics (extensible)
    std::unordered_map<std::string, double> customMetrics;
    
    // Timing
    std::chrono::system_clock::time_point timestamp;
    uint64_t sequenceNumber = 0;
};

// GetSnapshot - retrieves current telemetry snapshot
// Returns true if snapshot is valid (has been populated)
bool GetSnapshot(TelemetrySnapshot& out);

namespace telemetry {
    bool Initialize();
    bool InitializeHardware();  // Two-phase init: call after QApplication exists
    bool Poll(TelemetrySnapshot& out);
    void Shutdown();
    
    // GetSnapshot - alias for ::GetSnapshot
    inline bool GetSnapshot(TelemetrySnapshot& out) {
        return ::GetSnapshot(out);
    }
}

class Telemetry : public QObject {
    Q_OBJECT
public:
    Telemetry();
    ~Telemetry();
    
    // Two-phase initialization: call this after QApplication is running
    void initializeHardware();
    
    void recordEvent(const QString& event_name, const QJsonObject& metadata = QJsonObject());
    bool saveTelemetry(const QString& filepath);
    void enableTelemetry(bool enable);
    
    // GetSnapshot - retrieves current telemetry snapshot
    // Returns true if snapshot is valid (has been populated)
    bool GetSnapshot(TelemetrySnapshot& out) const;
    
    // GetSnapshot - non-const version for internal use
    bool GetSnapshot(TelemetrySnapshot& out);

private:
    bool is_enabled_ = false;
    QJsonArray events_;
    std::mutex mutex_;
    TelemetrySnapshot lastSnapshot_;
    bool snapshotValid_ = false;
};
