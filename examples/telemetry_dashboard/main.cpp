/**
 * RawrXD Telemetry Dashboard Example
 *
 * Demonstrates real-time metrics collection and visualization
 * for monitoring inference performance and system health.
 */

#include <rawrxd/RawrXD.hpp>
#include <rawrxd/telemetry/TelemetryCollector.hpp>
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <sstream>

using namespace rawrxd;
using namespace std::chrono_literals;

// Simple HTTP server for dashboard (production would use proper web framework)
class DashboardServer {
public:
    DashboardServer(uint16_t port = 8080) : port_(port), running_(false) {}

    bool Start() {
        std::cout << "Starting dashboard server on http://localhost:" << port_ << std::endl;
        running_ = true;
        // In production, start actual HTTP server here
        return true;
    }

    void Stop() {
        running_ = false;
    }

    void UpdateMetrics(const TelemetrySnapshot& snapshot) {
        latestSnapshot_ = snapshot;
    }

    std::string GetDashboardHTML() const {
        std::stringstream html;
        html << R"(<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Telemetry Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }
        .metric { background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; }
        .metric-title { font-weight: bold; color: #0f3460; }
        .metric-value { font-size: 24px; color: #e94560; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }
        h1 { color: #e94560; }
        .status-ok { color: #4ecca3; }
        .status-warn { color: #f4d03f; }
        .status-error { color: #e74c3c; }
    </style>
    <meta http-equiv="refresh" content="5">
</head>
<body>
    <h1>🚀 RawrXD Telemetry Dashboard</h1>
    <div class="grid">
        <div class="metric">
            <div class="metric-title">Inference Throughput</div>
            <div class="metric-value">)" << std::fixed << std::setprecision(1) << latestSnapshot_.tokensPerSecond << R"( t/s</div>
        </div>
        <div class="metric">
            <div class="metric-title">Latency (P99)</div>
            <div class="metric-value">)" << latestSnapshot_.latencyP99 << R"( ms</div>
        </div>
        <div class="metric">
            <div class="metric-title">Active Sessions</div>
            <div class="metric-value">)" << latestSnapshot_.activeSessions << R"(</div>
        </div>
        <div class="metric">
            <div class="metric-title">Memory Usage</div>
            <div class="metric-value">)" << (latestSnapshot_.memoryUsedMB / 1024.0) << R"( GB</div>
        </div>
        <div class="metric">
            <div class="metric-title">GPU Utilization</div>
            <div class="metric-value">)" << latestSnapshot_.gpuUtilization << R"( %</div>
        </div>
        <div class="metric">
            <div class="metric-title">Queue Depth</div>
            <div class="metric-value">)" << latestSnapshot_.queueDepth << R"(</div>
        </div>
    </div>
    <p>Last updated: )" << latestSnapshot_.timestamp << R"(</p>
</body>
</html>)";
        return html.str();
    }

private:
    uint16_t port_;
    std::atomic<bool> running_;
    TelemetrySnapshot latestSnapshot_;
};

// Print metrics to console in a dashboard format
void PrintDashboard(const TelemetrySnapshot& snapshot) {
    // Clear screen (ANSI escape codes)
    std::cout << "\033[2J\033[H";

    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           RawrXD Real-Time Telemetry Dashboard                 ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";

    // Performance metrics
    std::cout << "║ PERFORMANCE                                                      ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Throughput:    " << std::setw(8) << std::fixed << std::setprecision(1)
              << snapshot.tokensPerSecond << " tokens/s                    ║\n";
    std::cout << "║  Latency P50:   " << std::setw(8) << snapshot.latencyP50 << " ms                              ║\n";
    std::cout << "║  Latency P99:   " << std::setw(8) << snapshot.latencyP99 << " ms                              ║\n";
    std::cout << "║  Queue Depth:   " << std::setw(8) << snapshot.queueDepth << "                                 ║\n";

    // Resource metrics
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ RESOURCES                                                        ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Memory Used:   " << std::setw(8) << std::fixed << std::setprecision(2)
              << (snapshot.memoryUsedMB / 1024.0) << " GB / "
              << std::setw(6) << (snapshot.memoryTotalMB / 1024.0) << " GB         ║\n";
    std::cout << "║  GPU Memory:    " << std::setw(8) << std::fixed << std::setprecision(2)
              << (snapshot.gpuMemoryUsedMB / 1024.0) << " GB / "
              << std::setw(6) << (snapshot.gpuMemoryTotalMB / 1024.0) << " GB         ║\n";
    std::cout << "║  GPU Util:      " << std::setw(8) << snapshot.gpuUtilization << " %                             ║\n";
    std::cout << "║  CPU Util:      " << std::setw(8) << snapshot.cpuUtilization << " %                             ║\n";

    // Session metrics
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ SESSIONS                                                         ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Active:        " << std::setw(8) << snapshot.activeSessions << "                                 ║\n";
    std::cout << "║  Total:         " << std::setw(8) << snapshot.totalSessions << "                                 ║\n";
    std::cout << "║  Errors:        " << std::setw(8) << snapshot.errorCount << "                                 ║\n";

    // Status indicator
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ STATUS: ";
    if (snapshot.errorCount == 0 && snapshot.latencyP99 < 100) {
        std::cout << "🟢 HEALTHY                                      ";
    } else if (snapshot.errorCount < 10 && snapshot.latencyP99 < 500) {
        std::cout << "🟡 WARNING                                       ";
    } else {
        std::cout << "🔴 CRITICAL                                      ";
    }
    std::cout << "║\n";

    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
    std::cout << "  Timestamp: " << snapshot.timestamp << "\n";
    std::cout << "  Press Ctrl+C to exit\n";
}

int main(int argc, char* argv[]) {
    std::cout << "RawrXD Telemetry Dashboard Example\n";
    std::cout << "==================================\n\n";

    // Parse arguments
    bool webMode = false;
    uint16_t webPort = 8080;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--web" || arg == "-w") {
            webMode = true;
        } else if (arg == "--port" && i + 1 < argc) {
            webPort = static_cast<uint16_t>(std::stoi(argv[++i]));
        }
    }

    // Initialize runtime
    auto runtime = Runtime::Create();
    if (!runtime->Initialize()) {
        std::cerr << "Failed to initialize runtime\n";
        return 1;
    }

    std::cout << "✓ Runtime initialized\n";

    // Get telemetry collector
    auto telemetry = runtime->GetTelemetryCollector();
    if (!telemetry) {
        std::cerr << "Telemetry not available\n";
        return 1;
    }

    // Configure telemetry
    TelemetryConfig config;
    config.enabled = true;
    config.metricsInterval = 1s;
    config.exportEndpoint = "";
    config.enableConsoleOutput = false;  // We'll handle output ourselves

    if (!telemetry->Initialize(config)) {
        std::cerr << "Failed to initialize telemetry\n";
        return 1;
    }

    std::cout << "✓ Telemetry initialized\n";

    // Start web server if requested
    std::unique_ptr<DashboardServer> webServer;
    if (webMode) {
        webServer = std::make_unique<DashboardServer>(webPort);
        if (!webServer->Start()) {
            std::cerr << "Failed to start web server\n";
            return 1;
        }
        std::cout << "✓ Web dashboard: http://localhost:" << webPort << "\n";
    }

    std::cout << "\nStarting telemetry collection...\n";
    std::cout << "(Simulating inference workload for demonstration)\n\n";

    // Simulate some inference workload
    std::thread workloadThread([&runtime]() {
        auto model = runtime->LoadModel("demo-model");
        if (!model) return;

        for (int i = 0; i < 1000; ++i) {
            auto session = runtime->CreateSession(model);
            if (session) {
                // Simulate inference
                std::this_thread::sleep_for(10ms);
                session->Complete("Test prompt " + std::to_string(i));
            }
            std::this_thread::sleep_for(50ms);
        }
    });

    // Main display loop
    bool running = true;
    while (running) {
        auto snapshot = telemetry->GetSnapshot();

        if (webMode && webServer) {
            webServer->UpdateMetrics(snapshot);
            std::cout << "Web dashboard: http://localhost:" << webPort
                      << " (refresh to see updates)\r" << std::flush;
        } else {
            PrintDashboard(snapshot);
        }

        std::this_thread::sleep_for(1s);
    }

    // Cleanup
    if (webServer) {
        webServer->Stop();
    }

    workloadThread.join();
    telemetry->Shutdown();
    runtime->Shutdown();

    std::cout << "\n✓ Telemetry dashboard stopped\n";
    return 0;
}
