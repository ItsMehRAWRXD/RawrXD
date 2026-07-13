#pragma once

/**
 * TelemetryDashboardServer.hpp
 * 
 * Phase B.2 Batch 4/5: Live Dashboard WebSocket Server
 * 
 * Real-time telemetry streaming for dashboard visualization.
 * Exposes Unity Cycle metrics via WebSocket for live updates.
 */

#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <functional>
#include <memory>

// Forward declarations
namespace InfinitePerfection { class InfinitePerfectionEngine; }

namespace Sovereign {

// Forward declarations
struct UnityCycleTelemetry;
struct InfinitePerfectionTelemetrySnapshot;

/**
 * WebSocket client connection
 */
struct DashboardClient {
    int socketFd = -1;
    std::string clientId;
    int64_t connectedAt = 0;
    bool isSubscribed = false;
};

/**
 * Dashboard server configuration
 */
struct DashboardConfig {
    uint16_t port = 8080;
    int updateIntervalMs = 1000;  // Telemetry broadcast interval
    int maxClients = 100;
    bool enableCors = true;
    std::string allowedOrigins = "*";
};

/**
 * WebSocket server for real-time telemetry streaming
 */
class TelemetryDashboardServer {
public:
    explicit TelemetryDashboardServer(
        InfinitePerfection::InfinitePerfectionEngine* engine,
        const DashboardConfig& config = DashboardConfig{}
    );
    ~TelemetryDashboardServer();
    
    // Start the server
    bool Start();
    
    // Stop the server
    void Stop();
    
    // Check if server is running
    bool IsRunning() const { return running_.load(); }
    
    // Get server port
    uint16_t GetPort() const { return config_.port; }
    
    // Get connected client count
    int GetClientCount() const;
    
    // Broadcast telemetry to all subscribed clients
    void BroadcastTelemetry(const InfinitePerfectionTelemetrySnapshot& snapshot);
    
    // Send event to specific client
    void SendEvent(int clientSocket, const std::string& eventType, const std::string& data);
    
    // Get server status as JSON
    std::string GetStatusJson() const;
    
private:
    InfinitePerfection::InfinitePerfectionEngine* engine_;
    DashboardConfig config_;
    
    std::atomic<bool> running_{false};
    std::atomic<bool> shouldStop_{false};
    
    int serverSocket_ = -1;
    std::thread acceptThread_;
    std::thread broadcastThread_;
    
    mutable std::mutex clientsMutex_;
    std::vector<DashboardClient> clients_;
    
    // Server loop
    void AcceptLoop();
    void BroadcastLoop();
    
    // Client handling
    void HandleClient(int clientSocket);
    void RemoveClient(int clientSocket);
    
    // WebSocket protocol
    bool PerformHandshake(int clientSocket);
    std::string ParseWebSocketFrame(const std::vector<uint8_t>& data);
    std::vector<uint8_t> CreateWebSocketFrame(const std::string& message);
    
    // HTTP helpers
    void SendHttpResponse(int clientSocket, int status, const std::string& content);
    void SendWebSocketUpgrade(int clientSocket, const std::string& key);
    
    // Message handlers
    void HandleSubscribe(int clientSocket);
    void HandleUnsubscribe(int clientSocket);
    void HandleGetSnapshot(int clientSocket);
    void HandleGetHistory(int clientSocket, int count);
    
    // Utility
    std::string GenerateClientId();
    std::string CreateEventJson(const std::string& eventType, const std::string& data);
};

} // namespace Sovereign
