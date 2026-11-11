// realtime_updates.cpp
// Batch 11: Real-time Update System
//
// WebSocket server for live benchmark updates
// Features: Broadcasting, client management, event streaming

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <condition_variable>

namespace Benchmark {
namespace Dashboard {

// WebSocket message types
enum class WSMessageType {
    TEXT,
    BINARY,
    CLOSE,
    PING,
    PONG
};

// WebSocket frame
struct WSFrame {
    WSMessageType type;
    std::string payload;
    bool fin = true;
};

// Client connection
class WSClient {
public:
    WSClient(int id) : id_(id), connected_(true) {}
    
    int GetId() const { return id_; }
    bool IsConnected() const { return connected_; }
    void Disconnect() { connected_ = false; }
    
    void Send(const std::string& message) {
        if (connected_) {
            std::lock_guard<std::mutex> lock(send_mutex_);
            send_queue_.push(message);
        }
    }
    
    bool HasPendingMessages() {
        std::lock_guard<std::mutex> lock(send_mutex_);
        return !send_queue_.empty();
    }
    
    std::string GetNextMessage() {
        std::lock_guard<std::mutex> lock(send_mutex_);
        if (send_queue_.empty()) return "";
        std::string msg = send_queue_.front();
        send_queue_.pop();
        return msg;
    }

private:
    int id_;
    std::atomic<bool> connected_;
    std::queue<std::string> send_queue_;
    std::mutex send_mutex_;
};

// Real-time update server
class RealtimeUpdateServer {
public:
    struct Config {
        int port = 8081;
        int max_clients = 100;
        int ping_interval_ms = 30000;
    };

    explicit RealtimeUpdateServer(const Config& config = Config())
        : config_(config), running_(false), next_client_id_(1) {}

    ~RealtimeUpdateServer() {
        Stop();
    }

    // Start server
    bool Start() {
        if (running_) return true;
        
        running_ = true;
        
        // Start server thread
        server_thread_ = std::thread(&RealtimeUpdateServer::ServerLoop, this);
        
        // Start ping thread
        ping_thread_ = std::thread(&RealtimeUpdateServer::PingLoop, this);
        
        // Start broadcast thread
        broadcast_thread_ = std::thread(&RealtimeUpdateServer::BroadcastLoop, this);
        
        return true;
    }

    // Stop server
    void Stop() {
        running_ = false;
        cv_.notify_all();
        
        if (server_thread_.joinable()) server_thread_.join();
        if (ping_thread_.joinable()) ping_thread_.join();
        if (broadcast_thread_.joinable()) broadcast_thread_.join();
        
        // Disconnect all clients
        std::lock_guard<std::mutex> lock(clients_mutex_);
        for (auto& [id, client] : clients_) {
            client->Disconnect();
        }
        clients_.clear();
    }

    // Broadcast message to all clients
    void Broadcast(const std::string& message) {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        for (auto& [id, client] : clients_) {
            if (client->IsConnected()) {
                client->Send(message);
            }
        }
    }

    // Send to specific client
    void SendTo(int client_id, const std::string& message) {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        auto it = clients_.find(client_id);
        if (it != clients_.end() && it->second->IsConnected()) {
            it->second->Send(message);
        }
    }

    // Broadcast benchmark update
    void BroadcastBenchmarkUpdate(const std::string& benchmark_id,
                                   const std::string& status,
                                   const std::string& data) {
        std::string message = "{"
            "\"type\": \"benchmark_update\","
            "\"benchmark_id\": \"" + benchmark_id + "\","
            "\"status\": \"" + status + "\","
            "\"data\": " + data + ","
            "\"timestamp\": " + std::to_string(GetTimestamp()) +
        "}";
        
        Broadcast(message);
    }

    // Broadcast system metrics
    void BroadcastSystemMetrics(const std::string& metrics_json) {
        std::string message = "{"
            "\"type\": \"system_metrics\","
            "\"metrics\": " + metrics_json + ","
            "\"timestamp\": " + std::to_string(GetTimestamp()) +
        "}";
        
        Broadcast(message);
    }

    // Get connected client count
    int GetClientCount() {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        int count = 0;
        for (const auto& [id, client] : clients_) {
            if (client->IsConnected()) ++count;
        }
        return count;
    }

    // Set event handler
    using EventHandler = std::function<void(int client_id, const std::string& event)>;
    void SetEventHandler(EventHandler handler) {
        event_handler_ = handler;
    }

private:
    Config config_;
    std::atomic<bool> running_;
    std::atomic<int> next_client_id_;
    
    std::map<int, std::shared_ptr<WSClient>> clients_;
    std::mutex clients_mutex_;
    
    std::thread server_thread_;
    std::thread ping_thread_;
    std::thread broadcast_thread_;
    
    std::condition_variable cv_;
    
    EventHandler event_handler_;

    void ServerLoop() {
        // In production: Use actual WebSocket server library
        // This is a simplified placeholder
        
        while (running_) {
            // Accept new connections
            // Handle client messages
            // Process disconnections
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    void PingLoop() {
        while (running_) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(config_.ping_interval_ms));
            
            if (!running_) break;
            
            // Send ping to all clients
            Broadcast(R"({"type": "ping"})");
            
            // Clean up disconnected clients
            CleanupDisconnectedClients();
        }
    }

    void BroadcastLoop() {
        while (running_) {
            std::unique_lock<std::mutex> lock(clients_mutex_);
            cv_.wait_for(lock, std::chrono::milliseconds(100));
            
            if (!running_) break;
            
            // Process pending messages for each client
            for (auto& [id, client] : clients_) {
                if (client->IsConnected()) {
                    while (client->HasPendingMessages()) {
                        std::string msg = client->GetNextMessage();
                        // Send to client
                    }
                }
            }
        }
    }

    void CleanupDisconnectedClients() {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        for (auto it = clients_.begin(); it != clients_.end();) {
            if (!it->second->IsConnected()) {
                it = clients_.erase(it);
            } else {
                ++it;
            }
        }
    }

    int64_t GetTimestamp() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    // WebSocket protocol helpers
    std::string EncodeFrame(const WSFrame& frame) {
        // In production: Proper WebSocket frame encoding
        return frame.payload;
    }

    WSFrame DecodeFrame(const std::string& data) {
        // In production: Proper WebSocket frame decoding
        WSFrame frame;
        frame.type = WSMessageType::TEXT;
        frame.payload = data;
        return frame;
    }

    void HandleWebSocketHandshake(int client_socket) {
        // In production: Complete WebSocket handshake
    }
};

// Event broadcaster for benchmark events
class BenchmarkEventBroadcaster {
public:
    static BenchmarkEventBroadcaster& Instance() {
        static BenchmarkEventBroadcaster instance;
        return instance;
    }

    void Initialize(RealtimeUpdateServer* server) {
        server_ = server;
    }

    void BroadcastBenchmarkStarted(const std::string& benchmark_id,
                                   const std::string& config_json) {
        if (server_) {
            server_->BroadcastBenchmarkUpdate(benchmark_id, "started", config_json);
        }
    }

    void BroadcastBenchmarkProgress(const std::string& benchmark_id,
                                     int iteration,
                                     int total,
                                     double current_value) {
        if (server_) {
            std::string data = "{"
                "\"iteration\": " + std::to_string(iteration) + ","
                "\"total\": " + std::to_string(total) + ","
                "\"current_value\": " + std::to_string(current_value) +
            "}";
            server_->BroadcastBenchmarkUpdate(benchmark_id, "progress", data);
        }
    }

    void BroadcastBenchmarkCompleted(const std::string& benchmark_id,
                                      const std::string& results_json) {
        if (server_) {
            server_->BroadcastBenchmarkUpdate(benchmark_id, "completed", results_json);
        }
    }

    void BroadcastBenchmarkError(const std::string& benchmark_id,
                                  const std::string& error_message) {
        if (server_) {
            std::string data = "{\"error\": \"" + error_message + "\"}";
            server_->BroadcastBenchmarkUpdate(benchmark_id, "error", data);
        }
    }

    void BroadcastSystemUpdate() {
        if (server_) {
            // Get current system metrics
            std::string metrics = DataAPI::GetSystemMetrics();
            server_->BroadcastSystemMetrics(metrics);
        }
    }

private:
    BenchmarkEventBroadcaster() = default;
    RealtimeUpdateServer* server_ = nullptr;
};

// Periodic system metrics broadcaster
class SystemMetricsBroadcaster {
public:
    void Start(int interval_ms = 5000) {
        running_ = true;
        thread_ = std::thread([this, interval_ms]() {
            while (running_) {
                BenchmarkEventBroadcaster::Instance().BroadcastSystemUpdate();
                std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
            }
        });
    }

    void Stop() {
        running_ = false;
        if (thread_.joinable()) {
            thread_.join();
        }
    }

private:
    std::atomic<bool> running_{false};
    std::thread thread_;
};

} // namespace Dashboard
} // namespace Benchmark
