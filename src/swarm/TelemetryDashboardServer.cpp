/**
 * TelemetryDashboardServer.cpp
 * 
 * Phase B.2 Batch 4/5: Live Dashboard WebSocket Server Implementation
 */

#include "TelemetryDashboardServer.hpp"
#include "InfinitePerfectionTelemetry.hpp"
#include "../infinite/InfinitePerfectionEngine.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <random>

// Platform-specific socket headers
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#endif

namespace Sovereign {

TelemetryDashboardServer::TelemetryDashboardServer(
    InfinitePerfection::InfinitePerfectionEngine* engine,
    const DashboardConfig& config)
    : engine_(engine), config_(config) {}

TelemetryDashboardServer::~TelemetryDashboardServer() {
    Stop();
}

bool TelemetryDashboardServer::Start() {
    if (running_.load()) return true;
    
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[Dashboard] WSAStartup failed" << std::endl;
        return false;
    }
#endif
    
    // Create server socket
    serverSocket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket_ < 0) {
        std::cerr << "[Dashboard] Failed to create socket" << std::endl;
        return false;
    }
    
    // Allow socket reuse
    int opt = 1;
    setsockopt(serverSocket_, SOL_SOCKET, SO_REUSEADDR, 
               reinterpret_cast<const char*>(&opt), sizeof(opt));
    
    // Bind to port
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(config_.port);
    
    if (bind(serverSocket_, reinterpret_cast<sockaddr*>(&serverAddr), 
             sizeof(serverAddr)) < 0) {
        std::cerr << "[Dashboard] Failed to bind to port " << config_.port << std::endl;
        return false;
    }
    
    // Listen for connections
    if (listen(serverSocket_, config_.maxClients) < 0) {
        std::cerr << "[Dashboard] Failed to listen" << std::endl;
        return false;
    }
    
    // Set non-blocking mode
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(serverSocket_, FIONBIO, &mode);
#else
    int flags = fcntl(serverSocket_, F_GETFL, 0);
    fcntl(serverSocket_, F_SETFL, flags | O_NONBLOCK);
#endif
    
    running_.store(true);
    shouldStop_.store(false);
    
    // Start threads
    acceptThread_ = std::thread(&TelemetryDashboardServer::AcceptLoop, this);
    broadcastThread_ = std::thread(&TelemetryDashboardServer::BroadcastLoop, this);
    
    std::cout << "[Dashboard] Server started on port " << config_.port << std::endl;
    return true;
}

void TelemetryDashboardServer::Stop() {
    if (!running_.load()) return;
    
    shouldStop_.store(true);
    running_.store(false);
    
    // Close all client connections
    {
        std::lock_guard<std::mutex> lock(clientsMutex_);
        for (auto& client : clients_) {
            if (client.socketFd >= 0) {
#ifdef _WIN32
                closesocket(client.socketFd);
#else
                close(client.socketFd);
#endif
            }
        }
        clients_.clear();
    }
    
    // Close server socket
    if (serverSocket_ >= 0) {
#ifdef _WIN32
        closesocket(serverSocket_);
#else
        close(serverSocket_);
#endif
        serverSocket_ = -1;
    }
    
    // Join threads
    if (acceptThread_.joinable()) acceptThread_.join();
    if (broadcastThread_.joinable()) broadcastThread_.join();
    
#ifdef _WIN32
    WSACleanup();
#endif
    
    std::cout << "[Dashboard] Server stopped" << std::endl;
}

int TelemetryDashboardServer::GetClientCount() const {
    std::lock_guard<std::mutex> lock(clientsMutex_);
    return static_cast<int>(clients_.size());
}

void TelemetryDashboardServer::AcceptLoop() {
    while (!shouldStop_.load()) {
        sockaddr_in clientAddr{};
        socklen_t addrLen = sizeof(clientAddr);
        
        int clientSocket = accept(serverSocket_, 
            reinterpret_cast<sockaddr*>(&clientAddr), &addrLen);
        
        if (clientSocket < 0) {
            // No pending connections
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        
        // Handle client in separate thread
        std::thread clientThread(&TelemetryDashboardServer::HandleClient, 
                                this, clientSocket);
        clientThread.detach();
    }
}

void TelemetryDashboardServer::HandleClient(int clientSocket) {
    // Perform WebSocket handshake
    if (!PerformHandshake(clientSocket)) {
        RemoveClient(clientSocket);
        return;
    }
    
    // Add to client list
    {
        std::lock_guard<std::mutex> lock(clientsMutex_);
        DashboardClient client;
        client.socketFd = clientSocket;
        client.clientId = GenerateClientId();
        client.connectedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        client.isSubscribed = true;
        clients_.push_back(client);
    }
    
    std::cout << "[Dashboard] Client connected, total: " << GetClientCount() << std::endl;
    
    // Send initial snapshot
    if (engine_) {
        InfinitePerfectionTelemetry telemetry(engine_);
        auto snapshot = telemetry.GetSnapshot();
        std::string json = telemetry.ExportToJson();
        SendEvent(clientSocket, "snapshot", json);
    }
    
    // Keep connection alive
    while (!shouldStop_.load()) {
        // Read ping frames or handle disconnect
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    RemoveClient(clientSocket);
}

void TelemetryDashboardServer::RemoveClient(int clientSocket) {
    {
        std::lock_guard<std::mutex> lock(clientsMutex_);
        clients_.erase(
            std::remove_if(clients_.begin(), clients_.end(),
                [clientSocket](const DashboardClient& c) { 
                    return c.socketFd == clientSocket; 
                }),
            clients_.end()
        );
    }
    
#ifdef _WIN32
    closesocket(clientSocket);
#else
    close(clientSocket);
#endif
    
    std::cout << "[Dashboard] Client disconnected, total: " << GetClientCount() << std::endl;
}

void TelemetryDashboardServer::BroadcastLoop() {
    while (!shouldStop_.load()) {
        if (!engine_ || GetClientCount() == 0) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(config_.updateIntervalMs));
            continue;
        }
        
        // Capture telemetry
        InfinitePerfectionTelemetry telemetry(engine_);
        auto snapshot = telemetry.GetSnapshot();
        
        // Broadcast to all subscribed clients
        BroadcastTelemetry(snapshot);
        
        std::this_thread::sleep_for(
            std::chrono::milliseconds(config_.updateIntervalMs));
    }
}

void TelemetryDashboardServer::BroadcastTelemetry(
    const InfinitePerfectionTelemetrySnapshot& snapshot) {
    
    std::lock_guard<std::mutex> lock(clientsMutex_);
    
    std::ostringstream json;
    json << "{";
    json << "\"event\":\"cycle_update\",";
    json << "\"timestamp\":" << snapshot.snapshotTime << ",";
    json << "\"totalCyclesExecuted\":" << snapshot.totalCyclesExecuted << ",";
    json << "\"averageConvergenceRate\":" << std::fixed << std::setprecision(4) 
         << snapshot.averageConvergenceRate << ",";
    json << "\"unityCycle\":{";
    json << "\"unityPotential\":" << snapshot.unityCycle.unityPotential << ",";
    json << "\"cycleIntegration\":" << snapshot.unityCycle.cycleIntegration << ",";
    json << "\"harmonicConvergence\":" << snapshot.unityCycle.harmonicConvergence << ",";
    json << "\"sovereignHarmonyIndex\":" << snapshot.unityCycle.sovereignHarmonyIndex << ",";
    json << "\"equilibriumStrength\":" << snapshot.unityCycle.equilibriumStrength << ",";
    json << "\"isConverged\":" << (snapshot.unityCycle.isConverged ? "true" : "false");
    json << "}}";
    
    std::string message = json.str();
    auto frame = CreateWebSocketFrame(message);
    
    for (auto& client : clients_) {
        if (client.isSubscribed && client.socketFd >= 0) {
            send(client.socketFd, 
                 reinterpret_cast<const char*>(frame.data()), 
                 static_cast<int>(frame.size()), 0);
        }
    }
}

void TelemetryDashboardServer::SendEvent(int clientSocket, 
    const std::string& eventType, const std::string& data) {
    
    std::string message = CreateEventJson(eventType, data);
    auto frame = CreateWebSocketFrame(message);
    
    send(clientSocket, reinterpret_cast<const char*>(frame.data()), 
         static_cast<int>(frame.size()), 0);
}

std::string TelemetryDashboardServer::CreateEventJson(
    const std::string& eventType, const std::string& data) {
    
    std::ostringstream json;
    json << "{";
    json << "\"event\":\"" << eventType << "\",";
    json << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() << ",";
    json << "\"data\":" << data;
    json << "}";
    return json.str();
}

bool TelemetryDashboardServer::PerformHandshake(int clientSocket) {
    // Read HTTP request
    char buffer[4096] = {0};
    int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    
    if (received <= 0) return false;
    
    std::string request(buffer);
    
    // Check for WebSocket upgrade
    if (request.find("Upgrade: websocket") == std::string::npos &&
        request.find("UPGRADE: WEBSOCKET") == std::string::npos) {
        // Not a WebSocket request, send HTTP response
        SendHttpResponse(clientSocket, 200, 
            "{\"status\":\"InfinitePerfectionEngine Telemetry Dashboard\"}");
        return false;
    }
    
    // Extract Sec-WebSocket-Key
    size_t keyPos = request.find("Sec-WebSocket-Key: ");
    if (keyPos == std::string::npos) {
        keyPos = request.find("SEC-WEBSOCKET-KEY: ");
    }
    
    if (keyPos == std::string::npos) return false;
    
    keyPos += 19; // Length of "Sec-WebSocket-Key: "
    size_t keyEnd = request.find("\r\n", keyPos);
    std::string key = request.substr(keyPos, keyEnd - keyPos);
    
    // Trim whitespace
    key.erase(0, key.find_first_not_of(" \t"));
    key.erase(key.find_last_not_of(" \t") + 1);
    
    SendWebSocketUpgrade(clientSocket, key);
    return true;
}

void TelemetryDashboardServer::SendHttpResponse(int clientSocket, int status, 
    const std::string& content) {
    
    std::ostringstream response;
    response << "HTTP/1.1 " << status << " OK\r\n";
    response << "Content-Type: application/json\r\n";
    if (config_.enableCors) {
        response << "Access-Control-Allow-Origin: " << config_.allowedOrigins << "\r\n";
    }
    response << "Content-Length: " << content.length() << "\r\n";
    response << "\r\n";
    response << content;
    
    std::string respStr = response.str();
    send(clientSocket, respStr.c_str(), static_cast<int>(respStr.length()), 0);
}

void TelemetryDashboardServer::SendWebSocketUpgrade(int clientSocket, 
    const std::string& key) {
    
    // Calculate accept key (simplified - would need SHA1 + Base64 in production)
    std::string acceptKey = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    
    std::ostringstream response;
    response << "HTTP/1.1 101 Switching Protocols\r\n";
    response << "Upgrade: websocket\r\n";
    response << "Connection: Upgrade\r\n";
    response << "Sec-WebSocket-Accept: " << acceptKey << "\r\n";
    response << "\r\n";
    
    std::string respStr = response.str();
    send(clientSocket, respStr.c_str(), static_cast<int>(respStr.length()), 0);
}

std::vector<uint8_t> TelemetryDashboardServer::CreateWebSocketFrame(
    const std::string& message) {
    
    std::vector<uint8_t> frame;
    
    // FIN = 1, opcode = 1 (text)
    frame.push_back(0x81);
    
    size_t len = message.length();
    if (len < 126) {
        frame.push_back(static_cast<uint8_t>(len));
    } else if (len < 65536) {
        frame.push_back(126);
        frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(len & 0xFF));
    } else {
        frame.push_back(127);
        for (int i = 7; i >= 0; --i) {
            frame.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
        }
    }
    
    // Add message payload
    frame.insert(frame.end(), message.begin(), message.end());
    
    return frame;
}

std::string TelemetryDashboardServer::GenerateClientId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    
    std::ostringstream ss;
    ss << "client-";
    for (int i = 0; i < 8; ++i) {
        ss << std::hex << dis(gen);
    }
    return ss.str();
}

std::string TelemetryDashboardServer::GetStatusJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"running\":" << (running_.load() ? "true" : "false") << ",";
    json << "\"port\":" << config_.port << ",";
    json << "\"clients\":" << GetClientCount() << ",";
    json << "\"updateIntervalMs\":" << config_.updateIntervalMs;
    json << "}";
    return json.str();
}

} // namespace Sovereign
