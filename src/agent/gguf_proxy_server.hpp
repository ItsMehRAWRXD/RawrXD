/**
 * @file gguf_proxy_server.hpp
 * @brief TCP proxy between IDE-agent and GGUF model server (Qt-free, WinSock)
 */
#pragma once

<<<<<<< HEAD
#include <string>
#include <map>
#include <vector>
#include <mutex>
#include <memory>
#include <functional>
#include <nlohmann/json.hpp>
#include <cstdint>

class AgentHotPatcher;

struct ClientConnection {
    uintptr_t clientSocket = 0;
    uintptr_t ggufSocket = 0;
=======
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

// Link against ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

class AgentHotPatcher;

struct ClientConnection {
    SOCKET clientSocket = INVALID_SOCKET;
    SOCKET ggufSocket = INVALID_SOCKET;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::vector<uint8_t> requestBuffer;
    std::vector<uint8_t> responseBuffer;
};

class GGUFProxyServer {
public:
<<<<<<< HEAD
    GGUFProxyServer() = default;
    ~GGUFProxyServer();
    GGUFProxyServer(const GGUFProxyServer&) = delete;
    GGUFProxyServer& operator=(const GGUFProxyServer&) = delete;

    void initialize(int listenPort, AgentHotPatcher* hotPatcher, const std::string& ggufEndpoint);
    bool startServer();
    void stopServer();
    bool isListening() const;
    int getPort() const { return m_listenPort; }
    int getActiveConnections() const { return m_activeConnections; }
    nlohmann::json getServerStatistics() const;
    void setConnectionPoolSize(int size);
    void setConnectionTimeout(int ms);
    std::string parseIncomingRequest(const std::vector<uint8_t>& data);

    // Callbacks (replace Qt signals)
    std::function<void(int)> onServerStarted;
    std::function<void()> onServerStopped;

private:
    void handleIncomingConnection(uintptr_t socketDescriptor);
    void forwardToGGUF(uintptr_t socketDescriptor);
    void processGGUFResponse(uintptr_t socketDescriptor);
    void sendResponseToClient(uintptr_t socketDescriptor, const std::string& response);
=======
    GGUFProxyServer();
    ~GGUFProxyServer();

    // No copy
    GGUFProxyServer(const GGUFProxyServer&) = delete;
    GGUFProxyServer& operator=(const GGUFProxyServer&) = delete;

    void initialize(int listenPort, AgentHotPatcher* hotPatcher, const std::string& ggufEndpoint);
    
    // Returns true if started
    bool startServer();
    void stopServer();

    bool isListening() const { return m_isListening; }

    // Statistics json string
    std::string getServerStatistics() const;

private:
    void acceptLoop();
    void handleClient(SOCKET clientSocket);
    SOCKET connectToBackend();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    int m_listenPort = 0;
    std::string m_ggufEndpoint;
    AgentHotPatcher* m_hotPatcher = nullptr;
<<<<<<< HEAD
    uintptr_t m_listenSocket = 0;
    bool m_listening = false;
    std::map<uintptr_t, std::unique_ptr<ClientConnection>> m_connections;
    int m_connectionPoolSize = 10;
    int m_connectionTimeout = 5000;
    mutable std::mutex m_statsMutex;
    int64_t m_requestsProcessed = 0;
    int64_t m_hallucinationsCorrected = 0;
    int64_t m_navigationErrorsFixed = 0;
    int m_activeConnections = 0;
=======
    
    SOCKET m_listenSocket = INVALID_SOCKET;
    std::atomic<bool> m_isListening{false};
    std::thread m_acceptThread;
    
    mutable std::mutex m_mutex;
    std::vector<std::thread> m_clientThreads; // Or detach?
    
    std::atomic<long long> m_requestsProcessed{0};
    std::atomic<long long> m_bytesTransferred{0};
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};
