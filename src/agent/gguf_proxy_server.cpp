<<<<<<< HEAD
/**
 * @file gguf_proxy_server.cpp
 * @brief TCP proxy between IDE agent and GGUF model server (Qt-free, WinSock)
 */
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#include "gguf_proxy_server.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
   using SocketType = SOCKET;
   constexpr SocketType kInvalidSocket = INVALID_SOCKET;
#else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
   using SocketType = int;
   constexpr SocketType kInvalidSocket = -1;
   inline int closesocket(int fd) { return ::close(fd); }
#endif

#include <nlohmann/json.hpp>
#include "agent_hot_patcher.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <nlohmann/json.hpp>
#include <regex>
#include <cctype>
#include <WS2tcpip.h>

<<<<<<< HEAD
using json = nlohmann::json;

namespace {

#ifdef _WIN32
struct WinsockInit {
    WinsockInit() {
        WSADATA wd;
        WSAStartup(MAKEWORD(2, 2), &wd);
    }
    ~WinsockInit() { WSACleanup(); }
};
static WinsockInit s_wsInit;
#endif

void parseHostPort(const std::string& ep, std::string& host, int& port) {
    auto colon = ep.rfind(':');
    if (colon != std::string::npos) {
        host = ep.substr(0, colon);
        port = std::atoi(ep.substr(colon + 1).c_str());
    } else {
        host = ep;
        port = 11434;
    }
}

} // namespace

// ---------------------------------------------------------------------------
GGUFProxyServer::~GGUFProxyServer() {
    try { stopServer(); } catch (...) {
        fprintf(stderr, "[WARN] [GGUFProxyServer] Exception during destruction\n");
    }
}

void GGUFProxyServer::initialize(int listenPort, AgentHotPatcher* hotPatcher,
                                 const std::string& ggufEndpoint) {
    if (listenPort <= 0 || listenPort > 65535) {
        fprintf(stderr, "[CRIT] [GGUFProxyServer] Invalid port: %d\n", listenPort);
        return;
    }
    m_listenPort   = listenPort;
    m_hotPatcher   = hotPatcher;
    m_ggufEndpoint = ggufEndpoint;
    fprintf(stderr, "[INFO] [GGUFProxyServer] Initialized – port: %d, endpoint: %s\n",
            listenPort, ggufEndpoint.c_str());
}

bool GGUFProxyServer::startServer() {
    if (m_listening) {
        fprintf(stderr, "[INFO] [GGUFProxyServer] Already listening on port %d\n", m_listenPort);
        return true;
    }

    auto sock = static_cast<SocketType>(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (sock == kInvalidSocket) {
        fprintf(stderr, "[WARN] [GGUFProxyServer] socket() failed\n");
        return false;
    }

    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&optval), sizeof(optval));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(static_cast<uint16_t>(m_listenPort));

    if (::bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        fprintf(stderr, "[WARN] [GGUFProxyServer] bind() failed on port %d\n", m_listenPort);
        closesocket(static_cast<int>(sock));
        return false;
    }

    if (::listen(sock, SOMAXCONN) != 0) {
        fprintf(stderr, "[WARN] [GGUFProxyServer] listen() failed\n");
        closesocket(static_cast<int>(sock));
        return false;
    }

    m_listenSocket = static_cast<uintptr_t>(sock);
    m_listening    = true;
    fprintf(stderr, "[INFO] [GGUFProxyServer] Listening on port %d\n", m_listenPort);
    if (onServerStarted) onServerStarted(m_listenPort);
    return true;
}

void GGUFProxyServer::stopServer() {
    for (auto& [desc, conn] : m_connections) {
        if (conn->clientSocket) closesocket(static_cast<int>(conn->clientSocket));
        if (conn->ggufSocket)   closesocket(static_cast<int>(conn->ggufSocket));
    }
    m_connections.clear();
    m_activeConnections = 0;

    if (m_listenSocket) {
        closesocket(static_cast<int>(m_listenSocket));
        m_listenSocket = 0;
    }
    m_listening = false;
    fprintf(stderr, "[INFO] [GGUFProxyServer] Server stopped\n");
    if (onServerStopped) onServerStopped();
}

bool GGUFProxyServer::isListening() const { return m_listening; }

json GGUFProxyServer::getServerStatistics() const {
    std::lock_guard<std::mutex> lock(m_statsMutex);
    return {
        {"requestsProcessed",       m_requestsProcessed},
        {"hallucinationsCorrected",  m_hallucinationsCorrected},
        {"navigationErrorsFixed",    m_navigationErrorsFixed},
        {"activeConnections",        m_activeConnections},
        {"serverListening",          m_listening},
        {"listenPort",               m_listenPort},
        {"ggufEndpoint",             m_ggufEndpoint}
    };
}

void GGUFProxyServer::setConnectionPoolSize(int size) {
    m_connectionPoolSize = size;
}

void GGUFProxyServer::setConnectionTimeout(int ms) {
    m_connectionTimeout = ms;
}

// ---------------------------------------------------------------------------
void GGUFProxyServer::handleIncomingConnection(uintptr_t socketDescriptor) {
    fprintf(stderr, "[INFO] [GGUFProxyServer] New client connection: %zu\n",
            static_cast<size_t>(socketDescriptor));
    auto conn = std::make_unique<ClientConnection>();
    conn->clientSocket = socketDescriptor;
    m_connections[socketDescriptor] = std::move(conn);
    m_activeConnections++;
}

void GGUFProxyServer::forwardToGGUF(uintptr_t socketDescriptor) {
    auto it = m_connections.find(socketDescriptor);
    if (it == m_connections.end()) return;
    auto& conn = it->second;

    // Connect to GGUF if needed
    if (!conn->ggufSocket) {
        std::string host;
        int port = 11434;
        parseHostPort(m_ggufEndpoint, host, port);

        auto sock = static_cast<SocketType>(::socket(AF_INET, SOCK_STREAM, 0));
        if (sock == kInvalidSocket) {
            fprintf(stderr, "[WARN] [GGUFProxyServer] Failed to create GGUF socket\n");
            return;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(static_cast<uint16_t>(port));
        inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

        if (::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            fprintf(stderr, "[WARN] [GGUFProxyServer] connect() to %s:%d failed\n",
                    host.c_str(), port);
            closesocket(static_cast<int>(sock));
            return;
=======
#pragma comment(lib, "ws2_32.lib")

using json = nlohmann::json;

GGUFProxyServer::GGUFProxyServer() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

GGUFProxyServer::~GGUFProxyServer() {
    stopServer();
    WSACleanup();
}

void GGUFProxyServer::initialize(int listenPort, AgentHotPatcher* hotPatcher, const std::string& ggufEndpoint) {
    m_listenPort = listenPort;
    m_hotPatcher = hotPatcher;
    m_ggufEndpoint = ggufEndpoint;
}

bool GGUFProxyServer::startServer() {
    if (m_isListening) return true;

    m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSocket == INVALID_SOCKET) return false;

    // Helper: Allow address reuse (Explicit missing logic)
    char opt = 1;
    setsockopt(m_listenSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = inet_addr("127.0.0.1");
    service.sin_port = htons((u_short)m_listenPort);

    if (bind(m_listenSocket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        closesocket(m_listenSocket);
        return false;
    }

    if (listen(m_listenSocket, 100) == SOCKET_ERROR) {
        closesocket(m_listenSocket);
        return false;
    }

    m_isListening = true;
    m_acceptThread = std::thread(&GGUFProxyServer::acceptLoop, this);


    return true;
}

void GGUFProxyServer::stopServer() {
    m_isListening = false;
    if (m_listenSocket != INVALID_SOCKET) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
    }
    if (m_acceptThread.joinable()) {
        m_acceptThread.join();
    }
    // Detached client threads clean themselves up or we track and cancel them (hard with blocking sockets).
    // For this simple impl, we let OS cleanup process resources or rely on timeout.
}

void GGUFProxyServer::acceptLoop() {
    while (m_isListening) {
        SOCKET clientSocket = accept(m_listenSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            if (m_isListening) continue; 
            else break;
        }
        
        // Spawn thread for client
        std::thread t(&GGUFProxyServer::handleClient, this, clientSocket);
        t.detach(); // Let it run
    }
}

SOCKET GGUFProxyServer::connectToBackend() {
    std::string host = "localhost";
    std::string portStr = "8080";
    
    size_t colon = m_ggufEndpoint.find(':');
    if (colon != std::string::npos) {
        host = m_ggufEndpoint.substr(0, colon);
        portStr = m_ggufEndpoint.substr(colon + 1);
    }
    
    struct addrinfo hints, *result = NULL;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &result) != 0) {
        return INVALID_SOCKET;
    }

    SOCKET s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(result);
        return INVALID_SOCKET;
    }

    // Explicit missing logic: Set timeouts to prevent hanging
    DWORD timeout = 30000; // 30 seconds
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    if (connect(s, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        closesocket(s);
        s = INVALID_SOCKET;
    }

    freeaddrinfo(result);
    return s;
}

// Helper to read full HTTP message
static bool readFullMessage(SOCKET s, std::string& headers, std::string& body) {
    char buf[4096];
    std::string raw;
    int headerEnd = -1;
    
    // Read Headers
    while(true) {
        int r = recv(s, buf, sizeof(buf), 0);
        if (r <= 0) return false;
        raw.append(buf, r);
        
        size_t pos = raw.find("\r\n\r\n");
        if (pos != std::string::npos) {
            headerEnd = (int)pos;
            break;
        }
        if (raw.size() > 16384) return false; 
    }
    
    headers = raw.substr(0, headerEnd + 4);
    body = raw.substr(headerEnd + 4); 
    
    // Parse Content-Length
    int contentLength = 0;
    std::string lowerHeaders = headers;
    std::transform(lowerHeaders.begin(), lowerHeaders.end(), lowerHeaders.begin(), 
        [](unsigned char c){ return std::tolower(c); });
    
    size_t clPos = lowerHeaders.find("content-length: ");
    if (clPos != std::string::npos) {
        size_t endLine = lowerHeaders.find("\r\n", clPos);
        std::string val = headers.substr(clPos + 16, endLine - (clPos + 16));
        try { contentLength = std::stoi(val); } catch (...) { contentLength = 0; }
    }
    
    // Read remaining body
    while (body.size() < (size_t)contentLength) {
        int r = recv(s, buf, sizeof(buf), 0);
        if (r <= 0) break; 
        body.append(buf, r);
    }
    
    return true;
}

void GGUFProxyServer::handleClient(SOCKET clientSocket) {
    auto closeSockets = [&](SOCKET s1, SOCKET s2) {
        if (s1 != INVALID_SOCKET) closesocket(s1);
        if (s2 != INVALID_SOCKET) closesocket(s2);
    };

    std::string reqHeaders, reqBody;
    if (!readFullMessage(clientSocket, reqHeaders, reqBody)) {
        closeSockets(clientSocket, INVALID_SOCKET);
        return;
    }

    // Explicit missing logic: Track bytes transferred
    m_bytesTransferred += (reqHeaders.size() + reqBody.size());

    SOCKET serverSocket = connectToBackend();
    if (serverSocket == INVALID_SOCKET) {
        std::string err = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
        send(clientSocket, err.c_str(), (int)err.size(), 0);
        
        // Track error bytes
        m_bytesTransferred += err.size();
        
        closeSockets(clientSocket, INVALID_SOCKET);
        return;
    }

    // Extract context from request
    json context;
    try {
        if (!reqBody.empty() && reqBody[0] == '{') {
             context = json::parse(reqBody);
        }
    } catch(const std::exception& e) {
        // Log JSON parsing error
        std::cerr << "Error parsing request context: " << e.what() << std::endl;
    }

    // Forward Request
    std::string fullReq = reqHeaders + reqBody;
    if (send(serverSocket, fullReq.data(), (int)fullReq.size(), 0) == SOCKET_ERROR) {
        closeSockets(clientSocket, serverSocket);
        return;
    }

    // Read Response
    std::string respHeaders, respBody;
    if (!readFullMessage(serverSocket, respHeaders, respBody)) {
        closeSockets(clientSocket, serverSocket);
        return;
    }

    // Patch Logic
    std::string finalBody = respBody;
    bool modified = false;

    if (m_hotPatcher) {
        if (!respBody.empty() && (respBody[0] == '{' || respBody[0] == '[')) {
             try {
                // Pass the extracted context
                json patched = m_hotPatcher->interceptModelOutput(respBody, context);
                
                if (patched.contains("modified") && patched["modified"].get<bool>()) {
                    if (patched.contains("final_output")) {
                        finalBody = patched["final_output"].dump();
                        modified = true;
                    }
                }
             } catch (const std::exception& e) {
                 std::cerr << "Error during hot patching: " << e.what() << std::endl;
             }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        }

        conn->ggufSocket = static_cast<uintptr_t>(sock);
        fprintf(stderr, "[INFO] [GGUFProxyServer] Connected to GGUF at %s:%d\n",
                host.c_str(), port);
    }

    if (conn->ggufSocket && !conn->requestBuffer.empty()) {
        ::send(static_cast<SocketType>(conn->ggufSocket),
               reinterpret_cast<const char*>(conn->requestBuffer.data()),
               static_cast<int>(conn->requestBuffer.size()), 0);
        conn->requestBuffer.clear();
        std::lock_guard<std::mutex> lock(m_statsMutex);
        ++m_requestsProcessed;
    }

<<<<<<< HEAD
void GGUFProxyServer::processGGUFResponse(uintptr_t socketDescriptor) {
    auto it = m_connections.find(socketDescriptor);
    if (it == m_connections.end() || !m_hotPatcher) return;
    auto& conn = it->second;

    std::string response(conn->responseBuffer.begin(), conn->responseBuffer.end());
    // AgentHotPatcher uses the project's minimal JsonValue type (simple_json.hpp),
    // not nlohmann::json.
    JsonValue ctx = JsonValue::makeObject();
    JsonValue correctedVal = m_hotPatcher->interceptModelOutput(response, ctx);
    std::string corrected = correctedVal.toJsonString();

    if (conn->clientSocket) {
        ::send(static_cast<SocketType>(conn->clientSocket),
               corrected.c_str(), static_cast<int>(corrected.size()), 0);
        conn->responseBuffer.clear();
=======
    std::string responseData;
    if (modified) {
        std::string newHeaders = respHeaders;
        try {
            std::regex clRegex("Content-Length: [0-9]+\r\n", std::regex_constants::icase);
            newHeaders = std::regex_replace(newHeaders, clRegex, "Content-Length: " + std::to_string(finalBody.size()) + "\r\n");
        } catch(...) {}
        responseData = newHeaders + finalBody;
    } else {
        responseData = respHeaders + respBody;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }

<<<<<<< HEAD
void GGUFProxyServer::sendResponseToClient(uintptr_t socketDescriptor,
                                            const std::string& response) {
    auto it = m_connections.find(socketDescriptor);
    if (it == m_connections.end()) return;
    auto& conn = it->second;
    if (conn->clientSocket) {
        ::send(static_cast<SocketType>(conn->clientSocket),
               response.c_str(), static_cast<int>(response.size()), 0);
    }
}

std::string GGUFProxyServer::parseIncomingRequest(const std::vector<uint8_t>& data) {
    return std::string(data.begin(), data.end());
=======
    send(clientSocket, responseData.data(), (int)responseData.size(), 0);
    
    // Explicit missing logic: Track response bytes
    m_bytesTransferred += responseData.size();

    closeSockets(clientSocket, serverSocket);
    m_requestsProcessed++;
}

std::string GGUFProxyServer::getServerStatistics() const {
    std::lock_guard<std::mutex> locker(m_mutex);
    json j;
    j["requestsProcessed"] = m_requestsProcessed.load();
    j["bytesTransferred"] = m_bytesTransferred.load();
    // Explicit missing logic: Report active accept thread
    j["isAccepting"] = m_isListening.load();
    return j.dump();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}
