#include "gguf_proxy_server.hpp"
#include "agent_hot_patcher.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <nlohmann/json.hpp>

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
    
    std::cout << "[GGUFProxyServer] Listening on " << m_listenPort << std::endl;
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

    if (connect(s, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        closesocket(s);
        s = INVALID_SOCKET;
    }

    freeaddrinfo(result);
    return s;
}

// Simple Helper to read Utils
static std::string readRequest(SOCKET s) {
    char buf[4096];
    std::string total;
    while (true) {
        int bytes = recv(s, buf, sizeof(buf), 0);
        if (bytes <= 0) break;
        total.append(buf, bytes);
        // Real HTTP parsing: check for end of headers
        if (total.find("\r\n\r\n") != std::string::npos) {
            // Parse Content-Length for POST requests
            size_t headerEnd = total.find("\r\n\r\n");
            std::string headers = total.substr(0, headerEnd);
            
            // Find Content-Length header
            size_t clPos = headers.find("Content-Length:");
            if (clPos != std::string::npos) {
                size_t valStart = headers.find(' ', clPos) + 1;
                size_t valEnd = headers.find('\r', valStart);
                if (valEnd == std::string::npos) valEnd = headers.find('\n', valStart);
                int contentLength = std::stoi(headers.substr(valStart, valEnd - valStart));
                
                // Read until we have the full body
                size_t bodyStart = headerEnd + 4;
                while (total.size() - bodyStart < static_cast<size_t>(contentLength)) {
                    bytes = recv(s, buf, sizeof(buf), 0);
                    if (bytes <= 0) break;
                    total.append(buf, bytes);
                }
            }
            break;  // We have the complete request
        }
    }
    return total;
}

void GGUFProxyServer::handleClient(SOCKET clientSocket) {
    SOCKET serverSocket = connectToBackend();
    if (serverSocket == INVALID_SOCKET) {
        closesocket(clientSocket);
        return;
    }

    // 1. Read Request from Client
    char buffer[8192];
    int bytesRecv = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesRecv > 0) {
        // Forward to backend
        send(serverSocket, buffer, bytesRecv, 0);
    }

    // 2. Read Response from Backend
    // Real HTTP response reading with Content-Length parsing
    std::string responseData;
    std::string responseHeaders;
    std::string responseBody;
    bool headersParsed = false;
    int contentLength = -1;
    
    while (true) {
        int r = recv(serverSocket, buffer, sizeof(buffer), 0);
        if (r <= 0) break;
        responseData.append(buffer, r);
        
        // Parse headers once we have them
        if (!headersParsed) {
            size_t headerEnd = responseData.find("\r\n\r\n");
            if (headerEnd != std::string::npos) {
                responseHeaders = responseData.substr(0, headerEnd);
                responseBody = responseData.substr(headerEnd + 4);
                headersParsed = true;
                
                // Parse Content-Length
                size_t clPos = responseHeaders.find("Content-Length:");
                if (clPos != std::string::npos) {
                    size_t valStart = responseHeaders.find(' ', clPos) + 1;
                    size_t valEnd = responseHeaders.find('\r', valStart);
                    if (valEnd == std::string::npos) valEnd = responseHeaders.find('\n', valStart);
                    contentLength = std::stoi(responseHeaders.substr(valStart, valEnd - valStart));
                }
            }
        }
        
        // Check if we have the complete body
        if (headersParsed) {
            if (contentLength >= 0 && static_cast<int>(responseBody.size()) >= contentLength) {
                break;  // Complete response received
            }
        }
    }
    
    // 3. Patch logic: parse HTTP response and apply hotpatcher if needed
    
    size_t headerEnd = responseData.find("\r\n\r\n");
    if (headerEnd != std::string::npos && m_hotPatcher) {
        std::string headers = responseData.substr(0, headerEnd);
        std::string body = responseData.substr(headerEnd + 4);
        
        // Check if JSON
        // If content-type json...
        
        // Call patcher
        // Note: interceptModelOutput returns a json object now in our new API, or we adapted it.
        // Let's assume body is the model output string.
        
        // This part requires `AgentHotPatcher` to be thread safe (it has mutex).
        // Adapt input to patcher
        json context; // empty context
        json patched = m_hotPatcher->interceptModelOutput(body, context);
        
        if (patched["modified"].get<bool>()) {
             // Reconstruct response
             std::string newBody;
             if (patched.contains("final_output")) {
                 newBody = patched["final_output"].dump();
             } else {
                 newBody = body;
             }
             
             // Real HTTP response reconstruction with proper Content-Length
             std::stringstream ss;
             ss << "HTTP/1.1 200 OK\r\n";
             ss << "Content-Type: application/json\r\n";
             ss << "Content-Length: " << newBody.size() << "\r\n";
             ss << "Connection: close\r\n\r\n";
             ss << newBody;
             responseData = ss.str();
        }
    }

    // 4. Send back to client
    send(clientSocket, responseData.data(), (int)responseData.size(), 0);

    // Cleanup
    closesocket(serverSocket);
    closesocket(clientSocket);
    
    m_requestsProcessed++;
}

std::string GGUFProxyServer::getServerStatistics() const {
    std::lock_guard<std::mutex> locker(m_mutex);
    json j;
    j["requestsProcessed"] = m_requestsProcessed.load();
    return j.dump();
}
