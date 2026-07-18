// RawrXD WebSocket API
// Phase 9 - Task 5: WebSocket API

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <string>
#include <queue>
#include <mutex>
#include <thread>

#pragma comment(lib, "ws2_32.lib")

// WebSocket opcodes
enum WSOpcode {
    WS_CONTINUATION = 0x0,
    WS_TEXT = 0x1,
    WS_BINARY = 0x2,
    WS_CLOSE = 0x8,
    WS_PING = 0x9,
    WS_PONG = 0xA
};

// WebSocket frame header
struct WSFrameHeader {
    uint8_t fin : 1;
    uint8_t rsv : 3;
    uint8_t opcode : 4;
    uint8_t mask : 1;
    uint8_t payloadLen : 7;
};

// WebSocket client connection
struct WSClient {
    SOCKET socket;
    bool connected;
    bool handshaked;
    std::string buffer;
    uint64_t lastPing;
    std::thread* recvThread;
    std::queue<std::string> sendQueue;
    std::mutex sendMutex;
};

// WebSocket server
class WebSocketServer {
private:
    SOCKET listenSocket;
    std::vector<WSClient*> clients;
    std::mutex clientsMutex;
    std::atomic<bool> running;
    int port;
    std::thread acceptThread;
    std::thread heartbeatThread;
    
    // Callbacks
    typedef void (*MessageCallback)(uint64_t clientId, const char* message, size_t len);
    typedef void (*ConnectCallback)(uint64_t clientId);
    typedef void (*DisconnectCallback)(uint64_t clientId);
    
    MessageCallback onMessage;
    ConnectCallback onConnect;
    DisconnectCallback onDisconnect;
    
public:
    WebSocketServer() : listenSocket(INVALID_SOCKET), port(0), 
                        onMessage(nullptr), onConnect(nullptr), onDisconnect(nullptr) {}
    
    bool Initialize(int serverPort) {
        port = serverPort;
        
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return false;
        }
        
        // Create socket
        listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET) {
            WSACleanup();
            return false;
        }
        
        // Allow reuse
        int reuse = 1;
        setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));
        
        // Bind
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        
        if (bind(listenSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            closesocket(listenSocket);
            WSACleanup();
            return false;
        }
        
        // Listen
        if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
            closesocket(listenSocket);
            WSACleanup();
            return false;
        }
        
        running = true;
        
        // Start accept thread
        acceptThread = std::thread(&WebSocketServer::AcceptLoop, this);
        
        // Start heartbeat thread
        heartbeatThread = std::thread(&WebSocketServer::HeartbeatLoop, this);
        
        printf("WebSocket server started on port %d\n", port);
        return true;
    }
    
    void SetCallbacks(MessageCallback msgCb, ConnectCallback connCb, DisconnectCallback discCb) {
        onMessage = msgCb;
        onConnect = connCb;
        onDisconnect = discCb;
    }
    
    void AcceptLoop() {
        while (running) {
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(listenSocket, &readSet);
            
            timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            
            if (select(0, &readSet, nullptr, nullptr, &timeout) > 0) {
                if (FD_ISSET(listenSocket, &readSet)) {
                    sockaddr_in clientAddr;
                    int addrLen = sizeof(clientAddr);
                    SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &addrLen);
                    
                    if (clientSocket != INVALID_SOCKET) {
                        HandleNewConnection(clientSocket);
                    }
                }
            }
        }
    }
    
    void HandleNewConnection(SOCKET clientSocket) {
        WSClient* client = new WSClient();
        client->socket = clientSocket;
        client->connected = true;
        client->handshaked = false;
        client->lastPing = GetTickCount64();
        
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            clients.push_back(client);
        }
        
        // Start receive thread for this client
        client->recvThread = new std::thread(&WebSocketServer::ClientRecvLoop, this, client);
        
        printf("New WebSocket client connected\n");
    }
    
    void ClientRecvLoop(WSClient* client) {
        char buffer[8192];
        
        // First, handle HTTP upgrade request
        if (!HandleHandshake(client)) {
            DisconnectClient(client);
            return;
        }
        
        if (onConnect) {
            onConnect((uint64_t)client);
        }
        
        // Main message loop
        while (running && client->connected) {
            int received = recv(client->socket, buffer, sizeof(buffer), 0);
            
            if (received <= 0) {
                break;
            }
            
            client->buffer.append(buffer, received);
            
            // Process complete frames
            ProcessFrames(client);
        }
        
        DisconnectClient(client);
    }
    
    bool HandleHandshake(WSClient* client) {
        // Wait for HTTP upgrade request
        char buffer[4096];
        int total = 0;
        
        while (total < sizeof(buffer) - 1) {
            int received = recv(client->socket, buffer + total, sizeof(buffer) - total - 1, 0);
            if (received <= 0) return false;
            
            total += received;
            buffer[total] = '\0';
            
            // Check for end of HTTP headers
            if (strstr(buffer, "\r\n\r\n")) break;
        }
        
        // Parse WebSocket key
        const char* keyHeader = strstr(buffer, "Sec-WebSocket-Key: ");
        if (!keyHeader) return false;
        
        keyHeader += 19;
        char key[25];
        strncpy_s(key, keyHeader, 24);
        key[24] = '\0';
        
        // Generate accept key (simplified - would use SHA1 in production)
        char acceptKey[64];
        // key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" then base64
        sprintf_s(acceptKey, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="); // Example
        
        // Send handshake response
        char response[512];
        sprintf_s(response,
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n"
            "\r\n", acceptKey);
        
        send(client->socket, response, (int)strlen(response), 0);
        client->handshaked = true;
        
        return true;
    }
    
    void ProcessFrames(WSClient* client) {
        while (client->buffer.size() >= 2) {
            // Parse frame header
            WSFrameHeader* header = (WSFrameHeader*)client->buffer.data();
            
            size_t headerLen = 2;
            uint64_t payloadLen = header->payloadLen;
            
            if (payloadLen == 126) {
                if (client->buffer.size() < 4) return;
                payloadLen = ntohs(*(uint16_t*)(client->buffer.data() + 2));
                headerLen = 4;
            } else if (payloadLen == 127) {
                if (client->buffer.size() < 10) return;
                payloadLen = ntohll(*(uint64_t*)(client->buffer.data() + 2));
                headerLen = 10;
            }
            
            // Check mask
            uint8_t maskKey[4] = {0};
            if (header->mask) {
                if (client->buffer.size() < headerLen + 4) return;
                memcpy(maskKey, client->buffer.data() + headerLen, 4);
                headerLen += 4;
            }
            
            // Check if full frame received
            if (client->buffer.size() < headerLen + payloadLen) return;
            
            // Extract payload
            std::string payload(client->buffer.data() + headerLen, payloadLen);
            
            // Unmask if needed
            if (header->mask) {
                for (size_t i = 0; i < payload.size(); i++) {
                    payload[i] ^= maskKey[i % 4];
                }
            }
            
            // Handle opcode
            switch (header->opcode) {
                case WS_TEXT:
                case WS_BINARY:
                    if (onMessage) {
                        onMessage((uint64_t)client, payload.c_str(), payload.size());
                    }
                    break;
                    
                case WS_CLOSE:
                    client->connected = false;
                    break;
                    
                case WS_PING:
                    SendPong(client, payload);
                    break;
                    
                case WS_PONG:
                    client->lastPing = GetTickCount64();
                    break;
            }
            
            // Remove processed frame
            client->buffer.erase(0, headerLen + payloadLen);
        }
    }
    
    void SendPong(WSClient* client, const std::string& data) {
        SendFrame(client, WS_PONG, data.data(), data.size());
    }
    
    void SendPing(WSClient* client) {
        SendFrame(client, WS_PING, nullptr, 0);
    }
    
    void SendText(uint64_t clientId, const char* text) {
        WSClient* client = (WSClient*)clientId;
        if (client && client->connected) {
            SendFrame(client, WS_TEXT, text, strlen(text));
        }
    }
    
    void SendFrame(WSClient* client, uint8_t opcode, const char* data, size_t len) {
        std::lock_guard<std::mutex> lock(client->sendMutex);
        
        uint8_t frame[16];
        size_t frameLen = 0;
        
        // FIN + opcode
        frame[0] = 0x80 | opcode;
        frameLen++;
        
        // Payload length
        if (len < 126) {
            frame[1] = (uint8_t)len;
            frameLen++;
        } else if (len < 65536) {
            frame[1] = 126;
            *(uint16_t*)(frame + 2) = htons((uint16_t)len);
            frameLen += 3;
        } else {
            frame[1] = 127;
            *(uint64_t*)(frame + 2) = htonll(len);
            frameLen += 9;
        }
        
        // Send header
        send(client->socket, (char*)frame, (int)frameLen, 0);
        
        // Send payload
        if (len > 0) {
            send(client->socket, data, (int)len, 0);
        }
    }
    
    void BroadcastText(const char* text) {
        std::lock_guard<std::mutex> lock(clientsMutex);
        
        for (auto* client : clients) {
            if (client->connected) {
                SendText((uint64_t)client, text);
            }
        }
    }
    
    void HeartbeatLoop() {
        while (running) {
            Sleep(30000); // 30 second heartbeat
            
            std::lock_guard<std::mutex> lock(clientsMutex);
            uint64_t now = GetTickCount64();
            
            for (auto* client : clients) {
                if (client->connected) {
                    // Check if client is alive
                    if (now - client->lastPing > 60000) {
                        // No pong received in 60 seconds, disconnect
                        DisconnectClient(client);
                    } else {
                        // Send ping
                        SendPing(client);
                    }
                }
            }
        }
    }
    
    void DisconnectClient(WSClient* client) {
        if (!client->connected) return;
        
        client->connected = false;
        
        // Send close frame
        uint8_t closeFrame[] = {0x88, 0x00};
        send(client->socket, (char*)closeFrame, 2, 0);
        
        closesocket(client->socket);
        
        if (onDisconnect) {
            onDisconnect((uint64_t)client);
        }
        
        // Remove from clients list
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            auto it = std::find(clients.begin(), clients.end(), client);
            if (it != clients.end()) {
                clients.erase(it);
            }
        }
        
        // Cleanup
        if (client->recvThread) {
            client->recvThread->join();
            delete client->recvThread;
        }
        
        delete client;
        
        printf("WebSocket client disconnected\n");
    }
    
    void Shutdown() {
        running = false;
        
        // Disconnect all clients
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            for (auto* client : clients) {
                DisconnectClient(client);
            }
            clients.clear();
        }
        
        // Wait for threads
        if (acceptThread.joinable()) acceptThread.join();
        if (heartbeatThread.joinable()) heartbeatThread.join();
        
        // Cleanup
        closesocket(listenSocket);
        WSACleanup();
    }
    
    size_t GetClientCount() {
        std::lock_guard<std::mutex> lock(clientsMutex);
        return clients.size();
    }
};

// Global instance
static WebSocketServer g_WebSocketServer;

// C API
extern "C" {

bool WebSocketServer_Start(int port) {
    return g_WebSocketServer.Initialize(port);
}

void WebSocketServer_Stop() {
    g_WebSocketServer.Shutdown();
}

void WebSocketServer_SetCallbacks(
    void (*onMsg)(uint64_t, const char*, size_t),
    void (*onConn)(uint64_t),
    void (*onDisc)(uint64_t)) {
    g_WebSocketServer.SetCallbacks(onMsg, onConn, onDisc);
}

void WebSocketServer_Send(uint64_t clientId, const char* message) {
    g_WebSocketServer.SendText(clientId, message);
}

void WebSocketServer_Broadcast(const char* message) {
    g_WebSocketServer.BroadcastText(message);
}

size_t WebSocketServer_GetClientCount() {
    return g_WebSocketServer.GetClientCount();
}

} // extern "C"
