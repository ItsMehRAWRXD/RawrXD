// ============================================================================
// Deep2Server_Sovereign.cpp - Sovereign HTTP Server (Zero MSVC CRT)
// Uses custom CRT (crt0.asm) + socket_wrapper.c
// ============================================================================

// Prevent any CRT includes
#define _CRT_SECURE_NO_WARNINGS
#define _NO_CRT_STDIO_INLINE

// Windows API only
extern "C" {
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
}

// Link required libraries
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ntdll.lib")

// Custom declarations (no CRT)
extern "C" {
    void* memset(void* dest, int value, size_t count);
    void* memcpy(void* dest, const void* src, size_t count);
    size_t strlen(const char* str);
    int memcmp(const void* s1, const void* s2, size_t n);
}

// Simple JSON builder (no std::string, no CRT)
namespace json {
    
    struct Buffer {
        char* data;
        size_t capacity;
        size_t length;
        
        void init(char* buf, size_t cap) {
            data = buf;
            capacity = cap;
            length = 0;
            data[0] = '\0';
        }
        
        void append(const char* str) {
            size_t len = strlen(str);
            if (length + len < capacity) {
                memcpy(data + length, str, len + 1);
                length += len;
            }
        }
        
        void append_int(int val) {
            char buf[32];
            // Simple itoa
            int i = 30;
            int neg = val < 0;
            if (neg) val = -val;
            buf[31] = '\0';
            do {
                buf[i--] = '0' + (val % 10);
                val /= 10;
            } while (val > 0);
            if (neg) buf[i--] = '-';
            append(&buf[i + 1]);
        }
    };
    
    void escape_string(Buffer& out, const char* str) {
        out.append("\"");
        while (*str) {
            char c = *str++;
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default: {
                    char tmp[2] = {c, '\0'};
                    out.append(tmp);
                }
            }
        }
        out.append("\"");
    }
}

// ============================================================================
// HTTP Server Implementation
// ============================================================================

class SovereignHTTPServer {
public:
    bool start(int port = 11436) {
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            OutputDebugStringA("[Deep2] WSAStartup failed\n");
            return false;
        }
        
        // Create socket
        listenSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket_ == INVALID_SOCKET) {
            OutputDebugStringA("[Deep2] Socket creation failed\n");
            WSACleanup();
            return false;
        }
        
        // Allow reuse
        int opt = 1;
        setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
        
        // Bind
        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);
        
        if (bind(listenSocket_, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            OutputDebugStringA("[Deep2] Bind failed\n");
            closesocket(listenSocket_);
            WSACleanup();
            return false;
        }
        
        // Listen
        if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR) {
            OutputDebugStringA("[Deep2] Listen failed\n");
            closesocket(listenSocket_);
            WSACleanup();
            return false;
        }
        
        running_ = true;
        port_ = port;
        
        // Print startup message (direct to console)
        const char* msg = 
            "[Deep2] ==========================================\r\n"
            "[Deep2] Sovereign HTTP Server started\r\n"
            "[Deep2] Port: ";
        DWORD written;
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        WriteFile(hOut, msg, strlen(msg), &written, nullptr);
        
        // Print port number
        char portStr[16];
        int i = 14;
        int p = port;
        do {
            portStr[i--] = '0' + (p % 10);
            p /= 10;
        } while (p > 0);
        WriteFile(hOut, &portStr[i + 1], 14 - i, &written, nullptr);
        
        const char* msg2 = "\r\n"
            "[Deep2] Runtime: Sovereign (Zero CRT)\r\n"
            "[Deep2] ==========================================\r\n"
            "[Deep2] Endpoints:\r\n"
            "  GET  /health              - Health check\r\n"
            "  GET  /api/version         - Version info\r\n"
            "  GET  /api/phases          - Phase registry\r\n"
            "[Deep2] ==========================================\r\n\r\n";
        WriteFile(hOut, msg2, strlen(msg2), &written, nullptr);
        
        return true;
    }
    
    void run() {
        while (running_) {
            sockaddr_in clientAddr{};
            int clientLen = sizeof(clientAddr);
            
            SOCKET clientSocket = accept(listenSocket_, (sockaddr*)&clientAddr, &clientLen);
            if (clientSocket == INVALID_SOCKET) {
                if (running_) {
                    Sleep(10);
                }
                continue;
            }
            
            // Handle client in blocking mode (single-threaded for simplicity)
            handleClient(clientSocket);
        }
    }
    
    void stop() {
        running_ = false;
        if (listenSocket_ != INVALID_SOCKET) {
            closesocket(listenSocket_);
        }
        WSACleanup();
    }
    
private:
    SOCKET listenSocket_ = INVALID_SOCKET;
    bool running_ = false;
    int port_ = 11436;
    
    void handleClient(SOCKET clientSocket) {
        char buffer[4096];
        int received = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        
        if (received <= 0) {
            closesocket(clientSocket);
            return;
        }
        
        buffer[received] = '\0';
        
        // Parse request line
        char method[16] = {0};
        char path[256] = {0};
        parseRequestLine(buffer, method, path);
        
        // Route
        char responseBuffer[2048];
        json::Buffer jsonBuf;
        jsonBuf.init(responseBuffer, sizeof(responseBuffer));
        
        const char* status = "200 OK";
        const char* contentType = "application/json";
        
        if (strcmp(method, "GET") == 0 && strcmp(path, "/health") == 0) {
            jsonBuf.append("{\"status\":\"ok\",\"runtime\":\"Deep2\",\"backend\":\"sovereign\",\"version\":\"1.0.0-sovereign\"}");
        }
        else if (strcmp(method, "GET") == 0 && strcmp(path, "/api/version") == 0) {
            jsonBuf.append("{\"engine\":\"Deep2\",\"version\":\"1.0.0-sovereign\",\"native\":true,\"crt\":\"none\"}");
        }
        else if (strcmp(method, "GET") == 0 && strcmp(path, "/api/phases") == 0) {
            jsonBuf.append("{\"phases\":[");
            jsonBuf.append("{\"id\":0,\"name\":\"Discovery\",\"status\":\"complete\"}, ");
            jsonBuf.append("{\"id\":1,\"name\":\"Runtime\",\"status\":\"complete\"}, ");
            jsonBuf.append("{\"id\":2,\"name\":\"Kernels\",\"status\":\"complete\"}, ");
            jsonBuf.append("{\"id\":3,\"name\":\"GGUF\",\"status\":\"complete\"}");
            jsonBuf.append("]}");
        }
        else {
            status = "404 Not Found";
            jsonBuf.append("{\"error\":\"not found\",\"path\":\"");
            jsonBuf.append(path);
            jsonBuf.append("\"}");
        }
        
        // Send response
        sendHttpResponse(clientSocket, status, contentType, jsonBuf.data, jsonBuf.length);
        closesocket(clientSocket);
    }
    
    void parseRequestLine(const char* request, char* method, char* path) {
        // Simple parser - find first line
        const char* p = request;
        
        // Skip leading whitespace
        while (*p == ' ' || *p == '\t') p++;
        
        // Extract method
        int i = 0;
        while (*p && *p != ' ' && i < 15) {
            method[i++] = *p++;
        }
        method[i] = '\0';
        
        // Skip space
        while (*p == ' ') p++;
        
        // Extract path
        i = 0;
        while (*p && *p != ' ' && *p != '?' && i < 255) {
            path[i++] = *p++;
        }
        path[i] = '\0';
    }
    
    void sendHttpResponse(SOCKET sock, const char* status, const char* contentType, 
                          const char* body, size_t bodyLen) {
        char header[512];
        
        // Build header
        char* h = header;
        const char* prefix = "HTTP/1.1 ";
        memcpy(h, prefix, 9); h += 9;
        memcpy(h, status, strlen(status)); h += strlen(status);
        *h++ = '\r'; *h++ = '\n';
        
        const char* ct = "Content-Type: ";
        memcpy(h, ct, 14); h += 14;
        memcpy(h, contentType, strlen(contentType)); h += strlen(contentType);
        *h++ = '\r'; *h++ = '\n';
        
        const char* cl = "Content-Length: ";
        memcpy(h, cl, 16); h += 16;
        
        // Convert bodyLen to string
        char lenStr[16];
        int i = 14;
        size_t len = bodyLen;
        do {
            lenStr[i--] = '0' + (len % 10);
            len /= 10;
        } while (len > 0);
        memcpy(h, &lenStr[i + 1], 14 - i);
        h += 14 - i;
        
        *h++ = '\r'; *h++ = '\n';
        *h++ = '\r'; *h++ = '\n';
        *h = '\0';
        
        // Send header
        send(sock, header, h - header, 0);
        
        // Send body
        if (bodyLen > 0) {
            send(sock, body, (int)bodyLen, 0);
        }
    }
    
    static int strcmp(const char* s1, const char* s2) {
        while (*s1 && (*s1 == *s2)) {
            s1++;
            s2++;
        }
        return *(unsigned char*)s1 - *(unsigned char*)s2;
    }
};

// ============================================================================
// Entry Point
// ============================================================================

extern "C" int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    SovereignHTTPServer server;
    
    if (!server.start(11436)) {
        return 1;
    }
    
    server.run();
    server.stop();
    
    return 0;
}
