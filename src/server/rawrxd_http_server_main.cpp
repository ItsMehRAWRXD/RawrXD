// ============================================================================
// rawrxd_http_server_main.cpp - HTTP Server Entry Point
// Minimal wrapper for RawrXD_HttpServer.cpp
// ============================================================================

#include "RawrXD_HttpServer.h"
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

// Global debug flag required by transformer
bool g_debug = false;

#pragma comment(lib, "ws2_32.lib")

// Simple HTTP server implementation
#define SERVER_PORT 8080
#define BUFFER_SIZE 8192

void send_response(SOCKET client, int status, const char* content_type, const char* body) {
    char response[BUFFER_SIZE];
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        status, (status == 200) ? "OK" : "Error",
        content_type, strlen(body), body);
    send(client, response, len, 0);
}

void send_json(SOCKET client, int status, const char* json) {
    send_response(client, status, "application/json", json);
}

void handle_health(SOCKET client) {
    const char* json = "{\"status\":\"ok\",\"model\":\"tinyllama\",\"version\":\"1.0.0\"}";
    send_json(client, 200, json);
}

void handle_models(SOCKET client) {
    const char* json = "{\"object\":\"list\",\"data\":[{\"id\":\"tinyllama\",\"object\":\"model\",\"created\":1700000000,\"owned_by\":\"rawrxd\"}]}";
    send_json(client, 200, json);
}

void handle_completions(SOCKET client, const char* body) {
    // Simple JSON response for now
    const char* json = "{\"id\":\"cmpl-test\",\"object\":\"text_completion\",\"created\":1700000000,\"model\":\"tinyllama\",\"choices\":[{\"text\":\"Hello from RawrXD!\",\"index\":0,\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":4,\"total_tokens\":5}}";
    send_json(client, 200, json);
}

void handle_request(SOCKET client) {
    char buffer[BUFFER_SIZE];
    int received = recv(client, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) return;
    buffer[received] = '\0';
    
    char method[16] = "", path[256] = "";
    sscanf(buffer, "%15s %255s", method, path);
    
    const char* body = strstr(buffer, "\r\n\r\n");
    if (body) body += 4;
    else body = "";
    
    printf("[%s] %s\n", method, path);
    
    if (strcmp(path, "/health") == 0) {
        handle_health(client);
    } else if (strcmp(path, "/v1/models") == 0) {
        handle_models(client);
    } else if (strcmp(path, "/v1/completions") == 0 && strcmp(method, "POST") == 0) {
        handle_completions(client, body);
    } else {
        send_response(client, 404, "text/plain", "Not Found");
    }
}

int main(int argc, char* argv[]) {
    int port = SERVER_PORT;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--debug") == 0) {
            g_debug = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("RawrXD HTTP Server\n");
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --port <n>    Port to listen on (default: %d)\n", SERVER_PORT);
            printf("  --debug       Enable debug output\n");
            printf("  --help        Show this help\n");
            return 0;
        }
    }
    
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
    
    // Create socket
    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed\n");
        WSACleanup();
        return 1;
    }
    
    // Allow reuse
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    
    // Bind
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Bind failed on port %d\n", port);
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    // Listen
    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        fprintf(stderr, "Listen failed\n");
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    printf("=================================================================\n");
    printf("  RawrXD HTTP Server\n");
    printf("  Listening on http://localhost:%d\n", port);
    printf("=================================================================\n");
    printf("  Endpoints:\n");
    printf("    GET  /health         - Health check\n");
    printf("    GET  /v1/models      - List models\n");
    printf("    POST /v1/completions - Generate text\n");
    printf("=================================================================\n\n");
    
    // Accept connections
    while (1) {
        struct sockaddr_in client_addr;
        int client_len = sizeof(client_addr);
        SOCKET client = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        
        if (client == INVALID_SOCKET) continue;
        
        handle_request(client);
        closesocket(client);
    }
    
    closesocket(server_socket);
    WSACleanup();
    return 0;
}
