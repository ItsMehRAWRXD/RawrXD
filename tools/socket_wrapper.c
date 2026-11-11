/* ============================================================================
 * socket_wrapper.c - Winsock2 wrapper for sovereign build
 * Zero CRT dependency - uses only kernel32/ntdll/ws2_32
 * ============================================================================ */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

/* Custom types to avoid CRT headers */
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef long long int64_t;

/* Socket handle type */
typedef SOCKET socket_t;

/* Error codes */
#define SOV_OK 0
#define SOV_ERROR -1
#define SOV_WOULD_BLOCK -2

/* ============================================================================
 * Initialization
 * ============================================================================ */

static WSADATA g_wsaData;
static int g_wsaInitialized = 0;

int sov_socket_init(void) {
    if (g_wsaInitialized) return SOV_OK;
    
    if (WSAStartup(MAKEWORD(2, 2), &g_wsaData) != 0) {
        return SOV_ERROR;
    }
    
    g_wsaInitialized = 1;
    return SOV_OK;
}

void sov_socket_cleanup(void) {
    if (g_wsaInitialized) {
        WSACleanup();
        g_wsaInitialized = 0;
    }
}

/* ============================================================================
 * Socket Operations
 * ============================================================================ */

socket_t sov_socket_create(void) {
    return socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

void sov_socket_close(socket_t sock) {
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
    }
}

int sov_socket_bind(socket_t sock, uint16_t port) {
    struct sockaddr_in addr;
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    return bind(sock, (struct sockaddr*)&addr, sizeof(addr));
}

int sov_socket_listen(socket_t sock, int backlog) {
    return listen(sock, backlog);
}

socket_t sov_socket_accept(socket_t sock) {
    struct sockaddr_in clientAddr;
    int addrLen = sizeof(clientAddr);
    return accept(sock, (struct sockaddr*)&clientAddr, &addrLen);
}

int sov_socket_connect(socket_t sock, const char* host, uint16_t port) {
    struct sockaddr_in addr;
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    /* Simple inet_addr - assumes dotted decimal */
    addr.sin_addr.s_addr = inet_addr(host);
    if (addr.sin_addr.s_addr == INADDR_NONE) {
        /* Could add gethostbyname here if needed */
        return SOV_ERROR;
    }
    
    return connect(sock, (struct sockaddr*)&addr, sizeof(addr));
}

int sov_socket_set_nonblocking(socket_t sock) {
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode);
}

int sov_socket_set_reuseaddr(socket_t sock) {
    int opt = 1;
    return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
}

/* ============================================================================
 * I/O Operations
 * ============================================================================ */

int sov_socket_send(socket_t sock, const void* data, int len) {
    return send(sock, (const char*)data, len, 0);
}

int sov_socket_recv(socket_t sock, void* buffer, int len) {
    return recv(sock, (char*)buffer, len, 0);
}

int sov_socket_send_all(socket_t sock, const void* data, int len) {
    const char* ptr = (const char*)data;
    int total = 0;
    
    while (total < len) {
        int sent = send(sock, ptr + total, len - total, 0);
        if (sent == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                Sleep(1);
                continue;
            }
            return SOV_ERROR;
        }
        total += sent;
    }
    
    return total;
}

/* ============================================================================
 * HTTP Helpers
 * ============================================================================ */

static int sov_strncmp(const char* s1, const char* s2, int n) {
    while (n-- > 0) {
        if (*s1 != *s2) return (unsigned char)*s1 - (unsigned char)*s2;
        if (*s1 == '\0') return 0;
        s1++;
        s2++;
    }
    return 0;
}

static int sov_strlen(const char* s) {
    int len = 0;
    while (*s++) len++;
    return len;
}

int sov_http_send_response(socket_t sock, int code, const char* content_type, 
                           const char* body, int body_len) {
    char header[1024];
    int header_len;
    const char* status_text = "OK";
    
    if (code == 404) status_text = "Not Found";
    else if (code == 500) status_text = "Internal Server Error";
    
    /* Build HTTP response header */
    header_len = wsprintfA(header, 
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        code, status_text, content_type, body_len);
    
    /* Send header */
    if (sov_socket_send_all(sock, header, header_len) < 0) {
        return SOV_ERROR;
    }
    
    /* Send body */
    if (body_len > 0 && body) {
        if (sov_socket_send_all(sock, body, body_len) < 0) {
            return SOV_ERROR;
        }
    }
    
    return SOV_OK;
}

int sov_http_parse_request(const char* request, char* method, int method_size,
                           char* path, int path_size) {
    const char* p = request;
    int i = 0;
    
    /* Skip leading whitespace */
    while (*p == ' ' || *p == '\t') p++;
    
    /* Extract method */
    while (*p && *p != ' ' && i < method_size - 1) {
        method[i++] = *p++;
    }
    method[i] = '\0';
    
    /* Skip space */
    while (*p == ' ') p++;
    
    /* Extract path */
    i = 0;
    while (*p && *p != ' ' && *p != '?' && i < path_size - 1) {
        path[i++] = *p++;
    }
    path[i] = '\0';
    
    return SOV_OK;
}

/* ============================================================================
 * Server Helpers
 * ============================================================================ */

typedef struct {
    socket_t listen_sock;
    int running;
    void (*handler)(socket_t client, const char* request);
} sov_server_t;

int sov_server_init(sov_server_t* server, uint16_t port) {
    server->listen_sock = sov_socket_create();
    if (server->listen_sock == INVALID_SOCKET) {
        return SOV_ERROR;
    }
    
    sov_socket_set_reuseaddr(server->listen_sock);
    
    if (sov_socket_bind(server->listen_sock, port) != 0) {
        sov_socket_close(server->listen_sock);
        return SOV_ERROR;
    }
    
    if (sov_socket_listen(server->listen_sock, SOMAXCONN) != 0) {
        sov_socket_close(server->listen_sock);
        return SOV_ERROR;
    }
    
    server->running = 1;
    return SOV_OK;
}

void sov_server_run(sov_server_t* server) {
    char buffer[8192];
    
    while (server->running) {
        socket_t client = sov_socket_accept(server->listen_sock);
        if (client == INVALID_SOCKET) {
            Sleep(10);
            continue;
        }
        
        /* Receive request */
        int received = sov_socket_recv(client, buffer, sizeof(buffer) - 1);
        if (received > 0) {
            buffer[received] = '\0';
            
            if (server->handler) {
                server->handler(client, buffer);
            }
        }
        
        sov_socket_close(client);
    }
}

void sov_server_stop(sov_server_t* server) {
    server->running = 0;
    sov_socket_close(server->listen_sock);
}

/* ============================================================================
 * Entry point for testing
 * ============================================================================ */

#ifdef SOV_SOCKET_TEST

static void test_handler(socket_t client, const char* request) {
    char method[16], path[256];
    
    sov_http_parse_request(request, method, sizeof(method), path, sizeof(path));
    
    if (sov_strncmp(path, "/health", 7) == 0) {
        const char* response = "{\"status\":\"ok\",\"runtime\":\"sovereign\"}";
        sov_http_send_response(client, 200, "application/json", response, sov_strlen(response));
    } else {
        const char* response = "{\"error\":\"not found\"}";
        sov_http_send_response(client, 404, "application/json", response, sov_strlen(response));
    }
}

int main(void) {
    sov_server_t server;
    
    if (sov_socket_init() != SOV_OK) {
        return 1;
    }
    
    if (sov_server_init(&server, 11436) != SOV_OK) {
        sov_socket_cleanup();
        return 1;
    }
    
    server.handler = test_handler;
    
    /* Run server (blocking) */
    sov_server_run(&server);
    
    sov_server_stop(&server);
    sov_socket_cleanup();
    
    return 0;
}

#endif /* SOV_SOCKET_TEST */
