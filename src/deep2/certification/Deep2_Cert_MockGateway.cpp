// Deep2_Cert_MockGateway.cpp — tiny Win32 HTTP server for self-test (no Ship)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <process.h>

#pragma comment(lib, "ws2_32.lib")

static volatile LONG g_running = 0;
static SOCKET g_listen = INVALID_SOCKET;
static HANDLE g_thread = NULL;

static void Respond(SOCKET c, int code, const char* body) {
    char hdr[256];
    int blen = (int)strlen(body);
    _snprintf_s(hdr, sizeof(hdr), _TRUNCATE,
                "HTTP/1.1 %d OK\r\nContent-Type: application/json\r\n"
                "Content-Length: %d\r\nConnection: close\r\n\r\n",
                code, blen);
    send(c, hdr, (int)strlen(hdr), 0);
    send(c, body, blen, 0);
}

static int RecvRequest(SOCKET c, char* req, int reqMax) {
    int total = 0;
    while (total + 1 < reqMax) {
        int n = recv(c, req + total, reqMax - 1 - total, 0);
        if (n <= 0) break;
        total += n;
        req[total] = 0;
        if (strstr(req, "\r\n\r\n")) break;
    }
    return total;
}

static unsigned __stdcall ServeLoop(void*) {
    while (InterlockedCompareExchange(&g_running, 1, 1) == 1) {
        SOCKET c = accept(g_listen, NULL, NULL);
        if (c == INVALID_SOCKET) {
            if (!g_running) break;
            continue;
        }
        char req[8192];
        int n = RecvRequest(c, req, (int)sizeof(req));
        if (n > 0) {
            if (strstr(req, "GET /health")) {
                Respond(c, 200, "{\"status\":\"ok\",\"runtime\":\"deep2-mock\"}");
            } else if (strstr(req, "GET /v1/models")) {
                Respond(c, 200,
                        "{\"object\":\"list\",\"data\":[{\"id\":\"Deep2\","
                        "\"object\":\"model\"}]}");
            } else if (strstr(req, "POST /v1/chat/completions") ||
                       strstr(req, "POST /v1/chat/completions HTTP")) {
                Respond(c, 200,
                        "{\"id\":\"chatcmpl-mock\",\"object\":\"chat.completion\","
                        "\"choices\":[{\"index\":0,\"message\":{\"role\":"
                        "\"assistant\",\"content\":\"mock ok\"}}]}");
            } else if (strstr(req, "POST /mcp")) {
                Respond(c, 200,
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
                        "\"protocolVersion\":\"2024-11-05\",\"serverInfo\":{"
                        "\"name\":\"deep2-mock\"}}}");
            } else if (strstr(req, "GET /api/status")) {
                Respond(c, 200,
                        "{\"ok\":true,\"telemetry\":true,\"requests\":1}");
            } else {
                Respond(c, 404, "{\"error\":\"not_found\"}");
            }
        }
        closesocket(c);
    }
    return 0;
}

extern "C" int MockGatewayStart(unsigned short port) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;
    g_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listen == INVALID_SOCKET) return 0;
    BOOL yes = 1;
    setsockopt(g_listen, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(g_listen, (sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(g_listen);
        g_listen = INVALID_SOCKET;
        return 0;
    }
    if (listen(g_listen, 8) != 0) {
        closesocket(g_listen);
        g_listen = INVALID_SOCKET;
        return 0;
    }
    InterlockedExchange(&g_running, 1);
    g_thread = (HANDLE)_beginthreadex(NULL, 0, ServeLoop, NULL, 0, NULL);
    return g_thread != NULL;
}

extern "C" void MockGatewayStop() {
    InterlockedExchange(&g_running, 0);
    if (g_listen != INVALID_SOCKET) {
        closesocket(g_listen);
        g_listen = INVALID_SOCKET;
    }
    if (g_thread) {
        WaitForSingleObject(g_thread, 2000);
        CloseHandle(g_thread);
        g_thread = NULL;
    }
    WSACleanup();
}
