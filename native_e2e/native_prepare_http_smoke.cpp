// native_prepare_http_smoke.cpp — loopback HTTP proof for prepare
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rawr_native_e2e_abi.h"
#pragma comment(lib, "ws2_32.lib")

static int send_all(SOCKET s, const char* p, int n) {
    while (n > 0) {
        int k = send(s, p, n, 0);
        if (k <= 0) return 0;
        p += k; n -= k;
    }
    return 1;
}

int main(int argc, char** argv) {
    int port = (argc > 1) ? atoi(argv[1]) : 11961;
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 2;
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((u_short)port);
    int opt = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    if (bind(ls, (sockaddr*)&addr, sizeof(addr)) != 0) return 3;
    if (listen(ls, 8) != 0) return 4;
    printf("LISTEN 127.0.0.1:%d\n", port);
    fflush(stdout);
    for (;;) {
        SOCKET c = accept(ls, nullptr, nullptr);
        if (c == INVALID_SOCKET) continue;
        char req[16384]{};
        int got = recv(c, req, sizeof(req) - 1, 0);
        if (got <= 0) { closesocket(c); continue; }
        char method[16]{}, path[256]{};
        sscanf_s(req, "%15s %255s", method, (unsigned)sizeof(method),
                 path, (unsigned)sizeof(path));
        const char* body = strstr(req, "\r\n\r\n");
        body = body ? body + 4 : "";
        char json[8192]{};
        uint32_t st = 500;
        if (!RawrNative_HandleHttp(method, path, body, json,
                                   (uint32_t)sizeof(json), &st)) {
            st = 404;
            strcpy_s(json, "{\"ok\":false,\"error\":\"unhandled\"}");
        }
        char hdr[256];
        int hl = _snprintf_s(hdr, sizeof(hdr), _TRUNCATE,
            "HTTP/1.1 %u OK\r\nContent-Type: application/json\r\n"
            "Content-Length: %u\r\nConnection: close\r\n\r\n",
            st, (unsigned)strlen(json));
        send_all(c, hdr, hl);
        send_all(c, json, (int)strlen(json));
        closesocket(c);
        if (st == 200) break; /* one success then exit for smoke */
    }
    closesocket(ls);
    WSACleanup();
    return 0;
}
