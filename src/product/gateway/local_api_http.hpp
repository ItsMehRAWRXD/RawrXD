#pragma once
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#endif
#include "local_api.hpp"
#include <cstring>
#include <string>
namespace rawr::product {

#ifdef _WIN32
inline SOCKET LocalApiListen(unsigned short port) {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return INVALID_SOCKET;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(s, (sockaddr*)&a, sizeof(a)) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    if (listen(s, 8) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

inline bool LocalApiServeOne(SOCKET ls) {
    SOCKET c = accept(ls, nullptr, nullptr);
    if (c == INVALID_SOCKET) return false;
    char req[8192];
    int n = recv(c, req, sizeof(req) - 1, 0);
    if (n <= 0) {
        closesocket(c);
        return false;
    }
    req[n] = 0;
    std::string method = "GET", path = "/", body;
    if (strncmp(req, "POST ", 5) == 0) method = "POST";
    const char* sp = strchr(req, ' ');
    if (sp) {
        const char* sp2 = strchr(sp + 1, ' ');
        if (sp2) path.assign(sp + 1, sp2);
    }
    const char* hdr = strstr(req, "\r\n\r\n");
    if (hdr) body = hdr + 4;
    std::string json = LocalApiHandle(method, path, body);
    char hdrs[256];
    _snprintf_s(hdrs, sizeof(hdrs), _TRUNCATE,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                "Content-Length: %d\r\nConnection: close\r\n\r\n",
                (int)json.size());
    send(c, hdrs, (int)strlen(hdrs), 0);
    send(c, json.c_str(), (int)json.size(), 0);
    closesocket(c);
    return true;
}
#endif

} // namespace rawr::product
