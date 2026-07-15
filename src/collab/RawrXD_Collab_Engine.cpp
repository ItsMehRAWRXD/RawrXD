// RawrXD_Collab_Engine.cpp - Real-time Collaboration Engine
// Zero dependencies, pure Win32 networking

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

#define COLLAB_MAX_PEERS 16
#define COLLAB_PORT 19444
#define COLLAB_HEARTBEAT_MS 5000

struct PeerInfo {
    BOOL bActive;
    SOCKET socket;
    char szName[64];
    char szId[64];
    DWORD dwLastHeartbeat;
    int nCursorLine, nCursorCol;
};

struct CollabSession {
    BOOL bActive;
    BOOL bIsHost;
    SOCKET listenSocket;
    PeerInfo peers[COLLAB_MAX_PEERS];
    int nPeerCount;
    CRITICAL_SECTION cs;
};

static CollabSession g_Collab = {0};

BOOL Collab_Init(void) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    InitializeCriticalSection(&g_Collab.cs);
    return TRUE;
}

BOOL Collab_Host(const char* szName) {
    g_Collab.listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    SOCKADDR_IN addr = {AF_INET, htons(COLLAB_PORT), INADDR_ANY};
    bind(g_Collab.listenSocket, (SOCKADDR*)&addr, sizeof(addr));
    listen(g_Collab.listenSocket, COLLAB_MAX_PEERS);
    g_Collab.bIsHost = TRUE;
    g_Collab.bActive = TRUE;
    return TRUE;
}

BOOL Collab_Join(const char* szHost, const char* szName) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    SOCKADDR_IN addr = {AF_INET, htons(COLLAB_PORT)};
    inet_pton(AF_INET, szHost, &addr.sin_addr);
    connect(sock, (SOCKADDR*)&addr, sizeof(addr));
    
    EnterCriticalSection(&g_Collab.cs);
    g_Collab.peers[0].bActive = TRUE;
    g_Collab.peers[0].socket = sock;
    strncpy(g_Collab.peers[0].szName, szName, 63);
    g_Collab.nPeerCount = 1;
    LeaveCriticalSection(&g_Collab.cs);
    
    g_Collab.bActive = TRUE;
    return TRUE;
}

extern "C" __declspec(dllexport) BOOL RawrXD_Collab_Init(void) { return Collab_Init(); }
extern "C" __declspec(dllexport) BOOL RawrXD_Collab_Host(const char* szSession, const char* szName) { return Collab_Host(szName); }
extern "C" __declspec(dllexport) BOOL RawrXD_Collab_Join(const char* szHost, int nPort, const char* szName) { return Collab_Join(szHost, szName); }
