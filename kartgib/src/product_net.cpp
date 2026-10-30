#include <winsock2.h>
#include <ws2tcpip.h>
#include "product_scene.hpp"
#include "worldforge_bridge.hpp"
#include "player_step.hpp"
#include <cmath>
#include <string>
#include <vector>
#pragma comment(lib, "ws2_32.lib")

static void simulate(WorldForgeBridge& world, float* out) {
    KartState kart{};
    kart.throttle = 1.0f;
    for (int i = 0; i < 4; ++i) {
        stepKartBody(kart, 1.0f / 60.0f, [&](float x, float z) {
            return static_cast<float>(world.sampleHeightAt(x, z));
        });
        kart.throttle = 1.0f;
        out[i * 3] = kart.x; out[i * 3 + 1] = kart.y; out[i * 3 + 2] = kart.z;
    }
}

bool runProductPeer(int port, uint64_t seed) {
    WorldForgeBridge world;
    world.initialize(seed, "tropical");
    float out[12]{};
    simulate(world, out);
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return false;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    bool ok = false;
    for (int i = 0; i < 50 && !ok; ++i) {
        ok = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
        if (!ok) Sleep(20);
    }
    if (ok) ok = send(sock, reinterpret_cast<char*>(out), sizeof(out), 0) == sizeof(out);
    closesocket(sock);
    WSACleanup();
    return ok;
}

bool runProductHost(WorldForgeBridge& world) {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return false;
    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(47631);
    if (bind(listenSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return false;
    listen(listenSock, 1);
    wchar_t exe[32768]{};
    GetModuleFileNameW(nullptr, exe, 32768);
    std::wstring cmd = L"\"" + std::wstring(exe) + L"\" --product-peer 47631 20261025";
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(0);
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exe, buf.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) return false;
    fd_set set; FD_ZERO(&set); FD_SET(listenSock, &set);
    timeval tv{8, 0};
    bool ready = select(0, &set, nullptr, nullptr, &tv) > 0;
    SOCKET client = ready ? accept(listenSock, nullptr, nullptr) : INVALID_SOCKET;
    float got[12]{}, expect[12]{};
    bool ok = client != INVALID_SOCKET;
    int received = 0;
    while (ok && received < static_cast<int>(sizeof(got))) {
        int n = recv(client, reinterpret_cast<char*>(got) + received, sizeof(got) - received, 0);
        if (n <= 0) { ok = false; break; }
        received += n;
    }
    simulate(world, expect);
    for (int i = 0; ok && i < 12; ++i) if (std::fabs(got[i] - expect[i]) > 1.0e-3f) ok = false;
    if (ok) {
        productStats().remoteX = got[9];
        productStats().remoteY = got[10];
        productStats().remoteZ = got[11];
        productStats().sync = true;
    }
    if (client != INVALID_SOCKET) closesocket(client);
    closesocket(listenSock);
    WaitForSingleObject(pi.hProcess, 3000);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    WSACleanup();
    return ok;
}
