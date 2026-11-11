#include "backend/ollama_client.h"
#include <nlohmann/json.hpp>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")

using RawrXD::Backend::OllamaClient;
using RawrXD::Backend::OllamaGenerateRequest;
using RawrXD::Backend::OllamaResponse;

namespace {
struct Server {
    SOCKET listenSock = INVALID_SOCKET;
    SOCKET clientSock = INVALID_SOCKET;
    std::thread th;
    std::atomic<bool> stop{false};
    void shutdown() {
        stop.store(true);
        if (clientSock != INVALID_SOCKET) { closesocket(clientSock); clientSock = INVALID_SOCKET; }
        if (listenSock != INVALID_SOCKET) { closesocket(listenSock); listenSock = INVALID_SOCKET; }
        if (th.joinable()) th.join();
    }
    ~Server() { shutdown(); }
};

bool startServer(Server& s, int port, bool sendEmpty200) {
    WSADATA wsa{}; if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return false;
    s.listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s.listenSock == INVALID_SOCKET) return false;
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons((u_short)port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    int opt = 1; setsockopt(s.listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    if (bind(s.listenSock, (sockaddr*)&addr, sizeof(addr)) != 0) return false;
    if (listen(s.listenSock, 1) != 0) return false;
    s.th = std::thread([&s, sendEmpty200]() {
        sockaddr_in caddr{}; int clen = sizeof(caddr);
        s.clientSock = accept(s.listenSock, (sockaddr*)&caddr, &clen);
        if (s.clientSock == INVALID_SOCKET) return;
        if (sendEmpty200) {
            // Read request (best effort) then respond with empty body.
            char buf[2048]; recv(s.clientSock, buf, sizeof(buf), 0);
            const char* resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send(s.clientSock, resp, (int)strlen(resp), 0);
            closesocket(s.clientSock); s.clientSock = INVALID_SOCKET;
        } else {
            // Never respond: hold connection until shutdown to force client timeout.
            while (!s.stop.load()) Sleep(50);
        }
    });
    return true;
}

void printCase(const char* name, bool pass, const std::string& detail) {
    std::cout << (pass ? "PASS" : "FAIL") << " | " << name << " | " << detail << std::endl;
}
} // namespace

int main() {
    int failures = 0;

    // a) SUCCESS
    try {
        OllamaClient c("http://127.0.0.1:11434");
        c.setTimeoutSeconds(120);
        OllamaGenerateRequest req; req.model = "qwen3:8b"; req.prompt = "Reply with the single word: pong"; req.stream = false;
        req.options["num_predict"] = "8"; req.options["temperature"] = "0";
        auto r = c.generateSync(req);
        std::string text = r.response.empty() ? r.message : r.response;
        bool ok = r.done && r.http_status == 200 && !text.empty() && r.transport_error.empty();
        if (!ok) failures++;
        printCase("SUCCESS", ok, "http=" + std::to_string(r.http_status) + " done=" + std::to_string(r.done) + " done_reason=" + r.done_reason + " terr=" + r.transport_error + " text_len=" + std::to_string(text.size()));
    } catch (const std::exception& e) { failures++; printCase("SUCCESS", false, std::string("exception=")+e.what()); }

    // b) CANCELLED
    try {
        auto client = std::make_shared<OllamaClient>("http://127.0.0.1:11434");
        client->setTimeoutSeconds(180);
        std::atomic<bool> done{false};
        OllamaResponse out;
        auto t0 = std::chrono::steady_clock::now();
        std::thread worker([client, &out, &done]() {
            OllamaGenerateRequest req; req.model = "qwen3:8b";
            req.prompt = "Write a very long detailed essay about the history of computing, at least 2000 words.";
            req.stream = false; req.options["num_predict"] = "2048"; req.options["num_ctx"] = "4096";
            out = client->generateSync(req);
            done.store(true);
        });
        Sleep(1000);
        client->cancelActiveRequest();
        worker.join();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        bool ok = (out.transport_error == "CANCELLED") && ms < 15000;
        if (!ok) failures++;
        printCase("CANCELLED", ok, "terr=" + out.transport_error + " done_reason=" + out.done_reason + " elapsed_ms=" + std::to_string(ms) + " http=" + std::to_string(out.http_status));
    } catch (const std::exception& e) { failures++; printCase("CANCELLED", false, std::string("exception=")+e.what()); }

    // c) HTTP_CANNOT_CONNECT
    try {
        OllamaClient c("http://127.0.0.1:1");
        c.setTimeoutSeconds(5);
        OllamaGenerateRequest req; req.model = "qwen3:8b"; req.prompt = "hi"; req.stream = false; req.options["num_predict"] = "1";
        auto r = c.generateSync(req);
        bool ok = (c.lastError() == "HTTP_CANNOT_CONNECT" || r.transport_error == "HTTP_CANNOT_CONNECT");
        if (!ok) failures++;
        printCase("HTTP_CANNOT_CONNECT", ok, "lastError=" + c.lastError() + " terr=" + r.transport_error + " done_reason=" + r.done_reason);
    } catch (const std::exception& e) { failures++; printCase("HTTP_CANNOT_CONNECT", false, std::string("exception=")+e.what()); }

    // d) HTTP_TIMEOUT (accept but never respond)
    try {
        Server s; if (!startServer(s, 18114, false)) { failures++; printCase("HTTP_TIMEOUT", false, "server_start_failed"); }
        else {
            OllamaClient c("http://127.0.0.1:18114");
            c.setTimeoutSeconds(1);
            OllamaGenerateRequest req; req.model = "qwen3:8b"; req.prompt = "hi"; req.stream = false; req.options["num_predict"] = "1";
            auto t0 = std::chrono::steady_clock::now();
            auto r = c.generateSync(req);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
            bool ok = (c.lastError() == "HTTP_TIMEOUT" || r.transport_error == "HTTP_TIMEOUT") && ms < 10000;
            if (!ok) failures++;
            printCase("HTTP_TIMEOUT", ok, "lastError=" + c.lastError() + " terr=" + r.transport_error + " elapsed_ms=" + std::to_string(ms));
            s.shutdown();
        }
    } catch (const std::exception& e) { failures++; printCase("HTTP_TIMEOUT", false, std::string("exception=")+e.what()); }

    // e) EMPTY_RESPONSE (200 with empty body)
    try {
        Server s; if (!startServer(s, 18115, true)) { failures++; printCase("EMPTY_RESPONSE", false, "server_start_failed"); }
        else {
            Sleep(100);
            OllamaClient c("http://127.0.0.1:18115");
            c.setTimeoutSeconds(5);
            OllamaGenerateRequest req; req.model = "qwen3:8b"; req.prompt = "hi"; req.stream = false; req.options["num_predict"] = "1";
            auto r = c.generateSync(req);
            bool ok = (r.transport_error == "EMPTY_RESPONSE" || c.lastError() == "EMPTY_RESPONSE");
            if (!ok) failures++;
            printCase("EMPTY_RESPONSE", ok, "terr=" + r.transport_error + " lastError=" + c.lastError() + " done_reason=" + r.done_reason + " http=" + std::to_string(r.http_status));
            s.shutdown();
        }
    } catch (const std::exception& e) { failures++; printCase("EMPTY_RESPONSE", false, std::string("exception=")+e.what()); }

    std::cout << "FAILURES=" << failures << std::endl;
    return failures ? 1 : 0;
}
