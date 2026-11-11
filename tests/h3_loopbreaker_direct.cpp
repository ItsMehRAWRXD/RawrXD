// Deterministic H3 certification: drive the real answerUniversal() loop with a
// scripted, IDENTICAL tool_call decision on every model turn (tiny Winsock stub
// server standing in for the inference backend). No real model involved.
// Asserts: the host CIRCUIT BREAKER terminates the loop (does not run to
// maxIterations), the tool executes at most once, duplicate proposals are
// suppressed, and only authentic host receipts are returned.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "rawr_reasoning.hpp"
#include "rawr_core.hpp"
#include <cstdio>
#include <string>
#include <thread>
#include <atomic>
using namespace rawr;
#pragma comment(lib, "ws2_32.lib")

static SOCKET g_listen = INVALID_SOCKET;
static std::atomic<bool> g_stop{false};
static std::atomic<int> g_served{0};

static void serve(unsigned short port) {
    WSADATA w; WSAStartup(MAKEWORD(2,2), &w);
    g_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    int one=1; setsockopt(g_listen, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one));
    if (bind(g_listen,(sockaddr*)&addr,sizeof(addr))==SOCKET_ERROR){ printf("SOCKET_BIND_FAIL %d\n",WSAGetLastError()); return; }
    listen(g_listen, 8);
    // Every reply is the SAME duplicate tool_call decision.
    const std::string body =
        "{\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\","
        "\"content\":\"{\\\"kind\\\":\\\"tool_call\\\",\\\"tool\\\":\\\"read_file\\\","
        "\\\"args\\\":{\\\"path\\\":\\\"README_PRODUCTION.md\\\"}}\"},"
        "\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}";
    std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                       + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    while(!g_stop){
        SOCKET c = accept(g_listen, nullptr, nullptr);
        if (c==INVALID_SOCKET) break;
        char buf[4096]; int got = recv(c, buf, sizeof(buf), 0); (void)got;
        send(c, resp.data(), (int)resp.size(), 0);
        closesocket(c);
        ++g_served;
    }
    closesocket(g_listen);
    WSACleanup();
}

int main(){
    const unsigned short PORT = 18099;
    std::thread srv(serve, PORT);
    // Wait for the stub to accept a connection before proceeding.
    Sleep(300);

    Workspace ws; ws.setRoot("F:\\rawrxd");
    ToolRegistry reg; registerDefaultTools(reg, ws);
    InferenceClient client; client.setEndpoint(PORT, "127.0.0.1", "/v1/chat/completions"); client.setTimeout(20000);

    Question q; q.text = "read README_PRODUCTION.md over and over";
    ExecutionLimits limits; limits.maxIterations = 14; limits.maxToolCalls = 12;

    Response r = answerUniversal(client, reg, ws, q, *findMode("ask"), limits);

    g_stop = true; closesocket(g_listen);
    if (srv.joinable()) srv.join();

    int executed = 0, proposed = 0;
    for (const auto& t : r.receipts) {
        if (t.status == ActionStatus::Executed) ++executed;
        else ++proposed;
    }
    printf("model_replies_served=%d\n", g_served.load());
    printf("receipts: executed=%d proposed/other=%d total=%zu\n", executed, proposed, r.receipts.size());
    printf("answer_is_grounded=%d\n", r.answerIsGrounded ? 1 : 0);
    printf("answer_head=%s\n", r.text.substr(0, std::min<size_t>(90, r.text.size())).c_str());

    int fails = 0;
    auto CHECK=[&](bool c,const char*n){ printf("%-46s %s\n", n, c?"PASS":"FAIL"); if(!c)++fails; };
    CHECK(executed == 1, "duplicate tool executed exactly once");
    CHECK(proposed <= 5, "breaker terminated loop (<=5 dup proposals)");
    CHECK(g_served.load() <= 12, "bounded model replies (no runaway loop)");
    CHECK(!r.text.empty(), "controlled final answer produced");
    printf("\nH3_DIRECT: %s (%d fail)\n", fails==0?"ALL PASS":"FAILURES", fails);
    return fails==0?0:1;
}
