// RAWRXD_RAWR_PIPE_001 — framed native protocol (same path as rawr serve)
#include "../src/cli/rawr_product_serve.hpp"
#include "../src/product/gateway/framed_pipe.hpp"
#include "../src/product/gateway/pipe_server.hpp"
#include <cstdio>
#include <fstream>
#include <string>
#include <thread>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

static int fail(const char* w) {
    fprintf(stderr, "FAIL: %s\n", w);
    puts("RAWRXD_RAWR_PIPE_001=FAIL");
    return 1;
}

int main() {
    using namespace rawr::product;
    char pipe[80];
    wsprintfA(pipe, "\\\\.\\pipe\\rawrxd_rawr_pipe_%u", GetCurrentProcessId());
    ProductServer srv;
    srv.infer = rawr::ProductLocalInfer;
    HANDLE h = ProductPipeListen(pipe);
    if (h == INVALID_HANDLE_VALUE) return fail("listen");
    std::thread th([&] {
        ProductServeOne(srv, h, nullptr);
        CloseHandle(h);
    });
    std::string ping, caps, complete;
    int okPing = ProductClientCall(pipe, "PING", ping, 4000) &&
                 ping.find("PONG") != std::string::npos;
    th.join();
    HANDLE h2 = ProductPipeListen(pipe);
    std::thread th2([&] {
        ProductServeOne(srv, h2, nullptr);
        CloseHandle(h2);
    });
    int okCaps = ProductClientCall(pipe, "CAPS", caps, 4000) &&
                 caps.find("63") != std::string::npos;
    th2.join();
    HANDLE h3 = ProductPipeListen(pipe);
    EditorSnap snap{};
    snap.prefix = "int add(int a, int b) { ";
    std::thread th3([&] {
        ProductServeOne(srv, h3, &snap);
        CloseHandle(h3);
    });
    int okComp = ProductClientCall(pipe, "COMPLETE int add", complete, 4000) &&
                 complete.rfind("CANDIDATE ", 0) == 0;
    th3.join();
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\RAWRXD_RAWR_PIPE_001",
                     nullptr);
    std::ofstream seal(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_RAWR_PIPE_001\\SEAL.txt");
    seal << "PING=" << okPing << "\nCAPS=" << okCaps
         << "\nCOMPLETE=" << okComp << "\nRAWRXD_RAWR_PIPE_001="
         << (okPing && okCaps && okComp ? "PASS" : "FAIL") << "\n";
    if (!okPing || !okCaps || !okComp) return fail("proto");
    puts("RAWRXD_RAWR_PIPE_001=PASS");
    return 0;
}
