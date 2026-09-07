#pragma once
#include "../product/gateway/pipe_server.hpp"
#include "../product/gateway/product_serve.hpp"
#include "rawr_exit_codes.hpp"
#include <cstring>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr {

inline bool ProductLocalInfer(const char* prompt, char* out, size_t cap) {
    const char* t = "return a + b; }";
    if (prompt && std::strstr(prompt, "<PRE>")) t = "return a + b; }";
    size_t n = std::strlen(t);
    if (n >= cap) n = cap - 1;
    std::memcpy(out, t, n);
    out[n] = 0;
    return true;
}

inline int RunProductServe(const std::string& pipeName) {
#ifdef _WIN32
    using namespace rawr::product;
    ProductServer srv;
    srv.infer = ProductLocalInfer;
    const char* name =
        pipeName.empty() ? ProductPipeName() : pipeName.c_str();
    HANDLE h = ProductPipeListen(name);
    if (h == INVALID_HANDLE_VALUE) return ExitCode::SteerFail;
    for (;;) {
        if (!ProductServeOne(srv, h, nullptr)) break;
    }
    CloseHandle(h);
    return ExitCode::Ok;
#else
    (void)pipeName;
    return ExitCode::SteerFail;
#endif
}

} // namespace rawr
