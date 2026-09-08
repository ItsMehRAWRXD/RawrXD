#pragma once
#include "../product/gateway/local_api_http.hpp"
#include "rawr_exit_codes.hpp"
namespace rawr {

inline int RunProductHttpServe(unsigned short port) {
#ifdef _WIN32
    using namespace rawr::product;
    SOCKET s = LocalApiListen(port ? port : 11435);
    if (s == INVALID_SOCKET) return ExitCode::SteerFail;
    for (;;) {
        if (!LocalApiServeOne(s)) break;
    }
    closesocket(s);
    WSACleanup();
    return ExitCode::Ok;
#else
    (void)port;
    return ExitCode::SteerFail;
#endif
}

} // namespace rawr
