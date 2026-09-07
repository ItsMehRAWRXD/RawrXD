#pragma once
#include "framed_pipe.hpp"
#include "product_serve.hpp"
#ifdef _WIN32
namespace rawr::product {

inline HANDLE ProductPipeListen(const char* name) {
    return CreateNamedPipeA(
        name, PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 65536, 65536, 2000,
        nullptr);
}

inline bool ProductServeOne(ProductServer& s, HANDLE h, const EditorSnap* snap) {
    if (h == INVALID_HANDLE_VALUE || !h) return false;
    BOOL connected = ConnectNamedPipe(h, nullptr)
                         ? TRUE
                         : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (!connected) return false;
    std::string req, rsp;
    bool ok = FrameRead(h, req);
    if (ok) {
        rsp = s.dispatch(req, snap);
        ok = FrameWrite(h, rsp);
    }
    FlushFileBuffers(h);
    DisconnectNamedPipe(h);
    return ok;
}

} // namespace rawr::product
#endif
