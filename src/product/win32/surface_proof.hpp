#pragma once
#include "../cli/rawr_product_serve.hpp"
#include "../gateway/pipe_server.hpp"
#include "chrome.hpp"
#include "editor_agent.hpp"
#include "editor_hwnd.hpp"
#include "status_paint.hpp"
#include <string>
#ifdef _WIN32
#include <thread>
#endif

namespace rawr::product {

struct SurfaceWit {
    int hwnd = 0, recv = 0, ghost = 0, accept = 0, reject = 0;
    int status = 0, pipe = 0, e2e = 0;
};

inline bool SurfaceInfer(const char* p, char* o, size_t n) {
    return rawr::ProductLocalInfer(p, o, n);
}

inline SurfaceWit ProveSurface(const std::string& ws) {
    SurfaceWit w{};
    EventBus bus;
    Chrome ch;
    ch.bus = &bus;
    ch.doc.text = "int add(int a, int b) { ";
    ch.doc.caret = ch.doc.text.size();
    ch.doc.recaret();
    EditorHwnd hw;
    if (hw.create("RawrXDProductEditor")) {
        SyncDocToHwnd(ch.doc, hw);
        w.hwnd = hw.created;
    }
    Candidate cand = RankOne("return a + b; }", 1);
    std::string before = ch.doc.text;
    w.recv = ch.receiveCandidate(cand) ? 1 : 0;
    int srcProduct = ch.ghost.source == GhostSrcProduct ? 1 : 0;
    Win32GhostView legacy = ch.ghost;
    int legacyOk = BindLegacyGhost(legacy, "LEGACY_SHOULD_NOT_STICK") ? 1 : 0;
    w.ghost = (w.hwnd && srcProduct && !legacyOk && ch.paintGhost() &&
               ch.doc.text == before && hw.getText() == before)
                  ? 1
                  : 0;
    std::string st = PaintFromBus(bus);
    std::string sp = ch.statusPaint();
    w.status = (st.find("candidate") != std::string::npos ||
                sp.find("complete") != std::string::npos)
                   ? 1
                   : 0;
    Chrome acc = ch;
    w.accept = acc.accept() && acc.doc.text.find(cand.text) != std::string::npos &&
                       acc.overlay.docMutated
                   ? 1
                   : 0;
    if (w.hwnd) {
        SyncDocToHwnd(acc.doc, hw);
        if (hw.getText().find(cand.text) == std::string::npos) w.accept = 0;
    }
    Chrome rej = ch;
    rej.typeChar('x');
    w.reject = (rej.overlay.ghost.stale && !GhostViewMayPaint(rej.ghost, rej.doc.gen) &&
                rej.doc.text.find(cand.text) == std::string::npos)
                   ? 1
                   : 0;
#ifdef _WIN32
    char pipe[80];
    wsprintfA(pipe, "\\\\.\\pipe\\rawrxd_product_%u", GetCurrentProcessId());
    ProductServer srv;
    srv.infer = SurfaceInfer;
    HANDLE h = ProductPipeListen(pipe);
    std::thread th([&] {
        ProductServeOne(srv, h, nullptr);
        CloseHandle(h);
    });
    std::string rsp;
    w.pipe = ProductClientCall(pipe, "PING", rsp, 4000) &&
                     rsp.find("PONG") != std::string::npos
                 ? 1
                 : 0;
    th.join();
#endif
    EditorAgentSlice sl;
    sl.chrome.doc.path = ws + "\\sample.hpp";
    w.e2e = sl.run(ws, sl.chrome.doc.path, SurfaceInfer) ? 1 : 0;
    hw.destroy();
    return w;
}

} // namespace rawr::product
