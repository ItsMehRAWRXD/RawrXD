#pragma once
#include "../gateway/product_serve.hpp"
#include "../repo/repo_scanner.hpp"
#include "../win32/chrome.hpp"
#include <string>
namespace rawr::product {

struct EditorAgentSlice {
    Chrome chrome;
    ProductServer srv;
    RepoIndex idx;
    int scanned = 0;
    int contexted = 0;
    int piped = 0;
    int received = 0;
    int painted = 0;

    bool run(const std::string& ws, const std::string& file, InferFn infer) {
        srv.infer = infer;
        srv.sch.db.delayMs = 0;
        chrome.bus = &srv.bus;
        chrome.doc.path = file;
        chrome.doc.text = "int add(int a, int b) { ";
        chrome.doc.caret = chrome.doc.text.size();
        chrome.doc.recaret();
        ScanRepo(ws, idx, 64);
        scanned = idx.files.empty() ? 0 : 1;
        auto snap = chrome.doc.snap();
        auto assembled =
            srv.ctx.assemble(snap, CtxStrategy::Completion, {}, "");
        contexted = assembled.prompt.empty() ? 0 : 1;
        std::string rsp = srv.dispatch(std::string("COMPLETE ") + snap.prefix,
                                       &snap);
        piped = rsp.rfind("CANDIDATE ", 0) == 0 ? 1 : 0;
        Candidate c = RankOne(piped ? rsp.substr(10) : "", 1);
        received = chrome.receiveCandidate(c) &&
                           chrome.ghost.source == GhostSrcProduct
                       ? 1
                       : 0;
        std::string before = chrome.doc.text;
        painted = chrome.paintGhost() && GhostViewMayPaint(chrome.ghost, chrome.doc.gen)
                      ? 1
                      : 0;
        if (chrome.doc.text != before) return false;
        return scanned && contexted && piped && received && painted;
    }
};

} // namespace rawr::product
