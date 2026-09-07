// certs/rawrxd_autocomplete_cancel_001.cpp — P11: cancel + stale suppression
#include "../src/product/complete/completion_scheduler.hpp"
#include "../src/product/complete/ghost_text.hpp"
#include "../src/product/win32/chrome.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace rawr::product;

static bool FastInfer(const char* /*p*/, char* out, size_t cap) {
    const char* t = "return 0; }";
    size_t n = strlen(t);
    if (n >= cap) n = cap - 1;
    memcpy(out, t, n);
    out[n] = 0;
    return true;
}

int main() {
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_AUTOCOMPLETE_CANCEL_001", nullptr);
#endif
    CompletionScheduler sch;
    sch.db.delayMs = 0;
    ExecutionRequest req{};
    req.prompt = "int f() { ";

    sch.submit(req);
    sch.cancel.request();
    ExecutionResult cancelled = sch.run(FastInfer);
    int cancelOk =
        (cancelled.cancelled || cancelled.err == "cancel") ? 1 : 0;

    sch.cancel.clear();
    sch.submit(req);
    sch.submit(req); // drops prior job as stale
    ExecutionResult liveRun = sch.run(FastInfer);
    int staleSuppressed =
        (liveRun.gen == sch.liveGen && liveRun.ok && !liveRun.stale) ? 1 : 0;

    Chrome ch;
    ch.doc.text = "int f() { ";
    ch.doc.caret = ch.doc.text.size();
    ch.doc.recaret();
    Candidate c = RankOne("return 1; }", 1);
    ch.receiveCandidate(c);
    GhostText g = MakeGhost(ch.doc.gen, c);
    ch.typeChar('x');
    GhostOnGen(g, ch.doc.gen);
    int typeStale = (g.stale && !GhostLive(g, ch.doc.gen) &&
                     !GhostViewMayPaint(ch.ghost, ch.doc.gen))
                        ? 1
                        : 0;

    const bool pass = cancelOk && staleSuppressed && typeStale;
    std::ofstream seal(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_AUTOCOMPLETE_CANCEL_001\\SEAL.txt");
    seal << "CANCEL_HONORED=" << cancelOk
         << "\nSTALE_SUPPRESSED=" << staleSuppressed
         << "\nTYPE_STALE=" << typeStale
         << "\nRAWRXD_AUTOCOMPLETE_CANCEL_001=" << (pass ? "PASS" : "FAIL")
         << "\n";
    printf("CANCEL_HONORED=%d\nSTALE_SUPPRESSED=%d\nTYPE_STALE=%d\n", cancelOk,
           staleSuppressed, typeStale);
    puts(pass ? "RAWRXD_AUTOCOMPLETE_CANCEL_001=PASS"
              : "RAWRXD_AUTOCOMPLETE_CANCEL_001=FAIL");
    return pass ? 0 : 1;
}
