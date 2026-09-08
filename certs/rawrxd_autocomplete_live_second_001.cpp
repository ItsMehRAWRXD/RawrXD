// certs/rawrxd_autocomplete_live_second_001.cpp — C06: llama32 ghost path
#include "../src/cli/rawr_product_serve.hpp"
#include "../src/deep2/SemanticSafe.hpp"
#include "../src/deep2/RawrRunSession.hpp"
#include "../src/product/complete/completion_scheduler.hpp"
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
using namespace Deep2;
using namespace Deep2::rawr_run;
using namespace rawr::product;

static bool Llama32Infer(const char* prompt, char* out, size_t cap) {
    static Deep2Engine* eng = nullptr;
    static bool ok = false;
    if (!eng) {
        eng = new Deep2Engine();
        SemanticSafeApply();
        _putenv_s("RAWRXD_GREEDY", "1");
        RunWitness w{};
        ok = OpenSession(*eng, "llama32", w) && w.ollamaProcessUsed == 0 &&
             w.networkUsed == 0;
    }
    if (!ok || !prompt || !out || cap < 8) return false;
    GenerationOptions opts{};
    opts.maxTokens = 24;
    opts.temperature = 0.0f;
    opts.topK = 1;
    opts.seed = 7;
    std::string text;
    eng->generateStream(prompt, opts, [&](int32_t, const std::string& p) {
        text += p;
        return text.size() < 96;
    });
    if (text.empty()) return false;
    size_t n = text.size() < cap - 1 ? text.size() : cap - 1;
    memcpy(out, text.data(), n);
    out[n] = 0;
    return true;
}

int main() {
#ifdef _WIN32
    _putenv_s("RAWRXD_GREEDY", "1");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_AUTOCOMPLETE_LIVE_SECOND_001",
        nullptr);
#endif
    EventBus bus;
    Chrome ch;
    ch.bus = &bus;
    ch.doc.text = "int add(int a, int b) { ";
    ch.doc.caret = ch.doc.text.size();
    ch.doc.recaret();

    CompletionScheduler sch;
    sch.bus = &bus;
    sch.db.delayMs = 0;
    ExecutionRequest req{};
    req.prompt = ch.doc.text;
    req.maxTokens = 24;
    sch.submit(req);
    ExecutionResult r = sch.run(Llama32Infer);

    int realDecode = (r.ok && !r.text.empty() && r.err.empty()) ? 1 : 0;
    Candidate cand = RankOne(r.text.empty() ? "return a + b; }" : r.text, 1);
    int recv = ch.receiveCandidate(cand) ? 1 : 0;
    int ghost = (recv && ch.paintGhost()) ? 1 : 0;
    int accept = 0;
    if (ghost) {
        Chrome acc = ch;
        accept = acc.accept() && acc.doc.text.find(cand.text) != std::string::npos
                     ? 1
                     : 0;
    }
    const bool pass = realDecode && recv && ghost && accept;
    std::ofstream seal(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_AUTOCOMPLETE_LIVE_SECOND_001\\"
        "GATE_STATUS.txt");
    seal << "MODEL=llama32\nREAL_LOCAL_DECODE=" << realDecode
         << "\nOLLAMA=0\nNETWORK=0\nRECV=" << recv << "\nGHOST=" << ghost
         << "\nACCEPT=" << accept << "\nLATENCY_MS=" << r.latencyMs
         << "\nRAWRXD_AUTOCOMPLETE_LIVE_SECOND_001=" << (pass ? "PASS" : "FAIL")
         << "\n";
    puts(pass ? "RAWRXD_AUTOCOMPLETE_LIVE_SECOND_001=PASS"
              : "RAWRXD_AUTOCOMPLETE_LIVE_SECOND_001=FAIL");
    return pass ? 0 : 1;
}
