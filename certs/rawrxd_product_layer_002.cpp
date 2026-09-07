// RAWRXD_PRODUCT_LAYER_002 — watcher, guard, ghost, debug, gateway, crash
#include "../src/product/product_layer.hpp"
#include <cstdio>
#include <fstream>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

static int fail(const char* w) {
    fprintf(stderr, "FAIL: %s\n", w);
    puts("RAWRXD_PRODUCT_LAYER_002=FAIL");
    return 1;
}

int main() {
    using namespace rawr::product;
    if (!AbiOk()) return fail("abi");
    std::string dir = "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_LAYER_002";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(dir.c_str(), nullptr);
    std::string fpath = dir + "\\mod.hpp";
    {
        std::ofstream f(fpath);
        f << "class Mod { void run(); };\nvoid run() {}\n";
    }

    IncrementalIndex inc;
    if (!inc.ingest(fpath)) return fail("ingest");
    if (inc.ingest(fpath)) return fail("idempotent");
    {
        std::ofstream f(fpath);
        f << "class Mod { void run(); void stop(); };\nvoid stop() {}\n";
    }
    if (!inc.ingest(fpath)) return fail("delta");

    WatchIndex wi;
    if (!wi.start(dir)) return fail("watch");
    wi.pollAndIngest(fpath);
    wi.stop();

    if (!EvidenceExists(inc.idx.symbols, "Mod")) return fail("ev");
    if (GuardClaim(inc.idx.symbols, "class MissingType")) return fail("hallu");
    if (!GuardClaim(inc.idx.symbols, "class Mod")) return fail("claim");

    Candidate c = RankOne("int stop() { return 0; }", 1);
    GhostText g = MakeGhost(3, c);
    if (!GhostLive(g, 3)) return fail("ghost");

    EditorEvent ev{};
    ev.kind = IdeEv::Edit;
    ev.snap.path = fpath;
    TaskStatus st{"index", "index", 40};
    if (!StatusLine(st)) return fail("status");

    auto frames = ParseStack("RawrXD!run at mod.hpp:2\nRawrXD!main at main.cpp:10\n");
    if (frames.size() < 2 || frames[0].line != 2) return fail("stack");
    std::vector<Diag> ds{{fpath, 2, "error C2065: x"}, {fpath, 9, "error C2065: y"}};
    if (GroupDiags(ds).size() != 1) return fail("diag");

    auto cmd = ParseProductCmd("PING");
    if (HandleProductCmd(cmd).find("PONG") == std::string::npos)
        return fail("proto");

    CrashJournal j;
    j.path = dir + "\\crash.journal";
    if (!j.mark("psess_x", "complete")) return fail("crash");
    std::string sid, stage;
    if (!j.last(sid, stage) || sid != "psess_x") return fail("recover");

    EvalCase e{"CTX001", "<PRE>", 0};
    e.pass = EvalMatch("<PRE>\nint", e.expect);
    if (!e.pass) return fail("eval");

    std::ofstream seal(dir + "\\SEAL.txt");
    seal << "INCREMENTAL=1\nWATCH=1\nGUARD=1\nGHOST=1\nSTACK=1\n"
            "DIAG_GROUP=1\nPROTOCOL=1\nCRASH=1\nEVAL=1\n"
            "RAWRXD_PRODUCT_LAYER_002=PASS\n";
    puts("RAWRXD_PRODUCT_LAYER_002=PASS");
    return 0;
}
