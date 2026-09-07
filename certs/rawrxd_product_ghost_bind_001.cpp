// RAWRXD_PRODUCT_GHOST_BIND_001 — product candidate is the only ghost authority
#include "../src/product/win32/surface_proof.hpp"
#include "../src/win32app/ProductGhostBind.hpp"
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
    puts("RAWRXD_PRODUCT_GHOST_BIND_001=FAIL");
    return 1;
}

int main() {
    using namespace rawr::product;
    std::string dir =
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_GHOST_BIND_001";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(dir.c_str(), nullptr);
    {
        std::ofstream f(dir + "\\sample.hpp");
        f << "int add(int a, int b);\n";
    }

    Chrome ch;
    ch.doc.text = "int add(int a, int b) { ";
    ch.doc.caret = ch.doc.text.size();
    ch.doc.recaret();
    Candidate cand = RankOne("return a + b; }", 1);
    cand.id = GhostIdent(cand.text.c_str());
    std::string before = ch.doc.text;
    if (!ch.receiveCandidate(cand)) return fail("recv");

    int rec = 1;
    int src = ch.ghost.source == GhostSrcProduct ? 1 : 0;
    int textPar = ch.ghost.content == cand.text ? 1 : 0;
    int posPar = (ch.ghost.line == (int)ch.doc.line &&
                  ch.ghost.col == (int)ch.doc.col)
                     ? 1
                     : 0;
    int genPar = ch.ghost.gen == ch.doc.gen ? 1 : 0;
    Win32GhostView snap = ch.ghost;
    int legacy = BindLegacyGhost(snap, "ollama-or-lsp") ? 1 : 0;
    int unchanged = (ch.doc.text == before && ch.paintGhost() &&
                     GhostViewMayPaint(ch.ghost, ch.doc.gen))
                        ? 1
                        : 0;

    Chrome acc = ch;
    int accTxn = acc.accept() && acc.overlay.docMutated ? 1 : 0;
    int accPar = acc.doc.text.find(cand.text) != std::string::npos ? 1 : 0;

    Chrome rej = ch;
    rej.typeChar('x');
    int typeInv = (!GhostViewMayPaint(rej.ghost, rej.doc.gen) &&
                   rej.ghost.source == GhostSrcProduct)
                      ? 1
                      : 0;
    int stalePaint = GhostViewMayPaint(rej.ghost, rej.doc.gen) ? 1 : 0;

    SurfaceWit w = ProveSurface(dir);
    int all = rec && src && textPar && posPar && genPar && !legacy && unchanged &&
              accTxn && accPar && typeInv && !stalePaint && w.ghost && w.accept &&
              w.reject && w.e2e;

    std::ofstream seal(dir + "\\SEAL.txt");
    seal << "PRODUCT_CANDIDATE_RECEIVED=" << rec
         << "\nGHOST_SOURCE=" << (src ? "PRODUCT" : "OTHER")
         << "\nTEXT_PARITY=" << textPar << "\nPOSITION_PARITY=" << posPar
         << "\nGENERATION_PARITY=" << genPar
         << "\nLEGACY_COMPLETION_SOURCE=" << legacy
         << "\nDOCUMENT_BYTES_BEFORE_ACCEPT_UNCHANGED=" << unchanged
         << "\nACCEPT_VIA_DOCUMENT_TRANSACTION=" << accTxn
         << "\nACCEPT_TEXT_PARITY=" << accPar
         << "\nTYPE_INVALIDATES_PRODUCT_GHOST=" << typeInv
         << "\nSTALE_PRODUCT_CANDIDATE_PAINTED=" << stalePaint << "\n";
    seal << "RAWRXD_GHOST_TEXT_001=" << (w.ghost ? "PASS" : "FAIL")
         << "\nRAWRXD_GHOST_ACCEPT_001=" << (w.accept ? "PASS" : "FAIL")
         << "\nRAWRXD_GHOST_REJECT_001=" << (w.reject ? "PASS" : "FAIL")
         << "\nRAWRXD_EDITOR_AGENT_E2E_001=" << (w.e2e ? "PASS" : "FAIL")
         << "\nRAWRXD_PRODUCT_GHOST_BIND_001=" << (all ? "PASS" : "FAIL")
         << "\n";
    printf("RAWRXD_GHOST_TEXT_001=%s\n", w.ghost ? "PASS" : "FAIL");
    printf("RAWRXD_GHOST_ACCEPT_001=%s\n", w.accept ? "PASS" : "FAIL");
    printf("RAWRXD_GHOST_REJECT_001=%s\n", w.reject ? "PASS" : "FAIL");
    printf("RAWRXD_EDITOR_AGENT_E2E_001=%s\n", w.e2e ? "PASS" : "FAIL");
    puts(all ? "RAWRXD_PRODUCT_GHOST_BIND_001=PASS"
             : "RAWRXD_PRODUCT_GHOST_BIND_001=FAIL");
    return all ? 0 : 1;
}
