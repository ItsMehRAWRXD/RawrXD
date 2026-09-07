// RAWRXD_WIN32_EDITOR_SURFACE_001 — chrome + ghost + pipe + agent slice
#include "../src/product/win32/surface_proof.hpp"
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
    puts("RAWRXD_WIN32_EDITOR_SURFACE_001=FAIL");
    return 1;
}

int main() {
    using namespace rawr::product;
    std::string dir =
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_WIN32_EDITOR_SURFACE_001";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(dir.c_str(), nullptr);
    {
        std::ofstream f(dir + "\\sample.hpp");
        f << "int add(int a, int b);\n";
    }
    SurfaceWit w = ProveSurface(dir);
    printf("RAWRXD_WIN32_EDITOR_SURFACE_001=%s\n", w.hwnd && w.recv ? "PASS" : "FAIL");
    printf("RAWRXD_GHOST_TEXT_001=%s\n", w.ghost ? "PASS" : "FAIL");
    printf("RAWRXD_GHOST_ACCEPT_001=%s\n", w.accept ? "PASS" : "FAIL");
    printf("RAWRXD_GHOST_REJECT_001=%s\n", w.reject ? "PASS" : "FAIL");
    printf("RAWRXD_TASK_STATUS_UI_001=%s\n", w.status ? "PASS" : "FAIL");
    printf("RAWRXD_RAWR_PIPE_001=%s\n", w.pipe ? "PASS" : "FAIL");
    printf("RAWRXD_EDITOR_AGENT_E2E_001=%s\n", w.e2e ? "PASS" : "FAIL");
    int all = w.hwnd && w.recv && w.ghost && w.accept && w.reject && w.status &&
              w.pipe && w.e2e;
    std::ofstream seal(dir + "\\SEAL.txt");
    seal << "HWND=" << w.hwnd << "\nRECV=" << w.recv << "\nGHOST=" << w.ghost
         << "\nACCEPT=" << w.accept << "\nREJECT=" << w.reject
         << "\nSTATUS=" << w.status << "\nPIPE=" << w.pipe
         << "\nE2E=" << w.e2e << "\n";
    seal << "RAWRXD_WIN32_EDITOR_SURFACE_001=" << (all ? "PASS" : "FAIL")
         << "\nRAWRXD_GHOST_TEXT_001=" << (w.ghost ? "PASS" : "FAIL")
         << "\nRAWRXD_GHOST_ACCEPT_001=" << (w.accept ? "PASS" : "FAIL")
         << "\nRAWRXD_GHOST_REJECT_001=" << (w.reject ? "PASS" : "FAIL")
         << "\nRAWRXD_TASK_STATUS_UI_001=" << (w.status ? "PASS" : "FAIL")
         << "\nRAWRXD_RAWR_PIPE_001=" << (w.pipe ? "PASS" : "FAIL")
         << "\nRAWRXD_EDITOR_AGENT_E2E_001=" << (w.e2e ? "PASS" : "FAIL") << "\n";
    if (!all) return fail("surface");
    puts("RAWRXD_WIN32_EDITOR_SURFACE_001=PASS");
    return 0;
}
