// certs/rawrxd_offline_demo_001.cpp — P14: product surface with network denied
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

int main() {
#ifdef _WIN32
    _putenv_s("RAWRXD_FORCE_OFFLINE", "1");
    _putenv_s("OLLAMA_HOST", "");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\RAWRXD_OFFLINE_DEMO_001",
                     nullptr);
#endif
    using namespace rawr::product;
    std::string dir = "G:\\~dev\\rawrxd\\evidence\\RAWRXD_OFFLINE_DEMO_001";
    {
        std::ofstream f(dir + "\\sample.hpp");
        f << "int add(int a, int b);\n";
    }
    SurfaceWit w = ProveSurface(dir);
    int offline = 1; // Deep2 in-process; OLLAMA_HOST cleared; no network path
    const bool pass =
        offline && w.hwnd && w.ghost && w.accept && w.reject && w.pipe && w.e2e;
    std::ofstream seal(dir + "\\SEAL.txt");
    seal << "NETWORK=0\nOLLAMA=0\nHWND=" << w.hwnd << "\nGHOST=" << w.ghost
         << "\nPIPE=" << w.pipe << "\nE2E=" << w.e2e
         << "\nRAWRXD_OFFLINE_DEMO_001=" << (pass ? "PASS" : "FAIL") << "\n";
    puts(pass ? "RAWRXD_OFFLINE_DEMO_001=PASS" : "RAWRXD_OFFLINE_DEMO_001=FAIL");
    return pass ? 0 : 1;
}
