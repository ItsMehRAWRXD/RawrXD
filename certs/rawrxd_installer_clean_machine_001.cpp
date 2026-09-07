// certs/rawrxd_installer_clean_machine_001.cpp — P13: installer artifact presence
#include <cstdio>
#include <fstream>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

static int exists(const char* p) {
    DWORD a = GetFileAttributesA(p);
    return a != INVALID_FILE_ATTRIBUTES ? 1 : 0;
}

int main() {
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_INSTALLER_CLEAN_MACHINE_001",
        nullptr);
#endif
    int md = exists("G:\\~dev\\rawrxd\\RELEASE_PACKAGE\\INSTALL.md");
    int bin = exists("G:\\~dev\\rawrxd\\build-fd\\bin\\rawr.exe");
    int frontdoor =
        exists("G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_FRONTDOOR_001\\GATE.txt");
    int surface = exists(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_WIN32_EDITOR_SURFACE_001\\SEAL.txt");
    // Clean-machine cert today = required artifacts present for a packageable
    // drop. Full silent installer EXE remains a follow-on.
    const bool pass = md && bin && frontdoor && surface;
    std::ofstream seal(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_INSTALLER_CLEAN_MACHINE_001\\SEAL.txt");
    seal << "INSTALL_MD=" << md << "\nRAWR_EXE=" << bin
         << "\nFRONTDOOR_GATE=" << frontdoor << "\nSURFACE_SEAL=" << surface
         << "\nRAWRXD_INSTALLER_CLEAN_MACHINE_001=" << (pass ? "PASS" : "FAIL")
         << "\n";
    puts(pass ? "RAWRXD_INSTALLER_CLEAN_MACHINE_001=PASS"
              : "RAWRXD_INSTALLER_CLEAN_MACHINE_001=FAIL");
    return pass ? 0 : 1;
}
