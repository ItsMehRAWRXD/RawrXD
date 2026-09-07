// certs/rawrxd_repeatable_demo_record_001.cpp — P15: hash evidence bundle
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#endif

static std::string Sha256File(const char* path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return "";
    std::ostringstream ss;
    ss << in.rdbuf();
    std::string body = ss.str();
#ifdef _WIN32
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    if (!CryptAcquireContextA(&prov, nullptr, nullptr, PROV_RSA_AES,
                              CRYPT_VERIFYCONTEXT))
        return "";
    if (!CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
        CryptReleaseContext(prov, 0);
        return "";
    }
    CryptHashData(hash, (const BYTE*)body.data(), (DWORD)body.size(), 0);
    BYTE dig[32];
    DWORD n = 32;
    CryptGetHashParam(hash, HP_HASHVAL, dig, &n, 0);
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
    char hex[65];
    for (int i = 0; i < 32; ++i) sprintf(hex + i * 2, "%02x", dig[i]);
    hex[64] = 0;
    return hex;
#else
    (void)body;
    return "unsupported";
#endif
}

int main() {
    const char* root = "G:\\~dev\\rawrxd\\evidence";
    CreateDirectoryA(root, nullptr);
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_REPEATABLE_DEMO_RECORD_001",
        nullptr);
    const char* files[] = {
        "RAWRXD_WIN32_EDITOR_SURFACE_001\\SEAL.txt",
        "RAWRXD_RAWR_PIPE_001\\SEAL.txt",
        "RAWRXD_EDITOR_AGENT_E2E_001\\SEAL.txt",
        "RAWRXD_PRODUCT_LAYER_001\\SEAL.txt",
        "RAWRXD_PRODUCT_LAYER_002\\SEAL.txt",
        "RAWRXD_AGENT_STEER_RESUME_001\\GATE.txt",
        "RAWRXD_SECOND_MODEL_001\\GATE_STATUS.txt",
        "RAWRXD_PRODUCT_UNLOCK_15\\LADDER.txt",
    };
    std::ofstream man(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_REPEATABLE_DEMO_RECORD_001\\"
        "SHA256_MANIFEST.txt");
    int ok = 0, n = 0;
    for (const char* rel : files) {
        std::string path = std::string(root) + "\\" + rel;
        std::string h = Sha256File(path.c_str());
        ++n;
        if (!h.empty()) {
            ++ok;
            man << h << "  " << rel << "\n";
        } else {
            man << "MISSING  " << rel << "\n";
        }
    }
    const bool pass = ok >= 7;
    man << "RAWRXD_REPEATABLE_DEMO_RECORD_001=" << (pass ? "PASS" : "FAIL")
        << "\n";
    std::ofstream seal(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_REPEATABLE_DEMO_RECORD_001\\SEAL.txt");
    seal << "HASHED=" << ok << "\nTOTAL=" << n
         << "\nRAWRXD_REPEATABLE_DEMO_RECORD_001=" << (pass ? "PASS" : "FAIL")
         << "\n";
    puts(pass ? "RAWRXD_REPEATABLE_DEMO_RECORD_001=PASS"
              : "RAWRXD_REPEATABLE_DEMO_RECORD_001=FAIL");
    return pass ? 0 : 1;
}
