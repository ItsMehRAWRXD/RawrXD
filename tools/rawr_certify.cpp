// rawr_certify.cpp — RawrXD native certification runner (PC01/PC15 core).
//
// Runs a set of CPU acceptance test executables, captures each exit code, and
// emits a fail-closed JSON manifest with the shipping executable's SHA-256.
// Native C++17 + Win32 (bcrypt for SHA-256); no external runtime dependencies.
//
// Usage:
//   rawr_certify <shipping.exe> <test1.exe> [test2.exe ...]
//   rawr_certify --manifest <out.json> <shipping.exe> <test1.exe> ...
//
// Exit 0 = all gates pass; 1 = a gate failed; 2 = usage/IO error.

#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

static bool Sha256File(const std::string& path, std::string& hexOut) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)
        != 0) { CloseHandle(h); return false; }
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0); CloseHandle(h); return false;
    }
    std::vector<unsigned char> buf(1 << 20);
    DWORD n = 0;
    bool ok = true;
    while (ReadFile(h, buf.data(), (DWORD)buf.size(), &n, nullptr) && n > 0) {
        if (BCryptHashData(hash, buf.data(), n, 0) != 0) { ok = false; break; }
    }
    if (ok) {
        unsigned char digest[32];
        if (BCryptFinishHash(hash, digest, sizeof(digest), 0) != 0) ok = false;
        else {
            static const char* hex = "0123456789abcdef";
            hexOut.assign(64, '0');
            for (int i = 0; i < 32; ++i) {
                hexOut[i*2]   = hex[digest[i] >> 4];
                hexOut[i*2+1] = hex[digest[i] & 0xF];
            }
        }
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(h);
    return ok;
}

struct GateResult {
    std::string name;
    bool passed = false;
    int exitCode = -1;
};

static bool RunTest(const std::string& exe, int& exitCode) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    // Redirect the child's stdout/stderr to nul so its output does not clutter
    // the certification log and does not depend on an inherited console.
    HANDLE hNul = CreateFileA("nul", GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, 0, nullptr);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hNul;
    si.hStdError = hNul;
    std::vector<char> cmd(exe.begin(), exe.end());
    cmd.push_back('\0');
    // Working directory = the test executable's directory.
    std::string dir = exe.substr(0, exe.find_last_of("\\/"));
    if (!CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr,
                        dir.empty() ? nullptr : dir.c_str(), &si, &pi)) {
        if (hNul) CloseHandle(hNul);
        return false;
    }
    if (hNul) CloseHandle(hNul);
    WaitForSingleObject(pi.hProcess, 120000);   // 2 min per gate
    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    exitCode = (int)ec;
    return ec == 0;
}

int main(int argc, char** argv) {
    std::string manifestPath = "certify_manifest.json";
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--manifest" && i + 1 < argc) {
            manifestPath = argv[++i];
        } else {
            args.emplace_back(argv[i]);
        }
    }
    if (args.empty()) {
        std::printf("usage: rawr_certify [--manifest out.json] <shipping.exe> <test1.exe> ...\n");
        return 2;
    }
    const std::string shippingExe = args[0];
    std::string sha;
    const bool haveSha = Sha256File(shippingExe, sha);

    std::vector<GateResult> gates;
    for (size_t i = 1; i < args.size(); ++i) {
        GateResult g;
        g.name = args[i];
        g.passed = RunTest(args[i], g.exitCode);
        gates.push_back(g);
        std::printf("%s %s (exit=%d)\n", g.passed ? "PASS" : "FAIL",
                    g.name.c_str(), g.exitCode);
    }

    bool allPass = haveSha;
    for (const auto& g : gates) if (!g.passed) allPass = false;

    FILE* f = std::fopen(manifestPath.c_str(), "w");
    if (f) {
        std::fprintf(f, "{\n  \"schema\": \"rawr.certify.v1\",\n");
        std::fprintf(f, "  \"shipping\": \"%s\",\n", shippingExe.c_str());
        std::fprintf(f, "  \"shipping_sha256\": \"%s\",\n", haveSha ? sha.c_str() : "");
        std::fprintf(f, "  \"overall_pass\": %s,\n", allPass ? "true" : "false");
        std::fprintf(f, "  \"gates\": [\n");
        for (size_t i = 0; i < gates.size(); ++i) {
            std::fprintf(f, "    {\"name\": \"%s\", \"passed\": %s, \"exit\": %d}%s\n",
                         gates[i].name.c_str(), gates[i].passed ? "true" : "false",
                         gates[i].exitCode, i + 1 < gates.size() ? "," : "");
        }
        std::fprintf(f, "  ]\n}\n");
        std::fclose(f);
        std::printf("MANIFEST=%s\n", manifestPath.c_str());
    }
    std::printf("CERTIFY_OVERALL=%s\n", allPass ? "PASS" : "FAIL");
    std::printf("PROMOTE=0\n");
    return allPass ? 0 : 1;
}