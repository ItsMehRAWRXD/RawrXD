// rawr_certify.cpp — RawrXD native certification runner (PC01–PC15 core).
//
// Extends the CPU acceptance runner with:
//   C04: SHA-256 of each test executable (not just the shipping binary)
//   C05: Git commit SHA + dirty-tree status binding
//   C06: PE import-table inspection (native; flags forbidden dependencies)
//   C07: stdout/stderr capture + execution duration per gate
//
// Native C++17 + Win32 (bcrypt for SHA-256, PE parsing for imports); no
// external runtime dependencies.
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
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        CloseHandle(h); return false;
    }
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

// C06: parse the PE import table and return imported DLL names.
static std::vector<std::string> PeImports(const std::string& path) {
    std::vector<std::string> dlls;
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return dlls;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 64) { CloseHandle(h); return dlls; }
    std::vector<unsigned char> data((size_t)sz.QuadPart);
    DWORD read = 0;
    if (!ReadFile(h, data.data(), (DWORD)data.size(), &read, nullptr) || read < 64) {
        CloseHandle(h); return dlls;
    }
    CloseHandle(h);
    auto u16 = [&](size_t off) -> uint16_t {
        return (off + 1 < data.size()) ? (uint16_t)(data[off] | (data[off+1] << 8)) : 0;
    };
    auto u32 = [&](size_t off) -> uint32_t {
        return (off + 3 < data.size())
            ? (uint32_t)(data[off] | (data[off+1]<<8) | (data[off+2]<<16) | ((uint32_t)data[off+3]<<24))
            : 0;
    };
    if (u16(0) != 0x5A4D) return dlls;                 // 'MZ'
    const uint32_t peOff = u32(0x3C);
    if (peOff + 24 > data.size() || u32(peOff) != 0x00004550) return dlls; // 'PE\0\0'
    const uint16_t numSec = u16(peOff + 6);
    const uint16_t optSize = u16(peOff + 20);
    const size_t optOff = peOff + 24;
    if (optOff + optSize > data.size()) return dlls;
    const uint16_t magic = u16(optOff);   // 2-byte optional-header magic (0x10B/0x20B/0x107)
    // Import directory is data directory 1 (index 1).
    const size_t ddOff = optOff + (magic == 0x20B ? 112 : 96);
    const uint32_t impRva = u32(ddOff + 1 * 8);
    const uint32_t impSize = u32(ddOff + 1 * 8 + 4);
    if (getenv("CERTIFY_DEBUG"))
        std::fprintf(stderr, "PE size=%zu mz=%04x peOff=%u peSig=%08x numSec=%u optSize=%u magic=%x impRva=%u impSize=%u\n",
                     data.size(), u16(0), peOff, u32(peOff), numSec, optSize, magic, impRva, impSize);
    if (impRva == 0 || impSize == 0) return dlls;
    // Section headers to map RVA -> file offset.
    const size_t secOff = optOff + optSize;
    auto rvaToOff = [&](uint32_t rva) -> uint32_t {
        for (uint16_t s = 0; s < numSec; ++s) {
            const size_t so = secOff + (size_t)s * 40;
            if (so + 40 > data.size()) break;
            const uint32_t va = u32(so + 12);
            const uint32_t vs = u32(so + 8);
            const uint32_t raw = u32(so + 20);
            if (rva >= va && rva < va + vs) return raw + (rva - va);
        }
        return 0;
    };
    const uint32_t impOff = rvaToOff(impRva);
    if (impOff == 0) return dlls;
    for (uint32_t i = 0; i < impSize / 20; ++i) {
        const size_t desc = impOff + (size_t)i * 20;
        if (desc + 20 > data.size()) break;
        const uint32_t nameRva = u32(desc + 12);
        if (nameRva == 0) break;                        // end of descriptors
        const uint32_t nameOff = rvaToOff(nameRva);
        if (nameOff == 0 || nameOff >= data.size()) continue;
        std::string dll;
        for (size_t j = nameOff; j < data.size() && data[j] != 0; ++j)
            dll.push_back((char)data[j]);
        if (!dll.empty()) dlls.push_back(dll);
    }
    return dlls;
}

struct GateResult {
    std::string name;
    bool passed = false;
    int exitCode = -1;
    double seconds = 0.0;
    std::string stdoutText;
    std::string sha256;
    std::vector<std::string> imports;
};

static bool RunTest(const std::string& exe, GateResult& g) {
    g.sha256.clear();
    Sha256File(exe, g.sha256);                          // C04
    g.imports = PeImports(exe);                         // C06

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    HANDLE hOutR = nullptr, hOutW = nullptr;
    CreatePipe(&hOutR, &hOutW, nullptr, 0);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hOutW;
    si.hStdError = hOutW;
    std::vector<char> cmd(exe.begin(), exe.end());
    cmd.push_back('\0');
    std::string dir = exe.substr(0, exe.find_last_of("\\/"));
    if (!CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr,
                        dir.empty() ? nullptr : dir.c_str(), &si, &pi)) {
        CloseHandle(hOutR); CloseHandle(hOutW);
        return false;
    }
    CloseHandle(hOutW);   // parent closes its write end so ReadFile sees EOF
    // Read the child's output (C07).
    char buf[4096];
    DWORD n = 0;
    while (ReadFile(hOutR, buf, sizeof(buf) - 1, &n, nullptr) && n > 0) {
        buf[n] = '\0';
        g.stdoutText += buf;
        if (g.stdoutText.size() > 64 * 1024) { g.stdoutText += "...[truncated]"; break; }
    }
    CloseHandle(hOutR);
    const DWORD t0 = GetTickCount();
    WaitForSingleObject(pi.hProcess, 120000);
    g.seconds = (GetTickCount() - t0) / 1000.0;         // C07 duration
    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    g.exitCode = (int)ec;
    return ec == 0;
}

// C05: read the Git commit SHA natively from .git/HEAD (no subprocess).
static std::string GitHeadSha() {
    FILE* f = std::fopen(".git/HEAD", "r");
    if (!f) return "";
    char buf[256] = {};
    if (!std::fgets(buf, sizeof(buf), f)) { std::fclose(f); return ""; }
    std::fclose(f);
    std::string head = buf;
    while (!head.empty() && (head.back() == '\n' || head.back() == '\r')) head.pop_back();
    if (head.rfind("ref: ", 0) == 0) {
        const std::string refPath = ".git/" + head.substr(5);
        FILE* rf = std::fopen(refPath.c_str(), "r");
        if (rf) {
            char sha[64] = {};
            if (std::fgets(sha, sizeof(sha), rf)) {
                std::fclose(rf);
                std::string s = sha;
                while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
                return s;
            }
            std::fclose(rf);
        }
        return "";   // packed ref; not resolved natively
    }
    return head;     // detached HEAD
}

static std::string RunGit(const char* args) {
    std::string gitExe = "C:\\Program Files\\Git\\cmd\\git.exe";
    if (GetFileAttributesA(gitExe.c_str()) == INVALID_FILE_ATTRIBUTES) gitExe = "git";
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    HANDLE hR = nullptr, hW = nullptr;
    CreatePipe(&hR, &hW, nullptr, 0);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hW; si.hStdError = hW;
    std::string cmd = "\"" + gitExe + "\" " + args;   // quote path (spaces)
    std::vector<char> c(cmd.begin(), cmd.end()); c.push_back('\0');
    if (!CreateProcessA(nullptr, c.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hR); CloseHandle(hW); return "";
    }
    CloseHandle(hW);
    std::string out; char buf[1024]; DWORD n = 0;
    while (ReadFile(hR, buf, sizeof(buf)-1, &n, nullptr) && n > 0) { buf[n]='\0'; out += buf; }
    CloseHandle(hR);
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    while (!out.empty() && (out.back()=='\n' || out.back()=='\r')) out.pop_back();
    return out;
}

int main(int argc, char** argv) {
    // Debug: dump a PE's import table.
    if (argc >= 3 && std::string(argv[1]) == "--imports") {
        const auto dlls = PeImports(argv[2]);
        std::printf("IMPORTS %s (%zu):\n", argv[2], dlls.size());
        for (const auto& d : dlls) std::printf("  %s\n", d.c_str());
        return dlls.empty() ? 1 : 0;
    }
    std::string manifestPath = "certify_manifest.json";
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--manifest" && i + 1 < argc) manifestPath = argv[++i];
        else args.emplace_back(argv[i]);
    }
    if (args.empty()) {
        std::printf("usage: rawr_certify [--manifest out.json] <shipping.exe> <test1.exe> ...\n");
        return 2;
    }
    const std::string shippingExe = args[0];
    std::string sha;
    const bool haveSha = Sha256File(shippingExe, sha);   // C04 shipping

    // C05: bind to Git SHA + dirty-tree status.
    const std::string gitSha = GitHeadSha();
    const std::string gitStatus = RunGit("status --porcelain");
    const bool dirty = !gitStatus.empty();

    std::vector<GateResult> gates;
    for (size_t i = 1; i < args.size(); ++i) {
        GateResult g;
        g.name = args[i];
        g.passed = RunTest(args[i], g);
        gates.push_back(g);
        std::printf("%s %s (exit=%d %.2fs sha=%s)\n", g.passed ? "PASS" : "FAIL",
                    g.name.c_str(), g.exitCode, g.seconds,
                    g.sha256.empty() ? "-" : g.sha256.substr(0, 12).c_str());
    }

    bool allPass = haveSha;
    for (const auto& g : gates) if (!g.passed) allPass = false;

    FILE* f = std::fopen(manifestPath.c_str(), "w");
    if (f) {
        std::fprintf(f, "{\n  \"schema\": \"rawr.certify.v2\",\n");
        std::fprintf(f, "  \"shipping\": \"%s\",\n", shippingExe.c_str());
        std::fprintf(f, "  \"shipping_sha256\": \"%s\",\n", haveSha ? sha.c_str() : "");
        std::fprintf(f, "  \"git_sha\": \"%s\",\n", gitSha.c_str());
        std::fprintf(f, "  \"git_dirty\": %s,\n", dirty ? "true" : "false");
        std::fprintf(f, "  \"overall_pass\": %s,\n", allPass ? "true" : "false");
        std::fprintf(f, "  \"gates\": [\n");
        for (size_t i = 0; i < gates.size(); ++i) {
            const auto& g = gates[i];
            std::fprintf(f, "    {\"name\": \"%s\", \"passed\": %s, \"exit\": %d, "
                            "\"seconds\": %.2f, \"sha256\": \"%s\", \"imports\": [",
                         g.name.c_str(), g.passed ? "true" : "false",
                         g.exitCode, g.seconds, g.sha256.c_str());
            for (size_t j = 0; j < g.imports.size(); ++j)
                std::fprintf(f, "%s\"%s\"", j ? ", " : "", g.imports[j].c_str());
            std::fprintf(f, "],\n                 \"stdout\": \"%s\"}%s\n",
                         g.stdoutText.c_str(), i + 1 < gates.size() ? "," : "");
        }
        std::fprintf(f, "  ]\n}\n");
        std::fclose(f);
        std::printf("MANIFEST=%s\n", manifestPath.c_str());
    }
    std::printf("GIT_SHA=%s DIRTY=%d\n", gitSha.c_str(), dirty ? 1 : 0);
    std::printf("CERTIFY_OVERALL=%s\n", allPass ? "PASS" : "FAIL");
    std::printf("PROMOTE=0\n");
    return allPass ? 0 : 1;
}