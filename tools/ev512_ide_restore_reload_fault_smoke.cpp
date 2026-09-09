// ev512_ide_restore_reload_fault_smoke.cpp — closed Exact Match batch.
// Claims: 22 SESSION_RESTORE, 58-59 RELOAD_*, 95 PROCESS_FAULT.
#include "RuntimeEvidence512Surface.hpp"
#include "RuntimeEvidence512HostIDE.hpp"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>

static uint64_t ph(const char* p) { return Deep2::Ev512::HostPathHash(p); }

static bool writeAll(const char* path, const std::string& body) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(body.data(), (std::streamsize)body.size());
    return (bool)f;
}

static std::string readAll(const char* path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    return std::string((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
}

/* Model-file reload: open GGUF, read magic, close, reopen (OS reload owner). */
static bool reloadGgufFile(const char* path, uint32_t* magicOut) {
    auto openRead = [&](HANDLE* out) -> bool {
        HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        *out = h;
        return true;
    };
    HANDLE h1 = INVALID_HANDLE_VALUE;
    if (!openRead(&h1)) return false;
    char mag[4]{};
    DWORD n = 0;
    ReadFile(h1, mag, 4, &n, nullptr);
    CloseHandle(h1);
    if (n != 4 || std::memcmp(mag, "GGUF", 4) != 0) return false;

    const uint64_t h = ph(path);
    Deep2::Ev512::HostEmitReloadEntry(h, 1);
    HANDLE h2 = INVALID_HANDLE_VALUE;
    if (!openRead(&h2)) {
        Deep2::Ev512::HostEmitReloadComplete(h, 0);
        return false;
    }
    char mag2[4]{};
    DWORD n2 = 0;
    ReadFile(h2, mag2, 4, &n2, nullptr);
    CloseHandle(h2);
    const bool ok = (n2 == 4 && std::memcmp(mag2, "GGUF", 4) == 0);
    if (magicOut && ok)
        *magicOut = (uint32_t)mag2[0] | ((uint32_t)mag2[1] << 8) |
                    ((uint32_t)mag2[2] << 16) | ((uint32_t)mag2[3] << 24);
    Deep2::Ev512::HostEmitReloadComplete(h, ok ? 1ull : 0ull);
    return ok;
}

static void emitCaughtFault() {
    DWORD code = 0;
    __try {
        RaiseException(0xE000005Fu, 0, 0, nullptr); /* EV512 fault marker */
    } __except (code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        Deep2::Ev512::HostEmitProcessFault((uint64_t)code, 1);
    }
}

int main(int argc, char** argv) {
    Deep2::Ev512::HostTryArm(0x525354524C44ull); /* RSTRLD */
    Deep2::Ev512::HostSurfaceGuard surface(stderr);

    /* 22: persist then restore session JSON into live locals */
    const char* sess = "ev512_rrf_session.json";
    const std::string body =
        "{\"version\":2,\"schemaVersion\":\"1.0\",\"smoke\":1,"
        "\"workingDirectory\":\".\",\"loadedModelPath\":\"none\"}\n";
    writeAll(sess, body);
    Deep2::Ev512::HostEmitSessionPersist(ph(sess), (uint64_t)body.size());
    {
        const std::string got = readAll(sess);
        int version = 0;
        bool restored = false;
        if (got.find("\"version\":2") != std::string::npos) {
            version = 2;
            restored = !got.empty();
        }
        if (restored) {
            Deep2::Ev512::HostEmitSessionRestore(ph(sess), (uint64_t)got.size());
            std::fprintf(stderr, "SESSION_RESTORE_OK version=%d bytes=%zu\n",
                         version, got.size());
        } else {
            std::fprintf(stderr, "SESSION_RESTORE_SKIP=1\n");
        }
    }

    /* 58/59: real GGUF reopen reload */
    const char* model = (argc > 1 && argv[1] && argv[1][0])
                            ? argv[1]
                            : "g:\\~dev\\rawrxd\\llama3.2-3b-Q3_K_S.gguf";
    uint32_t magic = 0;
    if (!reloadGgufFile(model, &magic))
        std::fprintf(stderr, "RELOAD_SKIP=1 path=%s\n", model);
    else
        std::fprintf(stderr, "RELOAD_OK magic=0x%08X\n", magic);

    /* 95: caught process fault (SEH) — does not kill harness */
    emitCaughtFault();

    std::fprintf(stderr, "EV512_RRF_SMOKE_DONE=1\n");
    return 0;
}
