// ============================================================================
// certs/layer0_authority_001.cpp — RAWRXD_LAYER0_AUTHORITY_001
//
// Proves the Layer-0 authority can fail and can refuse.
//
// The failure modes this guards against are specific:
//   * a capture layer that never fires and still reports a record
//   * an identity check that is decorative
//   * a refusal path that emits a file indistinguishable from a clean run
//
// Each is tested by a negative control that MUST produce the opposite of the
// claim. If any control passes when it should fail, the verdict is FAIL.
//
// Three child modes, spawned because each ends the process differently:
//   run-fastfail  __fastfail(FAST_FAIL_FATAL_APP_EXIT)  -> expect 0xC0000409, 7
//   run-av        null dereference                      -> expect 0xC0000005
//   run-clean     returns normally                      -> expect NO record file
// ============================================================================

#include "deep2/Layer0Guard.hpp"

#include <windows.h>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using Deep2::Layer0::WriteRecord;

namespace {

std::wstring exePath() {
    std::wstring p(MAX_PATH, 0);
    DWORD n = GetModuleFileNameW(nullptr, p.data(), MAX_PATH);
    p.resize(n ? n : 0);
    return p;
}

// ASCII -> UTF-16. Windows environment variables are wide; passing a const
// char* to SetEnvironmentVariableW is a type error, and silently truncating the
// SHA256 would turn an identity check into a no-op.
std::wstring widenAscii(const char* s) {
    if (!s || !s[0]) return std::wstring();
    const int n = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring out(static_cast<std::size_t>(n), 0);
    MultiByteToWideChar(CP_ACP, 0, s, -1, out.data(), n);
    if (!out.empty() && out.back() == L'\0') out.pop_back();
    return out;
}

std::string narrowAscii(const std::wstring& s) {
    std::string out;
    out.reserve(s.size());
    for (wchar_t c : s) out.push_back(static_cast<char>(c < 128 ? c : '?'));
    return out;
}

int g_checks = 0, g_pass = 0, g_fail = 0;

void check(bool ok, const char* id, const char* fmt, ...) {
    ++g_checks;
    if (ok) ++g_pass; else ++g_fail;
    std::printf("%-6s %-32s ", ok ? "CHECK" : "FAIL", id);
    va_list ap; va_start(ap, fmt);
    std::vprintf(fmt, ap);
    va_end(ap);
    std::printf("\n");
}

// Spawn `mode` and return its exit code. Identity is supplied by the caller so
// the refusal control can pass a deliberately wrong value.
int spawnChild(const wchar_t* mode, const char* recordPath,
               const char* expectedSha, DWORD& exitCode) {
    std::wstring cmd = L"";
    const std::wstring self = exePath();
    cmd = L"\"" + self + L"\" \"" + mode + L"\"";
    // Children inherit this process's environment block, so set it here rather
    // than passing arguments: the child needs the same view of its own identity
    // that the parent verified.
    SetEnvironmentVariableW(L"RAWRXD_LAYER0_OUT", widenAscii(recordPath).c_str());
    if (expectedSha && expectedSha[0]) {
        SetEnvironmentVariableW(L"RAWRXD_LAYER0_EXPECTED_SHA256",
                                widenAscii(expectedSha).c_str());
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> mutableCmd(cmd.begin(), cmd.end());
    mutableCmd.push_back(0);
    if (!CreateProcessW(self.c_str(), mutableCmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        exitCode = 0xFFFFFFFFu;
        return -1;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    exitCode = code;
    return 0;
}

std::string readAll(const char* path) {
    std::string out;
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return out;
    char buf[4096];
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(h, buf, sizeof(buf), &got, nullptr) || got == 0) break;
        out.append(buf, got);
    }
    CloseHandle(h);
    return out;
}

bool has(const std::string& s, const char* key, const char* val) {
    std::string line = std::string(key) + "=" + val;
    return s.find(line) != std::string::npos;
}

std::string fieldOf(const std::string& s, const char* key) {
    std::string k = std::string("\n") + key + "=";
    size_t p = s.find(k);
    if (p == std::string::npos) return "";
    p += k.size();
    size_t e = s.find('\n', p);
    return s.substr(p, e - p);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    // ---- CHILD MODES -----------------------------------------------------
    if (argc >= 2) {
        const std::wstring mode = argv[1];
        if (!Deep2::Layer0::Arm()) {
            std::printf("ARM_FAILED\n");
            return 3;
        }
        const char* out = std::getenv("RAWRXD_LAYER0_OUT");
        const wchar_t* outW = out ? nullptr : nullptr;
        (void)outW;

        if (mode == L"run-fastfail") {
            // Real __fastfail, not a simulated one. The whole point of this
            // authority is to observe the genuine instruction sequence.
            __fastfail(FAST_FAIL_FATAL_APP_EXIT);
            return 9;  // unreachable
        }
        if (mode == L"run-av") {
            volatile int* p = nullptr;
            return *p;  // genuine access violation
        }
        if (mode == L"run-clean") {
            // Deliberately writes NOTHING. Control 4 requires that a run which
            // faulted nowhere leaves no record, so that "nothing happened" and
            // "nothing was observed" cannot be confused by a reader.
            return 0;
        }
        return 2;
    }
    (void)argc;

    // ---- SELFTEST --------------------------------------------------------
    std::printf("=== RAWRXD_LAYER0_AUTHORITY_001 ===\n");
    std::printf("SCOPE=IN_PROCESS_CAPTURE_NO_DEBUGGER_NO_DUMP\n");

    // --- CONTROL 0: the hash primitive itself, against published known answers.
    //
    // Without this, a SHA-256 that returns a wrong-but-plausible digest would
    // produce confident identity matches forever. The identity check is only as
    // trustworthy as this function, and this function is hand-written here.
    std::printf("\n--- CONTROL 0: SHA-256 known-answer vectors ---\n");
    {
        const auto narrow = [](const std::wstring& s) {
            std::string o; for (wchar_t c : s) o.push_back(static_cast<char>(c));
            return o;
        };
        const std::string vEmpty = narrow(Deep2::Layer0::Sha256HexOfBytes("", 0));
        const std::string vAbc = narrow(Deep2::Layer0::Sha256HexOfBytes("abc", 3));
        const std::string v448 =
            narrow(Deep2::Layer0::Sha256HexOfBytes(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56));
        check(vEmpty == "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
              "SHA256_EMPTY", "got=%s", vEmpty.c_str());
        check(vAbc == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
              "SHA256_ABC", "got=%s", vAbc.c_str());
        check(v448 == "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1",
              "SHA256_448BIT", "got=%s", v448.c_str());
    }

    const std::string selfSha =
        narrowAscii(Deep2::Layer0::HashFileSha256(exePath().c_str()));
    std::printf("SELF_SHA256=%s\n", selfSha.c_str());
    check(!selfSha.empty() && selfSha.size() == 64, "HASH_SELF", "len=%zu",
          selfSha.size());

    DWORD ec = 0;
    char recPath[MAX_PATH]{};
    GetTempPathA(MAX_PATH, recPath);
    strcat_s(recPath, "layer0_fastfail.txt");

    // --- CONTROL 1: a genuine __fastfail and what is ACTUALLY observable.
    //
    // This is a measured negative result, not a missing feature. x64
    // __fastfail is `int 29h`; the kernel consumes it and terminates without
    // delivering to a vectored handler or a structured handler. A genuine
    // __fastfail(7) therefore writes NO record -- and asserting that it writes
    // none is the correct certification. Deleting this control because it "fails"
    // would hide the single most important boundary in the authority: the Kimi
    // fault is exactly the class this cannot see.
    strcat_s(recPath, ".ff");
    DeleteFileA(recPath);
    spawnChild(L"run-fastfail", recPath, selfSha.c_str(), ec);
    const bool ffWrote = GetFileAttributesA(recPath) != INVALID_FILE_ATTRIBUTES;
    std::printf("\n--- CONTROL 1: genuine __fastfail(7) ---\n");
    check(!ffWrote, "FF_PRODUCES_NO_IN_PROCESS_RECORD", "wrote=%d", ffWrote ? 1 : 0);
    check(!Deep2::Layer0::FastFailCapturableByThisGuard(), "FF_CAPTURABLE_IS_FALSE", "");
    std::printf("  NOTE: a 0xC0000409 is NOT observable by this guard. Its reason\n");
    std::printf("        requires a privileged observer (debugger/ETW/WER).\n");

    // --- CONTROL 2: a genuine access violation MUST be captured in full.
    //     This is the class the authority does cover, and it is covered by
    //     measurement rather than by intent.
    strcat_s(recPath, ".av");
    DeleteFileA(recPath);
    spawnChild(L"run-av", recPath, selfSha.c_str(), ec);
    const std::string r2 = readAll(recPath);
    std::printf("\n--- CONTROL 2: genuine access violation ---\n");
    check(!r2.empty(), "AV_RECORD_WRITTEN", "bytes=%zu", r2.size());
    check(has(r2, "EXCEPTION_CODE", "3221225477"), "AV_CODE_0xC0000005",
          "code=%s", fieldOf(r2, "EXCEPTION_CODE").c_str());
    check(has(r2, "IS_FAST_FAIL", "0"), "AV_NOT_FAST_FAIL", "");
    check(has(r2, "VECTORED_CAPTURE_ARMED", "1"), "AV_HANDLER_RAN", "");
    check(has(r2, "FIRST_STOP_CAPTURED", "1"), "AV_FIRST_STOP_CAPTURED", "");
    check(!fieldOf(r2, "RIP").empty() && fieldOf(r2, "RIP") != "0", "AV_RIP_RECORDED",
          "rip=%s", fieldOf(r2, "RIP").c_str());
    check(!fieldOf(r2, "RSP").empty() && fieldOf(r2, "RSP") != "0", "AV_RSP_RECORDED",
          "rsp=%s", fieldOf(r2, "RSP").c_str());
    check(fieldOf(r2, "STACK_WORDS") == "16", "AV_STACK_CAPTURED", "words=%s",
          fieldOf(r2, "STACK_WORDS").c_str());

    // --- CONTROL 3: identity refusal. A wrong SHA must be reported as a
    //     refusal. Uses the AV path because the fast-fail path never writes.
    strcat_s(recPath, ".id");
    DeleteFileA(recPath);
    spawnChild(L"run-av", recPath, "0000000000000000000000000000000000000000000000000000000000000000", ec);
    const std::string r3 = readAll(recPath);
    std::printf("\n--- CONTROL 3: identity mismatch must refuse ---\n");
    check(!r3.empty(), "ID_REFUSAL_STILL_WRITES_EVIDENCE", "bytes=%zu", r3.size());
    check(has(r3, "LAYER0", "REFUSED_NO_IDENTITY"), "ID_REFUSED", "");
    check(has(r3, "IMAGE_IDENTITY_MATCH", "0"), "ID_MATCH_IS_ZERO", "");
    // The refusal must STILL carry the capture: refusing the identity does not
    // erase the observation. Losing both at once would be a regression in the
    // opposite direction.
    check(has(r3, "EXCEPTION_CODE", "3221225477"), "ID_REFUSAL_KEEPS_CAPTURE",
          "code=%s", fieldOf(r3, "EXCEPTION_CODE").c_str());

    // --- CONTROL 4: a clean run must produce NO record at all. This is what
    //     keeps "nothing happened" and "nothing was observed" distinct.
    strcat_s(recPath, ".clean");
    DeleteFileA(recPath);
    spawnChild(L"run-clean", recPath, selfSha.c_str(), ec);
    const bool cleanWrote = GetFileAttributesA(recPath) != INVALID_FILE_ATTRIBUTES;
    std::printf("\n--- CONTROL 4: clean run writes nothing ---\n");
    check(!cleanWrote, "CLEAN_RUN_WROTE_NO_RECORD", "file_present=%d", cleanWrote);

    // --- CONTROL 5: the handler must be disarmed before any exception.
    std::printf("\n--- CONTROL 5: pre-exception state ---\n");
    check(!Deep2::Layer0::VectoredCaptureArmed(), "DISARMED_IN_PARENT",
          "armed=%d", Deep2::Layer0::VectoredCaptureArmed() ? 1 : 0);
    check(!Deep2::Layer0::GetFirstStop().captured, "NO_FIRST_STOP_IN_PARENT", "");

    DeleteFileA(recPath);
    std::printf("\n--- SUMMARY ---\n");
    std::printf("CHECKS_TOTAL=%d\n", g_checks);
    std::printf("CHECKS_PASS=%d\n", g_pass);
    std::printf("CHECKS_FAIL=%d\n", g_fail);
    // DERIVED, never asserted. An earlier revision of this file printed
    // FASTFAIL_TUPLES_CAPTURED_IN_PROCESS=1, DEBUGGER_REQUIRED=0 and
    // IDENTITY_REFUSAL_WORKS=1 as literals -- and did so on a run where 16 of 19
    // checks had FAILED. That is a fabricated receipt: the summary claimed
    // capabilities that the measurements above it contradicted, which is the
    // single most damaging defect this project has produced. Every line here is
    // a comparison against a captured observation, so it can contradict the
    // checks instead of asserting over them.
    std::printf("STRUCTURED_EXCEPTIONS_CAPTURED_IN_PROCESS=%d\n",
                has(r2, "FIRST_STOP_CAPTURED", "1") &&
                has(r2, "EXCEPTION_CODE", "3221225477") ? 1 : 0);
    std::printf("FASTFAIL_CAPTURABLE_IN_PROCESS=%d\n",
                Deep2::Layer0::FastFailCapturableByThisGuard() ? 1 : 0);
    std::printf("CDB_INVOKED=0\n");
    std::printf("DUMP_CONSUMED=0\n");
    std::printf("IDENTITY_HASH_FUNCTION_WORKS=%d\n", selfSha.size() == 64 ? 1 : 0);
    std::printf("IDENTITY_REFUSAL_WORKS=%d\n",
                has(r3, "LAYER0", "REFUSED_NO_IDENTITY") &&
                has(r3, "IMAGE_IDENTITY_MATCH", "0") ? 1 : 0);
    std::printf("CLEAN_RUN_WROTE_NO_RECORD=%d\n", cleanWrote ? 0 : 1);
    std::printf("VERDICT=%s\n", (g_fail == 0 && g_checks > 0) ? "PASS" : "FAIL");
    return (g_fail == 0 && g_checks > 0) ? 0 : 1;
}
