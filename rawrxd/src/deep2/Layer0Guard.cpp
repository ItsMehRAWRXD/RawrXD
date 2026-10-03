// ============================================================================
// Layer0Guard.cpp — RAWRXD_LAYER0_AUTHORITY_001
// ============================================================================

#include "Layer0Guard.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace Deep2::Layer0 {

namespace {

FirstStop g_stop{};
volatile LONG g_armed = 0;          // LONG because the handler may run on any thread
volatile LONG g_captureArmed = 0;   // set INSIDE the handler; see header
PVOID g_veh = nullptr;
PVOID g_uef = nullptr;

// Copy at most 16 stack words starting at RSP. Deliberately RVA-less: without
// the module base this is a set of return addresses, and this layer's job is to
// establish that the EFFECT happened and where, not to pretend it can already
// resolve names. Symbolisation is a later layer and must not be faked here.
void captureStack(CONTEXT* ctx) {
    if (!ctx) return;
    __try {
        auto* sp = reinterpret_cast<std::uint64_t*>(ctx->Rsp);
        const std::uint32_t n = 16;
        for (std::uint32_t i = 0; i < n; ++i) {
            g_stop.frameReturn[i] = static_cast<std::uint32_t>(sp[i]);
            ++g_stop.frameCount;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // A guarded stack is not readable. That is a fact about the stack, not a
        // failure of this layer; the count already recorded stands.
    }
}

LONG WINAPI vehHandler(EXCEPTION_POINTERS* info) {
    // First instruction after entry: the fact the header promises is set here.
    InterlockedExchange(&g_captureArmed, 1);

    if (!info || !info->ExceptionRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // Capture the FIRST exception only. A later second-chance copy would
    // overwrite the original context and produce a plausible-looking record of
    // the wrong moment.
    if (InterlockedCompareExchange(&g_armed, 1, 0) != 0) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    EXCEPTION_RECORD* rec = info->ExceptionRecord;
    g_stop.captured      = true;
    g_stop.exceptionCode = rec->ExceptionCode;
    g_stop.exceptionFlags = rec->ExceptionFlags;
    g_stop.exceptionAddress = reinterpret_cast<std::uint64_t>(rec->ExceptionAddress);
    g_stop.infoCount = rec->NumberParameters > 4 ? 4 : rec->NumberParameters;
    for (ULONG i = 0; i < g_stop.infoCount; ++i) {
        g_stop.info[i] = rec->ExceptionInformation[i];
    }
    g_stop.threadId = GetCurrentThreadId();

    if (info->ContextRecord) {
        CONTEXT* ctx = info->ContextRecord;
        g_stop.rip = ctx->Rip;
        g_stop.rsp = ctx->Rsp;
        g_stop.rbp = ctx->Rbp;
        g_stop.rcx = ctx->Rcx;
        g_stop.rdx = ctx->Rdx;
        g_stop.rax = ctx->Rax;
        captureStack(ctx);
    }

    if (rec->ExceptionCode == 0xC0000409u) {   // STATUS_FAST_FAIL
        g_stop.isFailFast = true;
        // Two independent readings of the sub-code. For __fastfail the code is
        // documented as passing through both the exception parameter and RCX.
        g_stop.failCodeFromInfo = g_stop.infoCount >= 1 ? g_stop.info[0] : 0;
        g_stop.failCodeFromRcx  = g_stop.rcx;
        g_stop.failCodeAgrees   = (g_stop.infoCount >= 1) &&
                                 (g_stop.failCodeFromInfo == g_stop.failCodeFromRcx);
    }

    // Write the record HERE, inside the handler. The process is about to be
    // terminated by the OS, so a record written after the handler returns would
    // never exist. This is the entire reason the capture is in-process: there is
    // no "after" to write in.
    //
    // Caveat, stated rather than hidden: this allocates (std::string, std::vector)
    // inside an exception handler, which is not async-signal-safe in the POSIX
    // sense. Windows VEH is not that context, and the alternative -- no record at
    // all -- is strictly worse for the purpose this authority exists to serve.
    {
        wchar_t path[MAX_PATH]{};
        const DWORD n = GetEnvironmentVariableW(L"RAWRXD_LAYER0_OUT", path, MAX_PATH);
        if (n && n < MAX_PATH) WriteRecord(path, L"veh");
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Fail closed. If the guard could not be armed, the run must not be reported as
// an unobserved one: an absent guard and an absent fault look identical from the
// outside, and that ambiguity is what let four ghosts through.
LONG WINAPI uefHandler(EXCEPTION_POINTERS* info) {
    InterlockedExchange(&g_captureArmed, 1);
    if (info && info->ExceptionRecord) {
        if (InterlockedCompareExchange(&g_armed, 1, 0) == 0) {
            EXCEPTION_RECORD* rec = info->ExceptionRecord;
            g_stop.captured = true;
            g_stop.exceptionCode = rec->ExceptionCode;
            g_stop.exceptionFlags = rec->ExceptionFlags;
            g_stop.exceptionAddress =
                reinterpret_cast<std::uint64_t>(rec->ExceptionAddress);
            g_stop.infoCount = rec->NumberParameters > 4 ? 4 : rec->NumberParameters;
            for (ULONG i = 0; i < g_stop.infoCount; ++i)
                g_stop.info[i] = rec->ExceptionInformation[i];
            g_stop.threadId = GetCurrentThreadId();
            if (info->ContextRecord) {
                CONTEXT* ctx = info->ContextRecord;
                g_stop.rip = ctx->Rip; g_stop.rsp = ctx->Rsp;
                g_stop.rbp = ctx->Rbp; g_stop.rcx = ctx->Rcx;
                g_stop.rdx = ctx->Rdx; g_stop.rax = ctx->Rax;
                captureStack(ctx);
            }
            if (rec->ExceptionCode == 0xC0000409u) {
                g_stop.isFailFast = true;
                g_stop.failCodeFromInfo = g_stop.infoCount >= 1 ? g_stop.info[0] : 0;
                g_stop.failCodeFromRcx  = g_stop.rcx;
                g_stop.failCodeAgrees   = (g_stop.infoCount >= 1) &&
                                         (g_stop.failCodeFromInfo == g_stop.failCodeFromRcx);
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

bool Arm() {
    if (InterlockedCompareExchange(&g_armed, 0, 0) != 0) {
        // Already ran; arming again must not reset the record.
        return g_veh != nullptr;
    }
    g_veh = AddVectoredExceptionHandler(1, vehHandler);
    g_uef = SetUnhandledExceptionFilter(uefHandler);
    if (!g_veh) return false;
    InterlockedExchange(&g_armed, 1);
    // Clear it again: g_armed is a first-stop latch, not an arming latch.
    InterlockedExchange(&g_armed, 0);
    return true;
}

bool VectoredCaptureArmed() { return InterlockedCompareExchange(&g_captureArmed, 0, 0) != 0; }

// A MEASURED NEGATIVE RESULT, and the most important line in this file.
//
// __fastfail on x64 is `int 29h`. The kernel consumes it and terminates the
// process; it is NOT delivered to a vectored exception handler, and it is not a
// structured exception, so __try/__except does not see it either. Observed
// directly: a genuine __fastfail(FAST_FAIL_FATAL_APP_EXIT) produced NO record
// from this guard, while a genuine null dereference produced a complete one with
// correct code, RIP and stack.
//
// Consequence, stated plainly because it is load-bearing: this authority CANNOT
// observe a 0xC0000409. It covers structured exceptions. For a fast-fail the
// fault reason requires a privileged observer -- a debugger, ETW, or WER -- and
// it must not be inferred from anything this guard reports.
//
// The flag below is a hard-coded FALSE on purpose. It is the only honest value:
// a genuine __fastfail produced no record from this guard. Any code that wants
// to know whether a fast-fail is observable here must be told no, rather than
// left to infer an answer from a guard that demonstrably never fires for it.
bool FastFailCapturableByThisGuard() { return false; }

const FirstStop& GetFirstStop() { return g_stop; }

// ---------------------------------------------------------------------------
// Self-contained SHA-256.
//
// This started as a BCrypt call and returned an empty string, which silently
// degraded the identity check into a permanent no-op that still LOOKED like an
// enforcement. A primitive whose failure mode is "quietly disabled" is not
// acceptable for the one function that decides whether a measurement is
// admissible, so it is implemented here and validated against the published
// known-answer vectors in the probe.
//
// Self-contained also means no property negotiation, no provider configuration,
// and no bcrypt linkage -- this file's only job is to make a hash, and the
// fewer moving parts it has, the more a hash failure will look like a hash
// failure instead of a policy failure.
// ---------------------------------------------------------------------------
namespace {

inline std::uint32_t rotr32(std::uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

const std::uint32_t kSha256K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
    0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
    0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
    0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
    0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
    0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

void sha256Block(std::uint32_t h[8], const unsigned char* p) {
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(p[i * 4]) << 24) |
               (static_cast<std::uint32_t>(p[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(p[i * 4 + 2]) << 8) |
               (static_cast<std::uint32_t>(p[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        const std::uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
                                 (w[i - 15] >> 3);
        const std::uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
                                 (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    std::uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
        const std::uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const std::uint32_t ch = (e & f) ^ (~e & g);
        const std::uint32_t t1 = hh + S1 + ch + kSha256K[i] + w[i];
        const std::uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

// Exposed for the known-answer test in the probe. Digest of an explicit buffer.
std::wstring Sha256HexOfBuffer(const unsigned char* data, std::size_t n) {
    std::uint32_t h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                          0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    std::size_t off = 0;
    while (n - off >= 64) { sha256Block(h, data + off); off += 64; }
    unsigned char tail[128] = {0};
    const std::size_t rem = n - off;
    if (rem) std::memcpy(tail, data + off, rem);
    tail[rem] = 0x80;
    const std::size_t padTo = (rem + 1 <= 56) ? 64 : 128;
    const std::uint64_t bits = static_cast<std::uint64_t>(n) * 8ull;
    for (int i = 0; i < 8; ++i)
        tail[padTo - 1 - i] = static_cast<unsigned char>((bits >> (8 * i)) & 0xFF);
    for (std::size_t i = 0; i < padTo; i += 64) sha256Block(h, tail + i);

    static const char* kHex = "0123456789ABCDEF";
    std::wstring out;
    out.reserve(64);
    for (int i = 0; i < 8; ++i) {
        for (int b = 3; b >= 0; --b) {
            const unsigned char v =
                static_cast<unsigned char>((h[i] >> (8 * b)) & 0xFF);
            out.push_back(static_cast<wchar_t>(kHex[(v >> 4) & 0xF]));
            out.push_back(static_cast<wchar_t>(kHex[v & 0xF]));
        }
    }
    return out;
}

}  // namespace

std::wstring Sha256HexOfBytes(const void* data, std::size_t n) {
    return Sha256HexOfBuffer(static_cast<const unsigned char*>(data), n);
}

std::wstring HashFileSha256(const wchar_t* pathW) {
    HANDLE h = CreateFileW(pathW, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::wstring();
    std::uint32_t h8[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                           0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    constexpr std::size_t kChunk = 1u << 20;
    std::vector<unsigned char> buf(kChunk);
    bool anyRead = false;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(h, buf.data(), static_cast<DWORD>(kChunk), &got, nullptr) ||
            got == 0) break;
        anyRead = true;
        std::size_t off = 0;
        while (got - off >= 64) { sha256Block(h8, buf.data() + off); off += 64; }
        if (got - off > 0) {
            // Feed the tail by buffering it as a partial block is not possible
            // with this streaming shape, so the file is hashed by the buffer
            // helper instead when it does not divide evenly.
            CloseHandle(h);
            (void)anyRead;
            std::vector<unsigned char> all;
            HANDLE h2 = CreateFileW(pathW, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h2 == INVALID_HANDLE_VALUE) return std::wstring();
            for (;;) {
                DWORD g2 = 0;
                if (!ReadFile(h2, buf.data(), static_cast<DWORD>(kChunk), &g2,
                              nullptr) || g2 == 0) break;
                all.insert(all.end(), buf.begin(), buf.begin() + g2);
            }
            CloseHandle(h2);
            return Sha256HexOfBuffer(all.data(), all.size());
        }
    }
    CloseHandle(h);
    if (!anyRead) return std::wstring();
    // Exact multiple of 64 bytes: pad the empty remainder.
    unsigned char zeroPad[64] = {0x80};
    sha256Block(h8, zeroPad);
    static const char* kHex = "0123456789ABCDEF";
    std::wstring out;
    for (int i = 0; i < 8; ++i)
        for (int b = 3; b >= 0; --b) {
            const unsigned char v =
                static_cast<unsigned char>((h8[i] >> (8 * b)) & 0xFF);
            out.push_back(static_cast<wchar_t>(kHex[(v >> 4) & 0xF]));
            out.push_back(static_cast<wchar_t>(kHex[v & 0xF]));
        }
    return out;
}

bool WriteRecord(const wchar_t* pathW, const wchar_t* stageW) {
    // Refusal condition 1: nothing was captured. Emit nothing.
    if (!g_stop.captured) return false;

    HANDLE f = CreateFileW(pathW, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;

    // Refusal condition 2: no image identity. A record without one is exactly the
    // artifact this authority exists to prevent.
    wchar_t selfPath[MAX_PATH]{};
    wchar_t expected[65]{};
    const DWORD n = GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
    std::wstring actual;
    if (n) actual = HashFileSha256(selfPath);
    wchar_t* env = _wgetenv(L"RAWRXD_LAYER0_EXPECTED_SHA256");
    if (env) wcsncpy_s(expected, env, _TRUNCATE);
    // RAWRXD_LAYER0_IDENTITY_COMPARISON_001
    //
    // This line was `!actual.empty() && expected[0] != 0` -- it checked that
    // both strings were PRESENT and never compared them. Any digest therefore
    // "matched" any expectation, so the identity gate could be satisfied by a
    // hash of a completely different binary. The probe's CONTROL 3 caught it the
    // moment the hash function started working: before then the check passed
    // vacuously, because `actual` was empty and the whole condition was false.
    // A gate that fails closed for the wrong reason looks identical to a gate
    // that fails closed for the right one until the day it stops failing at all.
    const std::wstring expectedW(expected);
    bool haveIdentity = !actual.empty() && !expectedW.empty();
    if (haveIdentity) {
        if (actual.size() != expectedW.size()) {
            haveIdentity = false;
        } else {
            for (std::size_t i = 0; i < actual.size(); ++i) {
                wchar_t x = actual[i], y = expectedW[i];
                if (x >= L'a' && x <= L'z') x = static_cast<wchar_t>(x - 32);
                if (y >= L'a' && y <= L'z') y = static_cast<wchar_t>(y - 32);
                if (x != y) { haveIdentity = false; break; }
            }
        }
    }

    std::string t;
    auto add = [&t](const std::string& k, long long v) {
        t += k; t += '=';
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%lld", v);
        t += buf; t += '\n';
    };

    t += "# RAWRXD_LAYER0_AUTHORITY_001\n";
    t += haveIdentity ? "LAYER0=RECORDED\n" : "LAYER0=REFUSED_NO_IDENTITY\n";
    if (n) {
        std::string sp;
        for (const wchar_t* c = selfPath; *c; ++c)
            sp.push_back(static_cast<char>(*c < 128 ? *c : '?'));
        t += "IMAGE_PATH=" + sp + "\n";
    }
    {
        std::string a, e;
        for (auto c : actual) a.push_back(static_cast<char>(c));
        for (const wchar_t* c = expected; *c; ++c)
            e.push_back(static_cast<char>(*c < 128 ? *c : '?'));
        t += "IMAGE_SHA256=" + a + "\n";
        t += "EXPECTED_SHA256=" + e + "\n";
        add("IMAGE_IDENTITY_MATCH", haveIdentity ? 1 : 0);
    }
    if (stageW) {
        std::string s;
        for (const wchar_t* c = stageW; *c; ++c)
            s.push_back(static_cast<char>(*c < 128 ? *c : '?'));
        t += "STAGE=" + s + "\n";
    }
    t += "VECTORED_CAPTURE_ARMED="; t += VectoredCaptureArmed() ? "1\n" : "0\n";
    t += "FIRST_STOP_CAPTURED="; t += g_stop.captured ? "1\n" : "0\n";
    add("EXCEPTION_CODE", static_cast<long long>(g_stop.exceptionCode));
    add("EXCEPTION_FLAGS", static_cast<long long>(g_stop.exceptionFlags));
    add("EXCEPTION_ADDRESS", static_cast<long long>(g_stop.exceptionAddress));
    add("EXCEPTION_INFO_COUNT", static_cast<long long>(g_stop.infoCount));
    for (std::uint32_t i = 0; i < g_stop.infoCount; ++i)
        add("EXCEPTION_INFO_" + std::to_string(i),
            static_cast<long long>(g_stop.info[i]));
    add("TID", static_cast<long long>(g_stop.threadId));
    add("RIP", static_cast<long long>(g_stop.rip));
    add("RSP", static_cast<long long>(g_stop.rsp));
    add("RBP", static_cast<long long>(g_stop.rbp));
    add("RCX", static_cast<long long>(g_stop.rcx));
    add("RDX", static_cast<long long>(g_stop.rdx));
    add("RAX", static_cast<long long>(g_stop.rax));
    add("IS_FAST_FAIL", g_stop.isFailFast ? 1 : 0);
    add("FAILCODE_FROM_INFO", static_cast<long long>(g_stop.failCodeFromInfo));
    add("FAILCODE_FROM_RCX", static_cast<long long>(g_stop.failCodeFromRcx));
    add("FAILCODE_AGREES", g_stop.failCodeAgrees ? 1 : 0);
    add("STACK_WORDS", static_cast<long long>(g_stop.frameCount));
    for (std::uint32_t i = 0; i < g_stop.frameCount; ++i) {
        t += "STACK_" + std::to_string(i) + "=";
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%08X",
                      static_cast<unsigned>(g_stop.frameReturn[i]));
        t += buf;
        t += '\n';
    }

    DWORD put = 0;
    const BOOL ok = WriteFile(f, t.data(), static_cast<DWORD>(t.size()), &put, nullptr);
    CloseHandle(f);
    return ok && put == t.size();
}

}  // namespace Deep2::Layer0
