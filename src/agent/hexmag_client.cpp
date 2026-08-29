// hexmag_client.cpp — MASM HexMag client (no FastAPI fiction)
#include "agent/hexmag_client.hpp"
#include "core/hexmag_oracle_binder.hpp"
#include "agentic/HexMagAction.hpp"

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <sstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace RawrXD {
namespace HexMag {
namespace {

bool envTruthy(const char* name) {
    const char* v = std::getenv(name);
    return v && v[0] == '1' && v[1] == '\0';
}

std::vector<DecodedEvent> parseEventLog(const std::string& log) {
    std::vector<DecodedEvent> out;
    std::size_t i = 0;
    while (i < log.size()) {
        std::size_t nl = log.find('\n', i);
        if (nl == std::string::npos) nl = log.size();
        const std::string line = log.substr(i, nl - i);
        i = nl + (nl < log.size() ? 1 : 0);
        if (line.empty()) continue;
        DecodedEvent ev;
        const auto colon = line.find(':');
        if (colon == std::string::npos) {
            ev.name = line;
            ev.payload.clear();
        } else {
            ev.name = line.substr(0, colon);
            ev.payload = line.substr(colon + 1);
            while (!ev.payload.empty() && (ev.payload[0] == ' ' || ev.payload[0] == '\t'))
                ev.payload.erase(ev.payload.begin());
        }
        // Map name → kind (best-effort; unknown stays NONE)
        for (uint32_t k = 0; k < HX_EVT_COUNT; ++k) {
            if (ev.name == HxEventKindName(k)) {
                ev.kind = k;
                break;
            }
        }
        out.push_back(std::move(ev));
    }
    return out;
}

} // namespace

ClientIdentity clientIdentity() {
    ClientIdentity id;
#ifdef RAWR_HAS_MASM
    id.backend = "MASM";
    id.linked = 1;
    if (envTruthy("RAWRXD_HEXMAG_FORCE_UNAVAILABLE")) {
        id.clientPath = "UNAVAILABLE";
    } else if (envTruthy("RAWRXD_HEXMAG_ALLOW_NATIVE_FALLBACK") &&
               envTruthy("RAWRXD_HEXMAG_USE_NATIVE_FALLBACK")) {
        // Explicit dual-opt-in only — never silent.
        id.clientPath = "NATIVE_FALLBACK";
    } else {
        id.clientPath = "MASM";
    }
#else
    id.backend = "NONE";
    id.linked = 0;
    if (envTruthy("RAWRXD_HEXMAG_ALLOW_NATIVE_FALLBACK")) {
        id.clientPath = "NATIVE_FALLBACK";
    } else {
        id.clientPath = "UNAVAILABLE";
    }
#endif
    return id;
}

std::string formatClientIdentityBlock() {
    const ClientIdentity id = clientIdentity();
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "HEXMAG_BACKEND=%s\nHEXMAG_LINKED=%d\nHEXMAG_CLIENT_PATH=%s\n",
                  id.backend, id.linked, id.clientPath);
    return std::string(buf);
}

void HexMagClient::fillIdentity(ClientTrace& t) const {
    t.id = clientIdentity();
    if (forceUnavailable_) {
        t.id.clientPath = "UNAVAILABLE";
        t.diagnostic = "forceUnavailable=1 (cert/backend-down)";
    }
}

void HexMagClient::appendBackend(ClientTrace& t, const char* line) const {
    t.backendTrace += line;
    t.backendTrace += "\n";
}

bool HexMagClient::initialize(ClientTrace* trace) {
    ClientTrace local;
    ClientTrace& t = trace ? *trace : local;
    fillIdentity(t);

    if (forceUnavailable_ || std::strcmp(t.id.clientPath, "UNAVAILABLE") == 0) {
        t.diagnostic = "HexMag MASM unavailable (fail-closed)";
        appendBackend(t, "INIT skip UNAVAILABLE");
        return false;
    }

#ifdef RAWR_HAS_MASM
    if (std::strcmp(t.id.clientPath, "NATIVE_FALLBACK") == 0) {
        t.diagnostic = "NATIVE_FALLBACK explicitly selected (not MASM path)";
        appendBackend(t, "INIT NATIVE_FALLBACK (explicit)");
        return false; // client MASM path still fails closed for this cert
    }

    t.masmInitCalled = true;
    appendBackend(t, "HexMag_Init");
    t.generationIdBefore = HexMag_Tuner_GenerationId();
    const bool ok = ensureControlPlane();
    appendBackend(t, ok ? "HexMag_Init ok" : "HexMag_Init FAIL");
    if (!ok) {
        t.diagnostic = "HexMag_Init failed (fail-closed)";
        return false;
    }
    return HexMag_IsInitialized() != 0;
#else
    t.diagnostic = "RAWR_HAS_MASM not defined (fail-closed)";
    appendBackend(t, "INIT no RAWR_HAS_MASM");
    return false;
#endif
}

bool HexMagClient::healthCheck() const {
    if (forceUnavailable_) return false;
#ifdef RAWR_HAS_MASM
    return RawrXD::HexMag::healthCheck();
#else
    return false;
#endif
}

std::string HexMagClient::resolveBaseUrl() const {
#ifdef RAWR_HAS_MASM
    if (forceUnavailable_) return "masm://unavailable";
    return "masm://hexmag-control-plane";
#else
    return "unavailable://no-masm";
#endif
}

ClientAskResult HexMagClient::runMasmChain(const std::string& goal, uint32_t maxSteps) {
    ClientAskResult out;
    fillIdentity(out.trace);
    out.fabricatedFinal = false;
    out.clientSuccess = false;
    out.finalAuthority = false;

    if (goal.empty()) {
        out.ask.error = "empty/no-action goal";
        out.ask.success = false;
        out.trace.diagnostic = "empty goal — no fake success";
        appendBackend(out.trace, "REJECT empty goal");
        return out;
    }

    if (!initialize(&out.trace)) {
        out.ask.error = out.trace.diagnostic.empty()
            ? "backend unavailable"
            : out.trace.diagnostic;
        out.ask.success = false;
        return out;
    }

#ifdef RAWR_HAS_MASM
    clearOracleBinderHooks(); // raw MASM chain — no oracle fiction

    out.trace.generationIdBefore = HexMag_Tuner_GenerationId();
    out.trace.masmSubmitCalled = true;
    appendBackend(out.trace, "HexMag_SubmitGoal");
    const uint64_t gid = HexMag_SubmitGoal(goal.c_str(), static_cast<uint32_t>(goal.size()));
    out.trace.submitRc = gid;
    out.ask.goalId = gid;
    if (gid == 0) {
        out.ask.error = "SubmitGoal failed";
        appendBackend(out.trace, "SubmitGoal FAIL");
        return out;
    }

    out.trace.masmRunCalled = true;
    appendBackend(out.trace, "HexMag_RunToSatisfied");
    out.trace.runRc = HexMag_RunToSatisfied(maxSteps);

    out.trace.masmPollCalled = true;
    appendBackend(out.trace, "HexMag_PollEvent");
    HxEvent ev{};
    while (HexMag_PollEvent(&ev)) {
        DecodedEvent d;
        d.kind = ev.kind;
        d.name = HxEventKindName(ev.kind);
        d.payload = ev.payload;
        out.trace.events.push_back(std::move(d));
        ++out.trace.pollCount;
        if (ev.kind == HX_EVT_NEED_INPUT) {
            out.ask.needInput = true;
            out.ask.error = std::string("INSUFFICIENT_INFORMATION: ") + ev.payload;
            out.ask.answer = out.ask.error;
            out.ask.claimState = ClaimState::MissingInput;
        }
        if (ev.kind == HX_EVT_ANSWER_CANDIDATE || ev.kind == HX_EVT_ANSWER) {
            out.ask.selectedCandidate = ev.payload;
            out.ask.candidateSource = "masm";
        }
        if (ev.kind == HX_EVT_ANSWER_FINAL) {
            out.ask.emittedFinal = true;
            // Transport only — do NOT grant finalAuthority here.
        }
        if (ev.kind == HX_EVT_GOAL_SATISFIED) {
            out.ask.goalSatisfied = true;
        }
        ev = {};
    }

    out.trace.generationIdAfter = HexMag_Tuner_GenerationId();
    out.trace.tunerAttempt = HexMag_TunerAttempt();
    out.ask.agentsSpawned = HexMag_AgentsSpawned();
    out.ask.tunerAttempt = out.trace.tunerAttempt;
    out.ask.oracleInvoked = false;
    out.ask.deep2Invoked = false;

    // client_success = chain executed + events decoded. Never FINAL authority.
    out.clientSuccess = true;
    out.finalAuthority = false;
    out.ask.success = false; // raw chain never auto-FINAL
    out.fabricatedFinal = false;
    return out;
#else
    out.ask.error = "RAWR_HAS_MASM not defined";
    return out;
#endif
}

ClientAskResult HexMagClient::ask(const std::string& prompt, const std::string& context) {
    ClientAskResult out;
    fillIdentity(out.trace);
    out.fabricatedFinal = false;

    if (prompt.empty()) {
        out.ask.error = "empty/no-action goal";
        out.ask.success = false;
        out.clientSuccess = false;
        out.finalAuthority = false;
        out.trace.diagnostic = "empty goal — no fake success";
        appendBackend(out.trace, "REJECT empty goal");
        return out;
    }

    if (!initialize(&out.trace)) {
        out.ask.success = false;
        out.ask.error = out.trace.diagnostic.empty()
            ? "HexMag MASM unavailable (fail-closed)"
            : out.trace.diagnostic;
        out.clientSuccess = false;
        out.finalAuthority = false;
        return out;
    }

#ifdef RAWR_HAS_MASM
    out.trace.generationIdBefore = HexMag_Tuner_GenerationId();
    out.trace.masmInitCalled = true;
    out.trace.masmSubmitCalled = true;
    out.trace.masmRunCalled = true;
    out.trace.masmPollCalled = true;
    appendBackend(out.trace, "askWithAutoStart → HexMag_Init/Submit/Run/Poll + FINAL gates");

    // Control plane owns FINAL gates (allowFinal + isAllowedFinalClaim).
    out.ask = askWithAutoStart(prompt, context);
    out.trace.events = parseEventLog(out.ask.eventLog);
    out.trace.pollCount = static_cast<uint32_t>(out.trace.events.size());
    out.trace.generationIdAfter = HexMag_Tuner_GenerationId();
    out.trace.tunerAttempt = out.ask.tunerAttempt;
    out.trace.submitRc = out.ask.goalId;
    out.trace.runRc = out.ask.needInput ? HX_ERR_NEED_INPUT
                                        : (out.ask.goalSatisfied ? HX_OK : HX_ERR_IDLE_FAIL);

    // client_success != final_authority
    out.clientSuccess = !out.ask.error.empty() || !out.ask.answer.empty()
                        || !out.ask.eventLog.empty() || out.ask.goalId != 0;
    // If transport failed hard with empty everything, clientSuccess stays false.
    if (out.ask.goalId == 0 && out.ask.eventLog.empty() && out.ask.answer.empty()
        && !out.ask.error.empty() && out.ask.error.find("unavailable") != std::string::npos) {
        out.clientSuccess = false;
    }

    out.finalAuthority = out.ask.success;
    out.fabricatedFinal = false;

    // Invariant enforcement at client boundary:
    // - NEED_INPUT must not be downgraded to success
    if (out.ask.needInput && out.ask.success) {
        out.ask.success = false;
        out.finalAuthority = false;
        out.fabricatedFinal = true; // would be a client bug; cert fails
        out.trace.diagnostic = "INVARIANT VIOLATION: NEED_INPUT upgraded to success";
    }
    // - Candidate must not become FINAL without ask.success from gates
    if (!out.ask.success && out.ask.emittedFinal) {
        // MASM may emit FINAL event; client must not treat as authority
        out.finalAuthority = false;
    }
    return out;
#else
    out.ask.error = "RAWR_HAS_MASM not defined";
    out.clientSuccess = false;
    out.finalAuthority = false;
    return out;
#endif
}

} // namespace HexMag
} // namespace RawrXD

// ---------------------------------------------------------------------------
// Legacy JIT demo (NOT HexMag control plane) — kept for ABI compatibility.
// ---------------------------------------------------------------------------
#include <mutex>
#include <atomic>

struct HexMagJitBuffer {
    uint8_t* code = nullptr;
    size_t size = 0;
    size_t capacity = 0;
    HANDLE hProcess = nullptr;
};

static std::mutex g_hexmagMutex;
static std::atomic<bool> g_hexmagActive{false};
static HexMagJitBuffer g_hexmagBuffer{};

static uint8_t* HexMag_AllocateRWX(size_t size) {
    return static_cast<uint8_t*>(
        VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
}
static void HexMag_FreeRWX(uint8_t* ptr, size_t) {
    if (ptr) VirtualFree(ptr, 0, MEM_RELEASE);
}

extern "C" __declspec(dllexport) int HexMagJIT_Init(size_t capacity) {
    std::lock_guard<std::mutex> lock(g_hexmagMutex);
    if (g_hexmagBuffer.code) HexMag_FreeRWX(g_hexmagBuffer.code, g_hexmagBuffer.capacity);
    g_hexmagBuffer.code = HexMag_AllocateRWX(capacity);
    if (!g_hexmagBuffer.code) return -1;
    g_hexmagBuffer.size = 0;
    g_hexmagBuffer.capacity = capacity;
    g_hexmagBuffer.hProcess = GetCurrentProcess();
    g_hexmagActive.store(true);
    return 0;
}

extern "C" __declspec(dllexport) void HexMagJIT_Shutdown() {
    std::lock_guard<std::mutex> lock(g_hexmagMutex);
    g_hexmagActive.store(false);
    if (g_hexmagBuffer.code) {
        HexMag_FreeRWX(g_hexmagBuffer.code, g_hexmagBuffer.capacity);
        g_hexmagBuffer = {};
    }
}

extern "C" __declspec(dllexport) int HexMagJIT_EmitExit42() {
    // Minimal: mov eax,42; ret
    std::lock_guard<std::mutex> lock(g_hexmagMutex);
    if (!g_hexmagBuffer.code || g_hexmagBuffer.capacity < 8) return -1;
    g_hexmagBuffer.size = 0;
    g_hexmagBuffer.code[g_hexmagBuffer.size++] = 0xB8; // mov eax, imm32
    g_hexmagBuffer.code[g_hexmagBuffer.size++] = 42;
    g_hexmagBuffer.code[g_hexmagBuffer.size++] = 0;
    g_hexmagBuffer.code[g_hexmagBuffer.size++] = 0;
    g_hexmagBuffer.code[g_hexmagBuffer.size++] = 0;
    g_hexmagBuffer.code[g_hexmagBuffer.size++] = 0xC3; // ret
    FlushInstructionCache(g_hexmagBuffer.hProcess, g_hexmagBuffer.code, g_hexmagBuffer.size);
    return static_cast<int>(g_hexmagBuffer.size);
}

extern "C" __declspec(dllexport) int HexMagJIT_Execute() {
    if (!g_hexmagActive.load() || !g_hexmagBuffer.code) return -1;
    using JitFunc = int (*)();
    __try {
        return reinterpret_cast<JitFunc>(g_hexmagBuffer.code)();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -2;
    }
}

extern "C" __declspec(dllexport) int HexMagCLI_Run(int, const char**) {
    std::printf("[HexMagCLI] JIT demo only — control plane is HexMagClient::ask (MASM)\n");
    if (HexMagJIT_Init(64) != 0) return 1;
    if (HexMagJIT_EmitExit42() < 0) {
        HexMagJIT_Shutdown();
        return 1;
    }
    const int r = HexMagJIT_Execute();
    HexMagJIT_Shutdown();
    return r == 42 ? 0 : 1;
}

extern "C" void hexmag_connect_stub() {
#ifdef RAWR_HAS_MASM
    std::fprintf(stderr,
                 "[HexMag] hexmag_connect_stub: DISABLED for MASM backend. "
                 "Use HexMagClient::ask / askWithAutoStart (masm://hexmag-control-plane). "
                 "HexMag service fiction is not implemented.\n");
#else
    std::fprintf(stderr,
                 "[HexMag] hexmag_connect_stub: no MASM (RAWR_HAS_MASM undefined). "
                 "Fail-closed — no FastAPI auto-start.\n");
#endif
    std::fflush(stderr);
}
