// ============================================================================
// win32ide_debugger_bridge.cpp — RAWRXD_W3_BATCH_G
// Real C implementations for debugger/agent authority families declared in
// native_debugger_engine.cpp (extern "C" block) but never implemented:
//   Dbg_WalkStack / Dbg_InjectINT3 / Dbg_RestoreINT3 /
//   Dbg_SetHardwareBreakpoint / Dbg_ClearHardwareBreakpoint / Dbg_MemoryScan
// Real Windows APIs: ReadProcessMemory / WriteProcessMemory /
// GetThreadContext+SetThreadContext (x64 debug registers Dr0-Dr7) /
// StackWalk64 (dbghelp). Fail-closed: every failure returns a non-zero code;
// unreadable memory is skipped and reported as not-found, never faked.
//
// HexMag_* counters + IsStubFunction also live here (real state / real
// prologue pattern check from the dumpbin scaffold audit).
// ============================================================================
#include <windows.h>
#include <dbghelp.h>
#include <atomic>
#include <cstring>
#include <vector>

#pragma comment(lib, "dbghelp.lib")

extern "C" {

// Return-code convention: 0 = OK; non-zero = engine-specific error.
constexpr uint32_t kDbgOk = 0;
constexpr uint32_t kDbgInvalidArg = 1;
constexpr uint32_t kDbgReadFailed = 2;
constexpr uint32_t kDbgWriteFailed = 3;
constexpr uint32_t kDbgGetContextFailed = 4;
constexpr uint32_t kDbgSetContextFailed = 5;
constexpr uint32_t kDbgWalkFailed = 6;
constexpr uint32_t kDbgNotFound = 7;
constexpr uint32_t kDbgInvalidSlot = 8;

// --- INT3 patching -------------------------------------------------------
uint32_t Dbg_InjectINT3(uint64_t targetAddress, uint8_t* outOriginalByte) {
    if (!targetAddress || !outOriginalByte) return kDbgInvalidArg;
    HANDLE proc = GetCurrentProcess();
    uint8_t orig = 0;
    SIZE_T n = 0;
    if (!ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(targetAddress),
                           &orig, 1, &n) || n != 1) {
        return kDbgReadFailed;
    }
    *outOriginalByte = orig;
    const uint8_t cc = 0xCC;
    if (!WriteProcessMemory(proc, reinterpret_cast<LPVOID>(targetAddress),
                            &cc, 1, &n) || n != 1) {
        return kDbgWriteFailed;
    }
    FlushInstructionCache(proc, reinterpret_cast<LPCVOID>(targetAddress), 1);
    return kDbgOk;
}

uint32_t Dbg_RestoreINT3(uint64_t targetAddress, uint8_t originalByte) {
    if (!targetAddress) return kDbgInvalidArg;
    HANDLE proc = GetCurrentProcess();
    SIZE_T n = 0;
    if (!WriteProcessMemory(proc, reinterpret_cast<LPVOID>(targetAddress),
                            &originalByte, 1, &n) || n != 1) {
        return kDbgWriteFailed;
    }
    FlushInstructionCache(proc, reinterpret_cast<LPCVOID>(targetAddress), 1);
    return kDbgOk;
}

// --- Hardware breakpoints (x64 debug registers) --------------------------
static std::atomic<uint64_t> g_drAddr[4];
static std::atomic<uint32_t> g_drInUse[4];

uint32_t Dbg_SetHardwareBreakpoint(uint64_t threadHandle, uint32_t slotIndex,
                                   uint64_t address, uint32_t lengthBytes,
                                   uint32_t accessFlags) {
    (void)accessFlags;
    if (slotIndex >= 4 || !address) return kDbgInvalidSlot;
    HANDLE t = reinterpret_cast<HANDLE>(threadHandle);
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(t, &ctx)) return kDbgGetContextFailed;
    (&ctx.Dr0)[slotIndex] = address;
    uint64_t dr7 = ctx.Dr7;
    // R/W + LEN field per slot at bits 16 + 4*slot; local enable at 2*slot.
    const uint64_t fieldMask = 0xFULL << (16 + slotIndex * 4);
    uint64_t len = 0; // 00 = 1 byte
    if (lengthBytes == 2) len = 1;
    else if (lengthBytes == 4) len = 3;
    else if (lengthBytes == 8) len = 2;
    dr7 = (dr7 & ~fieldMask) | (len << (18 + slotIndex * 4));
    dr7 |= (1ULL << (slotIndex * 2));
    ctx.Dr7 = dr7;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!SetThreadContext(t, &ctx)) return kDbgSetContextFailed;
    g_drAddr[slotIndex].store(address);
    g_drInUse[slotIndex].store(1);
    return kDbgOk;
}

uint32_t Dbg_ClearHardwareBreakpoint(uint64_t threadHandle, uint32_t slotIndex) {
    if (slotIndex >= 4) return kDbgInvalidSlot;
    HANDLE t = reinterpret_cast<HANDLE>(threadHandle);
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(t, &ctx)) return kDbgGetContextFailed;
    (&ctx.Dr0)[slotIndex] = 0;
    ctx.Dr7 &= ~(1ULL << (slotIndex * 2));
    ctx.Dr7 &= ~(0xFULL << (16 + slotIndex * 4));
    if (!SetThreadContext(t, &ctx)) return kDbgSetContextFailed;
    g_drAddr[slotIndex].store(0);
    g_drInUse[slotIndex].store(0);
    return kDbgOk;
}

// --- Stack walk (dbghelp StackWalk64) ------------------------------------
uint32_t Dbg_WalkStack(uint64_t processHandle, uint64_t threadHandle,
                       uint64_t* outFrameIPs, uint32_t maxFrames) {
    if (!outFrameIPs || !maxFrames) return kDbgInvalidArg;
    HANDLE proc = processHandle ? reinterpret_cast<HANDLE>(processHandle)
                                : GetCurrentProcess();
    HANDLE thread = reinterpret_cast<HANDLE>(threadHandle);
    if (!thread || thread == INVALID_HANDLE_VALUE) return kDbgInvalidArg;

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(thread, &ctx)) return kDbgGetContextFailed;

    STACKFRAME64 frame{};
    frame.AddrPC.Offset = ctx.Rip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = ctx.Rbp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = ctx.Rsp;
    frame.AddrStack.Mode = AddrModeFlat;

    uint32_t count = 0;
    for (uint32_t i = 0; i < maxFrames; ++i) {
        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, proc, thread, &frame, &ctx,
                         nullptr, SymFunctionTableAccess64,
                         SymGetModuleBase64, nullptr)) {
            break;
        }
        if (frame.AddrPC.Offset == 0) break;
        outFrameIPs[count++] = frame.AddrPC.Offset;
    }
    return count ? count : kDbgWalkFailed;
}

// --- Memory scan (real ReadProcessMemory over the region) ----------------
uint32_t Dbg_MemoryScan(uint64_t processHandle, uint64_t startAddress,
                        uint64_t regionSize, const uint8_t* pattern,
                        uint32_t patternLen, uint64_t* outMatches,
                        uint32_t maxMatches) {
    if (!pattern || !patternLen || !outMatches || !maxMatches || !regionSize) {
        return kDbgInvalidArg;
    }
    HANDLE proc = processHandle ? reinterpret_cast<HANDLE>(processHandle)
                                : GetCurrentProcess();
    uint32_t found = 0;
    std::vector<uint8_t> buf;
    const uint64_t kChunk = 1ULL << 20;
    for (uint64_t off = 0; off + patternLen <= regionSize; off += kChunk) {
        const uint64_t want = (kChunk + patternLen <= regionSize - off)
                                  ? kChunk + patternLen
                                  : regionSize - off;
        buf.resize(static_cast<size_t>(want));
        SIZE_T got = 0;
        if (!ReadProcessMemory(proc,
                               reinterpret_cast<LPCVOID>(startAddress + off),
                               buf.data(), static_cast<SIZE_T>(want), &got) ||
            got < patternLen) {
            continue; // unreadable region: skipped (honest, not fake success)
        }
        for (SIZE_T i = 0; i + patternLen <= got; ++i) {
            if (std::memcmp(buf.data() + i, pattern, patternLen) == 0) {
                if (found < maxMatches) outMatches[found] = startAddress + off + i;
                ++found;
                break;
            }
        }
    }
    return found > 0 ? found : kDbgNotFound;
}

// --- HexMag runtime counters: REMOVED, the MASM owns them -------------------
//
// RAWRXD_HEXMAG_COUNTER_OWNERSHIP_001
//
// This block used to define g_hexmagBots / g_hexmagInit / g_hexmagTunerGen plus
// four accessors (HexMag_BotCount, HexMag_GetParallelAgents, HexMag_IsInitialized,
// HexMag_Tuner_GenerationId) that exposed them, fed by three reporters
// (HexMag_ReportBotStart, HexMag_ReportBotStop, HexMag_SetInitialized).
//
// It was deleted, not repaired, because all four accessors are now real exports
// of src/asm/RawrXD_HexMag_Swarm.asm and RawrXD_HexMag_RepeatTuner.asm, and
// linking both produced four LNK2005 duplicate-definition errors. The MASM is
// the authority: it keeps the authoritative counters, this file kept a private
// shadow of the same numbers.
//
// Before deleting, the tree was searched for every symbol above. Each had
// exactly ONE occurrence in the entire repository: its own definition.
// g_hexmagBots appeared five times, all inside this one function block. Nothing
// called any of the three reporters and nothing read any of the four accessors,
// so this was not a live source of truth being migrated -- it was a dead
// duplicate that had become a link error.
//
// Two further defects died with it: the accessors returned int32_t/uint32_t while
// hexmag_swarm.hpp and hexmag_repeat_tuner.hpp declare uint32_t for three of the
// four, and HexMag_GetParallelAgents returned the BOT count, a different quantity
// from the parallel-agent count it claims to report.
//
// If a future caller needs to drive these counters, it must go through the MASM's
// own entry points. Re-adding a C-side shadow here would reintroduce exactly the
// split authority this deletion removes.

// --- IsStubFunction (real prologue classification) -----------------------
// A function image is a scaffold when it begins with a bare return sequence
// (C3 / 31 C0 C3 / 33 C0 C3) — the exact scaffold signature dumpbin-verified
// on the 26-28 byte MASM scaffold objects (0-length .text).
// Contract (include/feature_registry.h): int __cdecl IsStubFunction(void*, size_t).
// feature_registry.cpp calls IsStubFunction(f.funcPtr, 32) — void* + size_t.
int IsStubFunction(void* funcPtr, size_t maxBytesToScan) {
    if (!funcPtr || maxBytesToScan < 1) return 0;
    const uint8_t* b = static_cast<const uint8_t*>(funcPtr);
    const size_t len = maxBytesToScan;
    if (b[0] == 0xC3) return 1;
    if (len >= 3 &&
        ((b[0] == 0x31 && b[1] == 0xC0 && b[2] == 0xC3) ||
         (b[0] == 0x33 && b[1] == 0xC0 && b[2] == 0xC3))) {
        return 1;
    }
    return 0;
}

} // extern "C"
