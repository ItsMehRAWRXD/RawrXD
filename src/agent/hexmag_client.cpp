// hexmag_client.cpp — HexMag CLI ↔ SovereignKernelJIT integration
// Bridges the HexMag FastAPI agent to the native JIT emitter pipeline.

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>

// ---------------------------------------------------------------------------
// Forward declarations from SovereignKernelJIT / TitanJIT_PE
// ---------------------------------------------------------------------------
namespace RawrXD::Runtime {
    class SovereignKernelJIT;
}

// ---------------------------------------------------------------------------
// HexMag JIT Opcode Buffer
// ---------------------------------------------------------------------------
struct HexMagJitBuffer {
    uint8_t* code;
    size_t   size;
    size_t   capacity;
    HANDLE   hProcess;
};

static std::mutex g_hexmagMutex;
static std::atomic<bool> g_hexmagActive{false};
static HexMagJitBuffer g_hexmagBuffer{nullptr, 0, 0, nullptr};

// ---------------------------------------------------------------------------
// Low-level: Allocate RWX memory for JIT
// ---------------------------------------------------------------------------
static uint8_t* HexMag_AllocateRWX(size_t size) {
    return static_cast<uint8_t*>(
        VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    );
}

static void HexMag_FreeRWX(uint8_t* ptr, size_t size) {
    if (ptr) VirtualFree(ptr, 0, MEM_RELEASE);
}

// ---------------------------------------------------------------------------
// Low-level: Emit x64 opcode bytes
// ---------------------------------------------------------------------------
static void HexMag_Emit_U8(HexMagJitBuffer* buf, uint8_t b) {
    if (buf->size + 1 > buf->capacity) return;
    buf->code[buf->size++] = b;
}

static void HexMag_Emit_U32(HexMagJitBuffer* buf, uint32_t v) {
    if (buf->size + 4 > buf->capacity) return;
    memcpy(&buf->code[buf->size], &v, 4);
    buf->size += 4;
}

static void HexMag_Emit_U64(HexMagJitBuffer* buf, uint64_t v) {
    if (buf->size + 8 > buf->capacity) return;
    memcpy(&buf->code[buf->size], &v, 8);
    buf->size += 8;
}

// ---------------------------------------------------------------------------
// Emit: mov rcx, imm64  (for 64-bit constants)
// ---------------------------------------------------------------------------
static void HexMag_Emit_MovRcxImm64(HexMagJitBuffer* buf, uint64_t imm) {
    // REX.W + B8+rd (mov r64, imm64)
    HexMag_Emit_U8(buf, 0x48);          // REX.W
    HexMag_Emit_U8(buf, 0xB9);          // mov rcx, imm64
    HexMag_Emit_U64(buf, imm);
}

// ---------------------------------------------------------------------------
// Emit: sub rsp, 0x28 (shadow space)
// ---------------------------------------------------------------------------
static void HexMag_Emit_ShadowSpace(HexMagJitBuffer* buf) {
    HexMag_Emit_U8(buf, 0x48);          // REX.W
    HexMag_Emit_U8(buf, 0x83);          // sub r/m64, imm8
    HexMag_Emit_U8(buf, 0xEC);          // ModR/M: rsp
    HexMag_Emit_U8(buf, 0x28);          // imm8: 0x28
}

// ---------------------------------------------------------------------------
// Emit: add rsp, 0x28 (restore shadow space)
// ---------------------------------------------------------------------------
static void HexMag_Emit_RestoreShadow(HexMagJitBuffer* buf) {
    HexMag_Emit_U8(buf, 0x48);          // REX.W
    HexMag_Emit_U8(buf, 0x83);          // add r/m64, imm8
    HexMag_Emit_U8(buf, 0xC4);          // ModR/M: rsp
    HexMag_Emit_U8(buf, 0x28);          // imm8: 0x28
}

// ---------------------------------------------------------------------------
// Emit: ret
// ---------------------------------------------------------------------------
static void HexMag_Emit_Ret(HexMagJitBuffer* buf) {
    HexMag_Emit_U8(buf, 0xC3);
}

// ---------------------------------------------------------------------------
// Emit: call [IAT_ExitProcess] — RIP-relative indirect call
// ---------------------------------------------------------------------------
static void HexMag_Emit_CallExitProcess(HexMagJitBuffer* buf, uint32_t iatRva) {
    // FF 15 disp32 — call qword ptr [rip+disp32]
    HexMag_Emit_U8(buf, 0xFF);
    HexMag_Emit_U8(buf, 0x15);
    // disp32 = target_RVA - (current_RVA + 6)
    // For now, emit placeholder 0 — will be patched by linker
    HexMag_Emit_U32(buf, 0x00000000);
}

// ---------------------------------------------------------------------------
// HexMag: Initialize JIT buffer
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int HexMagJIT_Init(size_t capacity) {
    std::lock_guard<std::mutex> lock(g_hexmagMutex);
    if (g_hexmagBuffer.code) {
        HexMag_FreeRWX(g_hexmagBuffer.code, g_hexmagBuffer.capacity);
    }
    g_hexmagBuffer.code = HexMag_AllocateRWX(capacity);
    if (!g_hexmagBuffer.code) return -1;
    g_hexmagBuffer.size = 0;
    g_hexmagBuffer.capacity = capacity;
    g_hexmagBuffer.hProcess = GetCurrentProcess();
    g_hexmagActive.store(true);
    return 0;
}

// ---------------------------------------------------------------------------
// HexMag: Shutdown JIT buffer
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) void HexMagJIT_Shutdown() {
    std::lock_guard<std::mutex> lock(g_hexmagMutex);
    g_hexmagActive.store(false);
    if (g_hexmagBuffer.code) {
        HexMag_FreeRWX(g_hexmagBuffer.code, g_hexmagBuffer.capacity);
        g_hexmagBuffer.code = nullptr;
        g_hexmagBuffer.size = 0;
        g_hexmagBuffer.capacity = 0;
    }
}

// ---------------------------------------------------------------------------
// HexMag: Emit a complete "exit 42" function
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int HexMagJIT_EmitExit42() {
    std::lock_guard<std::mutex> lock(g_hexmagMutex);
    if (!g_hexmagActive.load() || !g_hexmagBuffer.code) return -1;

    g_hexmagBuffer.size = 0;

    // sub rsp, 0x28
    HexMag_Emit_ShadowSpace(&g_hexmagBuffer);

    // mov rcx, 42
    HexMag_Emit_MovRcxImm64(&g_hexmagBuffer, 42);

    // call ExitProcess (stub — would be patched with real IAT)
    // For now, emit a simple ret to avoid crash
    HexMag_Emit_RestoreShadow(&g_hexmagBuffer);
    HexMag_Emit_Ret(&g_hexmagBuffer);

    // Flush instruction cache
    FlushInstructionCache(g_hexmagBuffer.hProcess, g_hexmagBuffer.code, g_hexmagBuffer.size);

    return static_cast<int>(g_hexmagBuffer.size);
}

// ---------------------------------------------------------------------------
// HexMag: Execute emitted code
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int HexMagJIT_Execute() {
    if (!g_hexmagActive.load() || !g_hexmagBuffer.code || g_hexmagBuffer.size == 0) {
        return -1;
    }

    typedef int (*JitFunc)();
    JitFunc func = reinterpret_cast<JitFunc>(g_hexmagBuffer.code);

    __try {
        int result = func();
        return result;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -2; // Access violation or other exception
    }
}

// ---------------------------------------------------------------------------
// HexMag: CLI entry point — called by Win32IDE menu / command line
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int HexMagCLI_Run(int argc, const char** argv) {
    printf("[HexMagCLI] Initializing JIT pipeline...\n");

    if (HexMagJIT_Init(4096) != 0) {
        fprintf(stderr, "[HexMagCLI] Failed to allocate JIT buffer\n");
        return 1;
    }

    printf("[HexMagCLI] Emitting exit-42 function...\n");
    int emitSize = HexMagJIT_EmitExit42();
    if (emitSize < 0) {
        fprintf(stderr, "[HexMagCLI] Emit failed\n");
        HexMagJIT_Shutdown();
        return 1;
    }
    printf("[HexMagCLI] Emitted %d bytes\n", emitSize);

    printf("[HexMagCLI] Executing JIT code...\n");
    int result = HexMagJIT_Execute();
    printf("[HexMagCLI] JIT returned: %d\n", result);

    HexMagJIT_Shutdown();
    printf("[HexMagCLI] Shutdown complete\n");
    return (result == 42) ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Legacy stub — kept for backward compatibility
// ---------------------------------------------------------------------------
extern "C" void hexmag_connect_stub() {
    printf("[HexMag] Legacy stub — use HexMagCLI_Run() instead\n");
}
