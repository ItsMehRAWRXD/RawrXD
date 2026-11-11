/*===========================================================================
 * IDEDebuggerArena.cpp
 * Zero-heap arena allocator and CDB parsers for debugger UI
 * 
 * Triple-buffered, lock-free, wait-free thread handoff
 *===========================================================================*/

#include "IDEDebuggerTypes.h"
#include <stdio.h>
#include <stdarg.h>
#include <intrin.h>  // For InterlockedExchangePointer

// Global triple-buffer state
FrameArena g_DebugArenas[MAX_DEBUG_FRAMES];
FrameArena* volatile pWriterArena = &g_DebugArenas[0];
FrameArena* volatile pReaderArena = &g_DebugArenas[1];
FrameArena* volatile pSharedArena = &g_DebugArenas[2];

volatile LONG g_BackendFrameCount = 0;
volatile LONG g_UIRenderedFrame = 0;

// Telemetry
DebuggerTelemetry g_DebuggerTelemetry = {};

// External IDE handle for PostMessage
extern HWND g_hWndMain;
extern UINT WM_APP_DEBUG_STATE_UPDATE;  // Defined in RawrXD_IDE_Win32.cpp

/*===========================================================================
 * Telemetry Implementation
 *=========================================================================*/

void RecordFrameSubmitted() {
    InterlockedIncrement64(&g_DebuggerTelemetry.framesSubmitted);
    g_DebuggerTelemetry.lastSubmitTime = GetTickCount64();
}

void RecordFrameRendered() {
    InterlockedIncrement64(&g_DebuggerTelemetry.framesRendered);
    g_DebuggerTelemetry.lastRenderTime = GetTickCount64();
    
    // Calculate dropped frames
    LONG64 submitted = g_DebuggerTelemetry.framesSubmitted;
    LONG64 rendered = g_DebuggerTelemetry.framesRendered;
    g_DebuggerTelemetry.framesDropped = submitted - rendered;
}

void RecordParseTime(LONG64 microseconds) {
    if (microseconds > g_DebuggerTelemetry.parseTimeUs) {
        g_DebuggerTelemetry.parseTimeUs = microseconds;
    }
}

void RecordRenderTime(LONG64 microseconds) {
    if (microseconds > g_DebuggerTelemetry.renderTimeUs) {
        g_DebuggerTelemetry.renderTimeUs = microseconds;
    }
    
    // Calculate latency
    LONG64 latency = GetTickCount64() - g_DebuggerTelemetry.lastSubmitTime;
    if (latency > g_DebuggerTelemetry.maxRenderLatencyMs) {
        g_DebuggerTelemetry.maxRenderLatencyMs = latency;
    }
}

void RecordArenaUsage(size_t bytesUsed) {
    if ((LONG64)bytesUsed > g_DebuggerTelemetry.arenaHighWaterMark) {
        g_DebuggerTelemetry.arenaHighWaterMark = (LONG64)bytesUsed;
    }
}

DebuggerTelemetry GetDebuggerTelemetry() {
    return g_DebuggerTelemetry;
}

/*===========================================================================
 * Arena Lifecycle
 *=========================================================================*/

void InitFrameArena(FrameArena* arena, size_t size) {
    arena->memory = (char*)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    arena->capacity = size;
    arena->cursor = 0;
    arena->frameId = 0;
}

void DestroyFrameArena(FrameArena* arena) {
    if (arena->memory) {
        VirtualFree(arena->memory, 0, MEM_RELEASE);
        arena->memory = NULL;
    }
    arena->capacity = 0;
    arena->cursor = 0;
}

void ResetFrameArena(FrameArena* arena) {
    arena->cursor = 0;
    // Note: We don't zero memory - just reset cursor for O(1) reset
}

/*===========================================================================
 * Arena Allocation
 *=========================================================================*/

const char* AllocateString(FrameArena* arena, const char* start, size_t length) {
    // Check overflow (leave room for null terminator)
    if (arena->cursor + length + 1 > arena->capacity) {
        return NULL;  // Arena full
    }
    
    char* dest = arena->memory + arena->cursor;
    const char* result = dest;
    
    // Manual memcpy
    for (size_t i = 0; i < length; ++i) {
        *dest++ = start[i];
    }
    *dest++ = '\0';
    
    arena->cursor += (length + 1);
    return result;
}

const char* AllocateStringCopy(FrameArena* arena, const char* str) {
    if (!str) return NULL;
    size_t len = 0;
    while (str[len]) ++len;
    return AllocateString(arena, str, len);
}

const char* AllocateFormat(FrameArena* arena, const char* fmt, ...) {
    char temp[256];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(temp, sizeof(temp), fmt, args);
    va_end(args);
    
    if (len < 0 || len >= (int)sizeof(temp)) {
        return NULL;  // Format too long
    }
    
    return AllocateString(arena, temp, (size_t)len);
}

/*===========================================================================
 * Triple Buffer Handoff
 * Lock-free, wait-free thread synchronization
 *=========================================================================*/

static volatile LONG64 g_SequenceCounter = 0;

void SubmitDebugStateToUI() {
    // Get sequence number atomically
    LONG64 seq = InterlockedIncrement64(&g_SequenceCounter);
    
    // Populate sequence in payload
    DebugStatePayload* payload = (DebugStatePayload*)pWriterArena->memory;
    payload->sequenceNumber = (uint64_t)seq;
    payload->submitTimestamp = GetTickCount64();
    
    // Record telemetry
    RecordFrameSubmitted();
    g_DebuggerTelemetry.lastSubmittedSequence = seq;
    
    // 1. Atomically swap writer arena into shared slot
    // Returns whatever was in shared (old reader arena or stale data)
    FrameArena* oldShared = (FrameArena*)InterlockedExchangePointer(
        (PVOID volatile*)&pSharedArena,
        pWriterArena
    );
    
    // 2. Backend now owns the old shared arena
    pWriterArena = oldShared;
    
    // 3. Reset it immediately for next frame
    ResetFrameArena(pWriterArena);
    
    // 4. Increment frame counter
    LONG newFrame = InterlockedIncrement(&g_BackendFrameCount);
    
    // 5. Store frame ID in arena for tracking
    if (pWriterArena) {
        pWriterArena->frameId = (uint32_t)newFrame;
    }
    
    // 6. Notify UI thread (fire-and-forget)
    if (g_hWndMain) {
        PostMessage(g_hWndMain, WM_APP_DEBUG_STATE_UPDATE, 0, 0);
    }
}

DebugStatePayload* ConsumeDebugState() {
    // 1. Atomically swap shared arena into reader slot
    // Returns the latest data from backend
    FrameArena* latestData = (FrameArena*)InterlockedExchangePointer(
        (PVOID volatile*)&pSharedArena,
        pReaderArena
    );
    
    // 2. UI now owns the latest data
    pReaderArena = latestData;
    
    // 3. Update rendered frame tracking
    if (pReaderArena) {
        g_UIRenderedFrame = pReaderArena->frameId;
    }
    
    // 4. Record telemetry and sequence tracking
    DebugStatePayload* payload = (DebugStatePayload*)pReaderArena->memory;
    if (payload) {
        payload->renderTimestamp = GetTickCount64();
        
        // Calculate sequence gap (coalesced frames)
        LONG64 prevSeq = g_DebuggerTelemetry.lastRenderedSequence;
        LONG64 currSeq = (LONG64)payload->sequenceNumber;
        if (prevSeq > 0 && currSeq > prevSeq + 1) {
            // Frames were coalesced (skipped)
            InterlockedAdd64(&g_DebuggerTelemetry.sequenceGaps, currSeq - prevSeq - 1);
        }
        g_DebuggerTelemetry.lastRenderedSequence = currSeq;
    }
    RecordFrameRendered();
    
    // 5. Return payload pointer (stored at start of arena)
    return (DebugStatePayload*)pReaderArena->memory;
}

bool HasNewDebugFrame() {
    LONG currentFrame = (LONG)InterlockedCompareExchange(
        (LONG volatile*)&g_BackendFrameCount, 
        0, 0
    );
    return currentFrame > g_UIRenderedFrame;
}

/*===========================================================================
 * CDB Hex Parser
 * Handles CDB's backtick format: 00007ffc`9a4b0000
 *=========================================================================*/

uint64_t ParseCDBHex(const char** ptr) {
    uint64_t val = 0;
    
    while (**ptr) {
        char c = **ptr;
        
        if (c >= '0' && c <= '9') {
            val = (val << 4) | (uint64_t)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            val = (val << 4) | (uint64_t)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            val = (val << 4) | (uint64_t)(c - 'A' + 10);
        } else if (c == '`') {
            // CDB 64-bit separator - skip it
        } else {
            break;  // End of hex sequence
        }
        
        (*ptr)++;
    }
    
    return val;
}

/*===========================================================================
 * CDB Register Parser
 * Format: rax=0000000000000001 rbx=0000000000000000 ...
 *=========================================================================*/

void ParseRegistersFast(const char* buffer, DebugStatePayload* payload, FrameArena* arena) {
    const char* p = buffer;
    size_t count = 0;
    
    while (*p && count < MAX_REGISTERS) {
        // Skip whitespace
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (!*p) break;
        
        // Parse register name (up to '=' or space)
        const char* nameStart = p;
        while (*p && *p != '=' && *p != ' ' && *p != '\t') p++;
        size_t nameLen = p - nameStart;
        
        if (*p == '=') {
            p++;  // Skip '='
            
            // Parse hex value
            uint64_t value = ParseCDBHex(&p);
            
            // Store in payload
            payload->registers[count].name = AllocateString(arena, nameStart, nameLen);
            payload->registers[count].value = value;
            payload->registers[count].changed = false;  // Will be set by comparison
            
            count++;
        } else {
            // Skip to next token
            while (*p && *p != ' ') p++;
        }
    }
    
    payload->registerCount = count;
}

/*===========================================================================
 * CDB Local Variables Parser
 * Format: 000000a6b5bff720 unsigned int token_count = 0n512
 *=========================================================================*/

void ParseLocalsFast(const char* buffer, DebugStatePayload* payload, FrameArena* arena) {
    const char* p = buffer;
    size_t count = 0;
    
    while (*p && count < MAX_LOCALS) {
        // Find end of line
        const char* lineEnd = p;
        while (*lineEnd && *lineEnd != '\n') lineEnd++;
        
        // Find '=' in this line
        const char* equals = p;
        while (equals < lineEnd && *equals != '=') equals++;
        
        if (equals < lineEnd) {
            // Extract value (after '=')
            const char* valStart = equals + 1;
            while (valStart < lineEnd && *valStart == ' ') valStart++;
            
            const char* valEnd = lineEnd;
            while (valEnd > valStart && (*(valEnd-1) == '\r' || *(valEnd-1) == ' ')) valEnd--;
            
            // Extract name (word before '=')
            const char* nameEnd = equals;
            while (nameEnd > p && *(nameEnd-1) == ' ') nameEnd--;
            
            const char* nameStart = nameEnd;
            while (nameStart > p && *(nameStart-1) != ' ') nameStart--;
            
            // Store in payload
            payload->locals[count].name = AllocateString(arena, nameStart, nameEnd - nameStart);
            payload->locals[count].value = AllocateString(arena, valStart, valEnd - valStart);
            payload->locals[count].type = "unknown";  // Would need more parsing
            payload->locals[count].address = 0;       // Would parse from start of line
            
            count++;
        }
        
        // Move to next line
        p = lineEnd;
        if (*p == '\n') p++;
    }
    
    payload->localCount = count;
}

/*===========================================================================
 * CDB Stack Parser
 * Format: # Child-SP          RetAddr           Call Site
 *=========================================================================*/

void ParseStackFast(const char* buffer, DebugStatePayload* payload, FrameArena* arena) {
    const char* p = buffer;
    size_t count = 0;
    
    // Skip header line
    while (*p && *p != '\n') p++;
    if (*p == '\n') p++;
    
    while (*p && count < 64) {
        // Skip whitespace and frame number
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#') {
            p++;
            while (*p >= '0' && *p <= '9') p++;
        }
        while (*p == ' ' || *p == '\t') p++;
        
        // Parse SP (stack pointer)
        uint64_t sp = ParseCDBHex(&p);
        while (*p == ' ' || *p == '\t') p++;
        
        // Parse RetAddr
        uint64_t retAddr = ParseCDBHex(&p);
        while (*p == ' ' || *p == '\t') p++;
        
        // Parse function name (rest of line)
        const char* funcStart = p;
        const char* lineEnd = p;
        while (*lineEnd && *lineEnd != '\n') lineEnd++;
        
        // Trim trailing whitespace
        const char* funcEnd = lineEnd;
        while (funcEnd > funcStart && (*(funcEnd-1) == ' ' || *(funcEnd-1) == '\t' || *(funcEnd-1) == '\r')) {
            funcEnd--;
        }
        
        // Store frame
        payload->stackFrames[count].frameNumber = (uint32_t)count;
        payload->stackFrames[count].stackPointer = sp;
        payload->stackFrames[count].instructionPointer = retAddr;
        payload->stackFrames[count].functionName = AllocateString(arena, funcStart, funcEnd - funcStart);
        payload->stackFrames[count].moduleName = NULL;
        payload->stackFrames[count].filePath = NULL;
        payload->stackFrames[count].lineNumber = 0;
        
        count++;
        
        // Move to next line
        p = lineEnd;
        if (*p == '\n') p++;
    }
    
    payload->stackFrameCount = count;
}

/*===========================================================================
 * Main CDB State Parser
 *=========================================================================*/

void ParseCDBState(const char* cdbOutput, DebugStatePayload* payload, FrameArena* arena) {
    // Reset payload
    payload->registerCount = 0;
    payload->localCount = 0;
    payload->stackFrameCount = 0;
    payload->instructionPointer = 0;
    payload->currentFile = NULL;
    payload->currentLine = 0;
    payload->isBreakpointHit = false;
    payload->isException = false;
    payload->exceptionMessage = NULL;
    
    // Parse based on content type
    // This would be called for different CDB commands
    // For now, auto-detect by looking for patterns
    
    if (strstr(cdbOutput, "rax=")) {
        ParseRegistersFast(cdbOutput, payload, arena);
    }
    
    if (strstr(cdbOutput, "unsigned int") || strstr(cdbOutput, "struct")) {
        ParseLocalsFast(cdbOutput, payload, arena);
    }
    
    if (strstr(cdbOutput, "Child-SP")) {
        ParseStackFast(cdbOutput, payload, arena);
    }
}
