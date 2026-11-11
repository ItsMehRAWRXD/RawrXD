/*===========================================================================
 * IDEDebuggerTypes.h
 * Zero-dependency transport structures for debugger UI thread marshalling
 * 
 * NO STL - Pure C structs for Win32 thread safety
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <stdint.h>

// Maximum counts for fixed-size arrays
#define MAX_REGISTERS 32
#define MAX_LOCALS 256
#define MAX_DEBUG_FRAMES 3

// Arena size: 1MB per frame (enough for thousands of strings)
#define FRAME_ARENA_SIZE (1024 * 1024)

/*===========================================================================
 * Transport Structures
 * Lightweight, cache-friendly, zero STL
 *=========================================================================*/

struct DebugRegister {
    const char* name;       // Points into arena memory
    uint64_t value;
    bool changed;           // Highlight if changed since last step
};

struct DebugLocal {
    const char* name;       // Variable name
    const char* type;       // C++ type string
    const char* value;      // Formatted value string
    uint64_t address;       // Memory address for inspection
};

struct DebugStackFrame {
    uint64_t instructionPointer;
    uint64_t stackPointer;
    uint64_t framePointer;
    const char* functionName;
    const char* moduleName;
    const char* filePath;
    uint32_t lineNumber;
};

struct DebugStatePayload {
    // Sequence tracking for frame coalescing validation
    uint64_t sequenceNumber;    // Monotonic sequence (1, 2, 3...)
    uint64_t submitTimestamp;   // Backend submit time (ms)
    uint64_t renderTimestamp;   // UI render time (ms)
    
    // Registers
    DebugRegister registers[MAX_REGISTERS];
    size_t registerCount;
    
    // Local variables
    DebugLocal locals[MAX_LOCALS];
    size_t localCount;
    
    // Stack
    DebugStackFrame stackFrames[64];
    size_t stackFrameCount;
    
    // Current execution point
    uint64_t instructionPointer;
    const char* currentFile;
    uint32_t currentLine;
    
    // Frame metadata
    uint64_t frameId;       // Legacy frame counter
    bool isBreakpointHit;
    bool isException;
    const char* exceptionMessage;
};

/*===========================================================================
 * Linear Memory Arena
 * Bump allocator for zero-heap debug strings
 *=========================================================================*/

struct FrameArena {
    char* memory;
    size_t capacity;
    size_t cursor;
    uint32_t frameId;       // For triple buffering sync
};

// Arena lifecycle
void InitFrameArena(FrameArena* arena, size_t size);
void DestroyFrameArena(FrameArena* arena);
void ResetFrameArena(FrameArena* arena);

// Allocation (returns pointer into arena, NULL on overflow)
const char* AllocateString(FrameArena* arena, const char* start, size_t length);
const char* AllocateStringCopy(FrameArena* arena, const char* str);

// Helper to allocate formatted string
const char* AllocateFormat(FrameArena* arena, const char* fmt, ...);

/*===========================================================================
 * Triple Buffering State
 * Global handoff point between backend and UI threads
 *=========================================================================*/

// Extern declarations - defined in IDEDebuggerAdapter.cpp
extern FrameArena g_DebugArenas[MAX_DEBUG_FRAMES];
extern FrameArena* volatile pWriterArena;
extern FrameArena* volatile pReaderArena;
extern FrameArena* volatile pSharedArena;
extern volatile LONG g_BackendFrameCount;
extern volatile LONG g_UIRenderedFrame;

/*===========================================================================
 * Telemetry Counters
 * For performance tuning and diagnostics
 *=========================================================================*/
struct DebuggerTelemetry {
    volatile LONG64 framesSubmitted;      // Total frames from backend
    volatile LONG64 framesRendered;       // Total frames consumed by UI
    volatile LONG64 framesDropped;          // Calculated: submitted - rendered
    volatile LONG64 maxRenderLatencyMs;   // Worst-case UI lag
    volatile LONG64 arenaHighWaterMark;     // Peak arena usage
    volatile LONG64 parseTimeUs;            // Microseconds to parse CDB output
    volatile LONG64 renderTimeUs;           // Microseconds to render frame
    volatile LONG64 lastSubmitTime;         // Timestamp of last submit
    volatile LONG64 lastRenderTime;         // Timestamp of last render
    
    // Sequence tracking for coalescing validation
    volatile LONG64 lastSubmittedSequence;  // Last sequence number submitted
    volatile LONG64 lastRenderedSequence;   // Last sequence number rendered
    volatile LONG64 sequenceGaps;           // Count of skipped sequences (coalesced)
};

extern DebuggerTelemetry g_DebuggerTelemetry;

// Telemetry helpers
void RecordFrameSubmitted();
void RecordFrameRendered();
void RecordParseTime(LONG64 microseconds);
void RecordRenderTime(LONG64 microseconds);
void RecordArenaUsage(size_t bytesUsed);
DebuggerTelemetry GetDebuggerTelemetry();

// Thread-safe handoff functions
void SubmitDebugStateToUI();           // Call from backend thread
DebugStatePayload* ConsumeDebugState();  // Call from UI thread
bool HasNewDebugFrame();                 // Check before consuming

/*===========================================================================
 * CDB Parser Functions
 * Zero-copy lexical scanners
 *=========================================================================*/

// Parse hex value, handles CDB backtick format (00007ffc`9a4b0000)
uint64_t ParseCDBHex(const char** ptr);

// Parse register output from CDB 'r' command
void ParseRegistersFast(const char* buffer, DebugStatePayload* payload, FrameArena* arena);

// Parse local variables from CDB 'dv /t /v' command  
void ParseLocalsFast(const char* buffer, DebugStatePayload* payload, FrameArena* arena);

// Parse stack trace from CDB 'k' command
void ParseStackFast(const char* buffer, DebugStatePayload* payload, FrameArena* arena);

// Main entry: parse complete CDB state
void ParseCDBState(const char* cdbOutput, DebugStatePayload* payload, FrameArena* arena);
