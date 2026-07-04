#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stddef.h>

// External functions from cli_stream.cpp
extern "C" int RawrXD_CliHeadlessEntry();

// External functions from RawrXD_PipeServer_v2.asm
extern "C" {
    uint64_t RawrXD_PipeServer_Init();
    uint64_t RawrXD_PipeServer_RunOnce();
    uint64_t RawrXD_PipeServer_Shutdown();
}

// External functions from cli_history.asm
extern "C" void RawrXD_REPL_MainLoop();
extern "C" void RawrXD_InitConsoleHandles();

// Command line parsing helper
bool HasArgument(int argc, char* argv[], const char* arg) {
    for (int i = 1; i < argc; i++) {
        if (argv[i] && _stricmp(argv[i], arg) == 0) {
            return true;
        }
    }
    return false;
}

// Check if stdin is a pipe or redirected file
bool IsStdinPiped() {
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin == INVALID_HANDLE_VALUE) return false;
    
    DWORD dwFileType = GetFileType(hStdin);
    dwFileType &= ~FILE_TYPE_REMOTE;
    
    return (dwFileType == FILE_TYPE_PIPE) || (dwFileType == FILE_TYPE_DISK);
}

// Hotpatch payload structure
#pragma pack(push, 1)
struct HotpatchPayload {
    uint32_t magic;           // 0x52485044 "RHPD"
    uint32_t version;         // Payload version
    uint32_t payloadSize;     // Size of payload data
    uint32_t flags;           // Execution flags
    uint64_t timestamp;       // Unix timestamp
    uint32_t crc32;           // CRC32 checksum
    uint8_t  data[0];         // Variable-length payload
};
#pragma pack(pop)

#define HOTPATCH_MAGIC 0x52485044  // "RHPD"
#define HOTPATCH_VERSION 1

// Calculate simple checksum
uint32_t CalculateCRC32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return ~crc;
}

// Validate hotpatch payload
bool ValidatePayload(const uint8_t* buffer, size_t len, HotpatchPayload** outPayload, size_t* outDataLen) {
    if (len < sizeof(HotpatchPayload)) {
        return false;
    }
    
    HotpatchPayload* payload = (HotpatchPayload*)buffer;
    
    // Check magic
    if (payload->magic != HOTPATCH_MAGIC) {
        fprintf(stderr, "[ERROR] Invalid payload magic: 0x%08X (expected 0x%08X)\n", payload->magic, HOTPATCH_MAGIC);
        return false;
    }
    
    // Check version
    if (payload->version != HOTPATCH_VERSION) {
        fprintf(stderr, "[ERROR] Unsupported payload version: %u (expected %u)\n", payload->version, HOTPATCH_VERSION);
        return false;
    }
    
    // Check size
    size_t totalSize = sizeof(HotpatchPayload) + payload->payloadSize;
    if (totalSize > len) {
        fprintf(stderr, "[ERROR] Payload size mismatch: header says %u, buffer has %zu\n", payload->payloadSize, len - sizeof(HotpatchPayload));
        return false;
    }
    
    // Verify checksum
    uint32_t calcCrc = CalculateCRC32((uint8_t*)&payload->version, sizeof(HotpatchPayload) - offsetof(HotpatchPayload, version) - sizeof(uint32_t));
    calcCrc = CalculateCRC32(payload->data, payload->payloadSize);
    if (calcCrc != payload->crc32) {
        fprintf(stderr, "[ERROR] CRC32 mismatch: calculated 0x%08X, expected 0x%08X\n", calcCrc, payload->crc32);
        return false;
    }
    
    *outPayload = payload;
    *outDataLen = payload->payloadSize;
    return true;
}

// Process hotpatch payload through ASM router
bool ExecuteHotpatch(const uint8_t* data, size_t len) {
    HotpatchPayload* payload;
    size_t dataLen;
    
    if (!ValidatePayload(data, len, &payload, &dataLen)) {
        return false;
    }
    
    fprintf(stderr, "[INFO] Valid hotpatch payload: %u bytes, flags=0x%08X\n", payload->payloadSize, payload->flags);
    fprintf(stderr, "[INFO] Payload validated successfully (hotpatch router not linked in this build)\n");
    
    // In production, this would call RawrXD_RequestHotpatch from rawrxd_hotpatch_router.asm
    // For now, we just validate the payload format
    return true;
}

// Buffer piped input and process as hotpatch payload
bool ProcessPipedInput(bool stressTest = false) {
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    
    if (hStdin == INVALID_HANDLE_VALUE || hStdout == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Read all piped input into buffer
    static uint8_t buffer[65536];
    DWORD totalRead = 0;
    DWORD bytesRead = 0;
    
    clock_t startTime = clock();
    
    while (totalRead < sizeof(buffer) - 1) {
        if (!ReadFile(hStdin, buffer + totalRead, sizeof(buffer) - totalRead - 1, &bytesRead, NULL)) {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF) {
                break;
            }
            return false;
        }
        if (bytesRead == 0) break;
        totalRead += bytesRead;
        
        // Stress test: add artificial delay to test buffer handling
        if (stressTest && (totalRead % 1024) == 0) {
            Sleep(1);
        }
    }
    
    clock_t endTime = clock();
    double elapsedMs = ((double)(endTime - startTime)) / CLOCKS_PER_SEC * 1000.0;
    
    if (totalRead == 0) {
        return false; // No piped data
    }
    
    // Single prompt for piped input
    DWORD written;
    const char* prompt = "rawrxd> ";
    WriteFile(hStdout, prompt, 8, &written, NULL);
    
    // Try to process as hotpatch payload
    if (ExecuteHotpatch(buffer, totalRead)) {
        WriteFile(hStdout, "HOTPATCH_OK", 11, &written, NULL);
    } else {
        // Not a valid hotpatch - just echo the data
        WriteFile(hStdout, buffer, totalRead, &written, NULL);
    }
    
    WriteFile(hStdout, "\r\n", 2, &written, NULL);
    
    if (stressTest) {
        fprintf(stderr, "[STRESS] Read %u bytes in %.2f ms (%.2f KB/s)\n",
                totalRead, elapsedMs, (totalRead / 1024.0) / (elapsedMs / 1000.0));
    }
    
    return true;
}

// Entry point - uses main() for standard console entry
int main(int argc, char* argv[]) {
    // Check for headless/pipe mode first
    bool isHeadless = false;
    for (int i = 1; i < argc; i++) {
        if (argv[i] && (strcmp(argv[i], "--headless") == 0 || strcmp(argv[i], "-h") == 0)) {
            isHeadless = true;
            break;
        }
    }
    
    // Check for stress test mode
    bool stressTest = HasArgument(argc, argv, "--stress") || HasArgument(argc, argv, "-s");
    
    if (isHeadless) {
        // Initialize named pipe server for IPC
        uint64_t pipeResult = RawrXD_PipeServer_Init();
        if (pipeResult != 0) {
            printf("[ERROR] Failed to initialize pipe server: %llu\n", pipeResult);
            return 1;
        }
        
        printf("[INFO] Named pipe server initialized: \\\\.\\pipe\\RawrXD_Inference\n");
        printf("[INFO] Entering pipe server loop...\n");
        fflush(stdout);
        
        // Run pipe server loop
        while (true) {
            uint64_t runResult = RawrXD_PipeServer_RunOnce();
            if (runResult == 0xFFFFFFFF) {
                // Shutdown requested
                break;
            }

            // MASM RunOnce returns encoded Win32 errors:
            // 0x1xxxxxxx connect, 0x2xxxxxxx read, 0x3xxxxxxx write.
            if ((runResult & 0xF0000000ULL) != 0) {
                printf("[PIPE][WARN] RunOnce error code=0x%llX\n", runResult);
                fflush(stdout);
            }

            Sleep(10);
        }
        
        RawrXD_PipeServer_Shutdown();
        printf("[INFO] Pipe server shutdown complete.\n");
        return 0;
    }
    
    // Check if stdin is piped - if so, buffer and process as hotpatch payload
    if (IsStdinPiped()) {
        if (ProcessPipedInput(stressTest)) {
            return 0;
        }
        // Fall through to REPL if pipe processing failed
    }
    
    // Interactive REPL mode
    RawrXD_InitConsoleHandles();
    RawrXD_REPL_MainLoop();
    
    return 0;
}
