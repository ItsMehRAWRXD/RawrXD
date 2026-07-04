// ============================================================================
// RawrXD Hotpatch Client - Standalone Pipe Client
// Sends bytecode payloads to running rawrxd-cli.exe via named pipe
// ============================================================================

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stddef.h>

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

#define HOTPATCH_MAGIC 0x52485044
#define HOTPATCH_VERSION 1
#define PIPE_NAME "\\\\.\\pipe\\RawrXD_Inference"
#define DEFAULT_TIMEOUT_MS 10000

// Calculate CRC32 checksum
uint32_t CalculateCRC32(const uint8_t* data, size_t len, uint32_t initialCrc = 0xFFFFFFFF) {
    uint32_t crc = initialCrc;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return (initialCrc == 0xFFFFFFFF) ? ~crc : crc;
}

// Build a hotpatch payload from raw bytes
HotpatchPayload* BuildPayload(const uint8_t* data, size_t dataLen, uint32_t flags) {
    size_t totalSize = sizeof(HotpatchPayload) + dataLen;
    HotpatchPayload* payload = (HotpatchPayload*)malloc(totalSize);
    if (!payload) return NULL;
    
    payload->magic = HOTPATCH_MAGIC;
    payload->version = HOTPATCH_VERSION;
    payload->payloadSize = (uint32_t)dataLen;
    payload->flags = flags;
    payload->timestamp = (uint64_t)time(NULL);
    memcpy(payload->data, data, dataLen);
    
    // Calculate CRC over payload data only (simplified)
    payload->crc32 = CalculateCRC32(payload->data, dataLen);
    
    return payload;
}

// Send payload via named pipe
bool SendPayload(HotpatchPayload* payload, size_t totalSize, uint8_t* response, size_t* responseLen) {
    HANDLE hPipe = CreateFileA(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (hPipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[ERROR] Failed to connect to pipe: %lu\n", GetLastError());
        return false;
    }
    
    // Set pipe to message mode
    DWORD dwMode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL)) {
        fprintf(stderr, "[WARN] Failed to set message mode: %lu\n", GetLastError());
    }
    
    // Send payload
    DWORD bytesWritten;
    if (!WriteFile(hPipe, payload, (DWORD)totalSize, &bytesWritten, NULL)) {
        fprintf(stderr, "[ERROR] WriteFile failed: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return false;
    }
    
    printf("[INFO] Sent %lu bytes to pipe\n", bytesWritten);
    
    // Flush to ensure server receives it
    FlushFileBuffers(hPipe);
    
    // Read response
    DWORD bytesRead;
    BOOL success = ReadFile(hPipe, response, (DWORD)*responseLen, &bytesRead, NULL);
    if (success || GetLastError() == ERROR_MORE_DATA) {
        *responseLen = bytesRead;
        printf("[INFO] Received %lu bytes response\n", bytesRead);
    } else {
        fprintf(stderr, "[WARN] ReadFile failed: %lu\n", GetLastError());
        *responseLen = 0;
    }
    
    CloseHandle(hPipe);
    return true;
}

// Print usage
void PrintUsage(const char* prog) {
    printf("Usage: %s [options] <payload_file>\n", prog);
    printf("Options:\n");
    printf("  -f, --file <path>    Payload file to send (binary)\n");
    printf("  -s, --string <text>    Send string as payload\n");
    printf("  -x, --hex <hexstr>    Send hex string as payload\n");
    printf("  -t, --timeout <ms>    Timeout in milliseconds (default: 10000)\n");
    printf("  -v, --verbose         Verbose output\n");
    printf("  -h, --help            Show this help\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    const char* payloadFile = NULL;
    const char* payloadString = NULL;
    const char* payloadHex = NULL;
    uint32_t flags = 0;
    DWORD timeoutMs = DEFAULT_TIMEOUT_MS;
    bool verbose = false;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) {
            if (++i < argc) payloadFile = argv[i];
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--string") == 0) {
            if (++i < argc) payloadString = argv[i];
        } else if (strcmp(argv[i], "-x") == 0 || strcmp(argv[i], "--hex") == 0) {
            if (++i < argc) payloadHex = argv[i];
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--timeout") == 0) {
            if (++i < argc) timeoutMs = atoi(argv[i]);
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-') {
            payloadFile = argv[i];
        }
    }
    
    // Build payload data
    uint8_t* payloadData = NULL;
    size_t payloadLen = 0;
    
    if (payloadFile) {
        FILE* f = fopen(payloadFile, "rb");
        if (!f) {
            fprintf(stderr, "[ERROR] Failed to open %s\n", payloadFile);
            return 1;
        }
        fseek(f, 0, SEEK_END);
        payloadLen = ftell(f);
        fseek(f, 0, SEEK_SET);
        payloadData = (uint8_t*)malloc(payloadLen);
        fread(payloadData, 1, payloadLen, f);
        fclose(f);
        if (verbose) printf("[INFO] Loaded %zu bytes from %s\n", payloadLen, payloadFile);
    } else if (payloadString) {
        payloadLen = strlen(payloadString);
        payloadData = (uint8_t*)malloc(payloadLen);
        memcpy(payloadData, payloadString, payloadLen);
        if (verbose) printf("[INFO] Using string payload (%zu bytes)\n", payloadLen);
    } else if (payloadHex) {
        // Parse hex string
        payloadLen = strlen(payloadHex) / 2;
        payloadData = (uint8_t*)malloc(payloadLen);
        for (size_t i = 0; i < payloadLen; i++) {
            unsigned int byte;
            sscanf(payloadHex + i*2, "%2x", &byte);
            payloadData[i] = (uint8_t)byte;
        }
        if (verbose) printf("[INFO] Using hex payload (%zu bytes)\n", payloadLen);
    } else {
        // Default test payload
        const char* testPayload = "{\"test\": \"hotpatch\"}";
        payloadLen = strlen(testPayload);
        payloadData = (uint8_t*)malloc(payloadLen);
        memcpy(payloadData, testPayload, payloadLen);
        printf("[INFO] Using default test payload\n");
    }
    
    // Build the hotpatch payload structure
    HotpatchPayload* payload = BuildPayload(payloadData, payloadLen, flags);
    if (!payload) {
        fprintf(stderr, "[ERROR] Failed to build payload\n");
        free(payloadData);
        return 1;
    }
    
    size_t totalSize = sizeof(HotpatchPayload) + payloadLen;
    if (verbose) {
        printf("[INFO] Payload: magic=0x%08X version=%u size=%u flags=0x%08X\n",
               payload->magic, payload->version, payload->payloadSize, payload->flags);
        printf("[INFO] Total packet size: %zu bytes\n", totalSize);
    }
    
    // Send and receive
    uint8_t response[4096];
    size_t responseLen = sizeof(response);
    
    printf("[INFO] Connecting to pipe: %s\n", PIPE_NAME);
    
    if (!SendPayload(payload, totalSize, response, &responseLen)) {
        fprintf(stderr, "[ERROR] Failed to send payload\n");
        free(payload);
        free(payloadData);
        return 1;
    }
    
    // Display response
    if (responseLen > 0) {
        printf("[SUCCESS] Response (%zu bytes):\n", responseLen);
        // Try to print as string first
        bool isPrintable = true;
        for (size_t i = 0; i < responseLen && i < 100; i++) {
            if (response[i] < 32 && response[i] != '\n' && response[i] != '\r') {
                isPrintable = false;
                break;
            }
        }
        if (isPrintable) {
            printf("%.*s\n", (int)responseLen, (char*)response);
        } else {
            // Print as hex
            for (size_t i = 0; i < responseLen && i < 64; i++) {
                printf("%02X ", response[i]);
                if ((i + 1) % 16 == 0) printf("\n");
            }
            printf("\n");
        }
    } else {
        printf("[WARN] No response received\n");
    }
    
    free(payload);
    free(payloadData);
    return 0;
}
