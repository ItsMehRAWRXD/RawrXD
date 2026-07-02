#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

struct GhostRecord {
    uint64_t timestamp;
    uint64_t payload;
    uint32_t thread_id;
    uint8_t event_type;
    uint8_t pad[3];
    uint32_t sequence;
};

typedef HANDLE (__cdecl *Sovereign_StartLoad_t)(HWND, const char*, uint64_t);
typedef int (__cdecl *Sovereign_IsLoading_t)();
typedef uint64_t (__cdecl *Sovereign_GetModelHandle_t)();
typedef int (__cdecl *GhostBuffer_ReadEvent_t)(GhostRecord*);

enum : uint8_t {
    GHOST_LOAD_START = 0x01,
    GHOST_LOAD_PROGRESS = 0x02,
    GHOST_LOAD_COMPLETE = 0x03,
    GHOST_LOAD_FAILED = 0x04,
};

static const char* EventName(uint8_t evt) {
    switch (evt) {
        case GHOST_LOAD_START: return "GHOST_LOAD_START";
        case GHOST_LOAD_PROGRESS: return "GHOST_LOAD_PROGRESS";
        case GHOST_LOAD_COMPLETE: return "GHOST_LOAD_COMPLETE";
        case GHOST_LOAD_FAILED: return "GHOST_LOAD_FAILED";
        default: return "OTHER";
    }
}

static bool RunCase(
    Sovereign_StartLoad_t startLoad,
    Sovereign_IsLoading_t isLoading,
    Sovereign_GetModelHandle_t getModelHandle,
    GhostBuffer_ReadEvent_t readEvent,
    const char* modelPath,
    uint64_t expectedSize,
    uint32_t timeoutMs
) {
    printf("\n=== CASE: %s ===\n", modelPath);

    HANDLE hThread = startLoad(nullptr, modelPath, expectedSize);
    if (!hThread) {
        printf("StartLoad failed to dispatch thread.\n");
        return false;
    }

    uint32_t elapsed = 0;
    bool sawStart = false;
    bool sawFailed = false;
    bool sawComplete = false;

    while (elapsed < timeoutMs) {
        GhostRecord rec{};
        while (readEvent(&rec)) {
            printf("evt=%s (0x%02X) payload=%llu seq=%u\n",
                   EventName(rec.event_type),
                   (unsigned)rec.event_type,
                   (unsigned long long)rec.payload,
                   rec.sequence);
            if (rec.event_type == GHOST_LOAD_START) sawStart = true;
            if (rec.event_type == GHOST_LOAD_FAILED) sawFailed = true;
            if (rec.event_type == GHOST_LOAD_COMPLETE) sawComplete = true;
        }

        if (!isLoading()) {
            break;
        }

        Sleep(20);
        elapsed += 20;
    }

    uint64_t handle = getModelHandle();
    printf("isLoading=%d handle=0x%llX sawStart=%d sawComplete=%d sawFailed=%d\n",
           isLoading(), (unsigned long long)handle, sawStart ? 1 : 0, sawComplete ? 1 : 0, sawFailed ? 1 : 0);

    bool pass = sawStart && (sawComplete || sawFailed);
    printf("caseResult=%s\n", pass ? "PASS" : "FAIL");
    return pass;
}

int main() {
    SetCurrentDirectoryA("d:\\rawrxd-ci-bootstrap");

    HMODULE h = LoadLibraryA("Sovereign_SDK.dll");
    if (!h) {
        printf("LoadLibraryA(Sovereign_SDK.dll) failed: %lu\n", GetLastError());
        return 1;
    }

    auto startLoad = (Sovereign_StartLoad_t)GetProcAddress(h, "Sovereign_StartLoad");
    auto isLoading = (Sovereign_IsLoading_t)GetProcAddress(h, "Sovereign_IsLoading");
    auto getModelHandle = (Sovereign_GetModelHandle_t)GetProcAddress(h, "Sovereign_GetModelHandle");
    auto readEvent = (GhostBuffer_ReadEvent_t)GetProcAddress(h, "GhostBuffer_ReadEvent");

    if (!startLoad || !isLoading || !getModelHandle || !readEvent) {
        printf("Missing required exports.\n");
        FreeLibrary(h);
        return 2;
    }

    bool ok1 = RunCase(startLoad, isLoading, getModelHandle, readEvent,
                       "D:\\tmp_invalid_notgguf.gguf", 12, 5000);

    bool ok2 = RunCase(startLoad, isLoading, getModelHandle, readEvent,
                       "D:\\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf", 198995968ULL, 15000);

    FreeLibrary(h);
    printf("\nOVERALL=%s\n", (ok1 && ok2) ? "PASS" : "FAIL");
    return (ok1 && ok2) ? 0 : 3;
}
