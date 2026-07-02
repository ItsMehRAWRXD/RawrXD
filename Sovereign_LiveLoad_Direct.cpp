#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

extern "C" {
    HANDLE Sovereign_StartLoad(HWND hwnd, const char* path, uint64_t expectedSize);
    int Sovereign_IsLoading();
    int Sovereign_GetLastLoadResult();
    uint64_t Sovereign_GetModelHandle();
    int GhostBuffer_ReadEvent(void* out);
}

struct GhostRecord {
    uint64_t timestamp;
    uint64_t payload;
    uint32_t thread_id;
    uint8_t event_type;
    uint8_t pad[3];
    uint32_t sequence;
};

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

static bool RunCase(const char* modelPath, uint64_t expectedSize, uint32_t timeoutMs) {
    printf("\n=== CASE: %s ===\n", modelPath);

    HANDLE h = Sovereign_StartLoad(nullptr, modelPath, expectedSize);
    if (!h) {
        printf("Sovereign_StartLoad failed\n");
        return false;
    }

    bool sawStart = false;
    bool sawComplete = false;
    bool sawFailed = false;
    bool orderingOk = true;
    bool seqSeen = false;
    uint32_t prevSeq = 0;
    bool readAv = false;

    uint32_t elapsed = 0;
    while (elapsed < timeoutMs) {
        GhostRecord rec{};
        while (true) {
            int hasEvent = 0;
            __try {
                hasEvent = GhostBuffer_ReadEvent(&rec);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                readAv = true;
                printf("CRITICAL: GhostBuffer_ReadEvent AV during load telemetry drain\n");
                break;
            }

            if (!hasEvent) {
                break;
            }

            if (seqSeen && rec.sequence <= prevSeq) {
                orderingOk = false;
                printf("ORDER VIOLATION: prevSeq=%u currentSeq=%u\n", prevSeq, rec.sequence);
            }
            prevSeq = rec.sequence;
            seqSeen = true;

            printf("evt=%s(0x%02X) payload=%llu seq=%u\n",
                   EventName(rec.event_type), (unsigned)rec.event_type,
                   (unsigned long long)rec.payload, rec.sequence);
            if (rec.event_type == GHOST_LOAD_START) sawStart = true;
            if (rec.event_type == GHOST_LOAD_COMPLETE) sawComplete = true;
            if (rec.event_type == GHOST_LOAD_FAILED) sawFailed = true;
        }

        if (readAv) {
            break;
        }

        if (!Sovereign_IsLoading()) break;
        Sleep(20);
        elapsed += 20;
    }

    uint64_t handle = Sovereign_GetModelHandle();
    const int lastLoadResult = Sovereign_GetLastLoadResult();
    printf("isLoading=%d handle=0x%llX sawStart=%d sawComplete=%d sawFailed=%d orderingOk=%d lastLoadResult=%d\n",
           Sovereign_IsLoading(), (unsigned long long)handle,
           sawStart ? 1 : 0, sawComplete ? 1 : 0, sawFailed ? 1 : 0,
           orderingOk ? 1 : 0, lastLoadResult);

    bool leakFreeOnFail = true;
    if (sawFailed && handle != 0) {
        leakFreeOnFail = false;
        printf("CRITICAL: Load failed but handle is still valid!\n");
    }

    bool pass = sawStart && (sawComplete || sawFailed) && orderingOk && leakFreeOnFail && !readAv;
    printf("caseResult=%s\n", pass ? "PASS" : "FAIL");
    return pass;
}

int main() {
    bool ok = RunCase("D:\\this_file_should_not_exist_telemetry_probe.gguf", 0, 5000);
    printf("\nOVERALL=%s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
