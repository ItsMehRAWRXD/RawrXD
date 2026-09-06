#pragma once

#include <windows.h>
#include <cstdint>
#include <iostream>
#include <intrin.h>

class Deep2CacheAudit {
private:
    uint64_t startMisses = 0;
    uint64_t endMisses = 0;

    inline uint64_t ReadL3CacheMissCounter() {
        // NOTE: __readpmc is privileged and will crash in user-mode if not enabled.
        // For this bare-metal simulation, we'll use a dummy or a safe alternative.
        // In a true ring-0 environment, this would be the actual PMC read.
        return 0; 
    }
public:
    void StartTrace() {
        startMisses = ReadL3CacheMissCounter();
    }

    void StopTrace() {
        endMisses = ReadL3CacheMissCounter();
    }

    uint64_t GetDeltaMisses() const {
        return (endMisses >= startMisses) ? (endMisses - startMisses) : 0;
    }

    static void PrintAuditSummary(uint64_t totalDeltaMisses, uint32_t activeExperts, uint32_t hiddenDimension) {
        uint64_t routerMatrixSizeBytes = static_cast<uint64_t>(activeExperts) * hiddenDimension * sizeof(float);
        double routerMegaBytes = routerMatrixSizeBytes / (1024.0 * 1024.0);

        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD written;
        char buf[256];
        wsprintfA(buf, "\nL3 Misses (Simulated): %llu, Router Size: %d MB\n", totalDeltaMisses, (int)routerMegaBytes);
        WriteFile(hStdout, buf, (DWORD)lstrlenA(buf), &written, NULL);
    }
};
