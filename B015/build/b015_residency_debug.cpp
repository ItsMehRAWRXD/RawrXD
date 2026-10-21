// ============================================================================
// b015_residency_debug.cpp — step-through debug version
// ============================================================================
#include "ResidencyCertification.hpp"
#include <cstdio>
#include <windows.h>

using namespace RawrXD::Memory;
using namespace RawrXD::Memory::Cert;

int main() {
    std::printf("B015: Residency State Machine Certification (DEBUG)\n");
    std::printf("====================================================\n\n");

    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    wchar_t tempFile[MAX_PATH];
    GetTempFileNameW(tempPath, L"b015", 0, tempFile);

    // NOTE: SSDWriteBackQueue requires FILE_FLAG_OVERLAPPED for CreateIoCompletionPort
    HANDLE hFile = CreateFileW(tempFile,
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, CREATE_ALWAYS,
        FILE_FLAG_OVERLAPPED,
        nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        std::printf("Failed to create temp backing file.\n");
        return 1;
    }

    LARGE_INTEGER size;
    size.QuadPart = 1LL << 30;
    SetFilePointerEx(hFile, size, nullptr, FILE_BEGIN);
    SetEndOfFile(hFile);
    SetFilePointerEx(hFile, LARGE_INTEGER{0}, nullptr, FILE_BEGIN);

    BlockTable table(4096);
    SSDWriteBackQueue queue(table, hFile);
    if (!queue.start(1)) {
        std::printf("Failed to start SSD write-back queue.\n");
        CloseHandle(hFile);
        DeleteFileW(tempFile);
        return 1;
    }

    DRPEvictionEngine engine(table, queue);

    std::printf("Running Gate A...\n");
    std::fflush(stdout);

    std::printf("[B015:A0] before RunGateA\n");
    std::fflush(stdout);

    GateAResult gateA = RunGateA(table, engine, 64ULL << 20, 48ULL << 20);

    std::printf("[B015:A1] after RunGateA\n");
    std::fflush(stdout);

    std::printf("Gate A: %s\n", gateA.passed ? "PASS" : "FAIL");
    if (gateA.error) std::printf("  Error: %s\n", gateA.error);

    std::printf("Running Gate B...\n");
    GateBResult gateB = RunGateB(table, engine, queue, hFile, 4, 4 * 1024 * 1024);
    std::printf("Gate B: %s\n", gateB.passed ? "PASS" : "FAIL");
    if (gateB.error) std::printf("  Error: %s\n", gateB.error);

    std::printf("Running Gate C...\n");
    GateCResult gateC = RunGateC(table, engine, 4, 4 * 1024 * 1024);
    std::printf("Gate C: %s\n", gateC.passed ? "PASS" : "FAIL");
    if (gateC.error) std::printf("  Error: %s\n", gateC.error);

    std::printf("Running Gate D...\n");
    GateDResult gateD = RunGateD(table, engine, queue, hFile, 1, 2);
    std::printf("Gate D: %s\n", gateD.passed ? "PASS" : "FAIL");
    if (gateD.error) std::printf("  Error: %s\n", gateD.error);

    queue.stop();
    CloseHandle(hFile);
    DeleteFileW(tempFile);

    bool allPassed = gateA.passed && gateB.passed && gateC.passed && gateD.passed;
    std::printf("\nOVERALL: %s\n", allPassed ? "ALL PASSED" : "SOME FAILED");
    return allPassed ? 0 : 1;
}
