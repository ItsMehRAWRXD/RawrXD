// ============================================================================
// b015_residency_cert_test.cpp
// Standalone certification test for B015 residency state machine.
//
// Build (MSVC):
//   cl /EHsc /O2 /I..\..\src\runtime\memory /I..\..\src b015_residency_cert_test.cpp ..\..\src\runtime\memory\BlockTable.cpp ..\..\src\runtime\memory\SSDWriteBackQueue.cpp ..\..\src\runtime\memory\DRP_EvictionEngine.cpp ..\..\src\runtime\memory\ResidencyCertification.cpp ..\..\src\runtime\memory\StreamingMatMulResidencyBridge.cpp /Fe:b015_residency_cert_test.exe
//
// Build (GCC/Clang):
//   g++ -O2 -o b015_residency_cert_test b015_residency_cert_test.cpp BlockTable.cpp SSDWriteBackQueue.cpp DRP_EvictionEngine.cpp ResidencyCertification.cpp StreamingMatMulResidencyBridge.cpp
// ============================================================================
#include "ResidencyCertification.hpp"
#include <cstdio>
#include <windows.h>

using namespace RawrXD::Memory;
using namespace RawrXD::Memory::Cert;

int main() {
    std::printf("B015: Residency State Machine Certification\n");
    std::printf("============================================\n\n");

    // Create a temporary backing file for SSD simulation
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    wchar_t tempFile[MAX_PATH];
    GetTempFileNameW(tempPath, L"b015", 0, tempFile);

    HANDLE hFile = CreateFileW(tempFile,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_FLAG_OVERLAPPED,
        nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        std::printf("Failed to create temp backing file.\n");
        return 1;
    }

    // Pre-allocate 1 GB
    LARGE_INTEGER size;
    size.QuadPart = 1LL << 30;
    SetFilePointerEx(hFile, size, nullptr, FILE_BEGIN);
    SetEndOfFile(hFile);
    SetFilePointerEx(hFile, LARGE_INTEGER{0}, nullptr, FILE_BEGIN);

    // Build subsystem
    BlockTable table(4096);
    SSDWriteBackQueue queue(table, hFile);
    if (!queue.start(1)) {
        std::printf("Failed to start SSD write-back queue.\n");
        CloseHandle(hFile);
        DeleteFileW(tempFile);
        return 1;
    }

    DRPEvictionEngine engine(table, queue);

    // Run all gates
    CertificationReport report = Cert::RunAllGates(table, engine, queue, hFile);
    Cert::PrintReport(report);

    // Cleanup
    queue.stop();
    CloseHandle(hFile);
    DeleteFileW(tempFile);

    return report.allPassed ? 0 : 1;
}
