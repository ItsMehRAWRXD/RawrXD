#include <windows.h>
#include <cstdint>
#include "Deep2ThreadTuning.hpp"
#include "Deep2Quantization.hpp"
#include "Deep2MatrixWrapper.hpp"
#include "Deep2MultiGpuBridge.hpp"
#include "Deep2Profiler.hpp"
#include "Deep2StorageRing.hpp"
#include "Deep2TrafficAccounting.hpp"
#include "Deep2MoeRouter.hpp"
#include "Deep2ExpertAuditor.hpp"

using namespace rawrxd::deep2;

// Minimal printf-like helper for CRT-free execution
void RawPrint(const char* msg) {
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    WriteFile(hStdout, msg, (DWORD)lstrlenA(msg), &written, NULL);
}

void RawPrintInt(const char* prefix, uint64_t val) {
    char buf[64];
    RawPrint(prefix);
    wsprintfA(buf, "%llu\n", val);
    RawPrint(buf);
}

enum class RunConfig {
    Sync,
    IOCPSingleSlot,
    IOCPOverlap,
    Sustained,
    ColdCache
};

void ExecuteParameterizedSweep(RunConfig config, const char* label, uint32_t tokensToGen = 128) {
    Deep2Profiler profiler;
    SovereignTrafficAccounting traffic;
    const uint32_t totalModelLayers = 96;
    const uint64_t matrixDimension = 8192;
    const uint64_t sliceSize = (matrixDimension * matrixDimension / 512) * sizeof(Deep2Quantization::QuantizedBlock512);

    traffic.SetModelFacts(671000000000ULL, 125812500000ULL, 64);

    try {
        Deep2ThreadTuning::VacuumSequestrationOS();
        Deep2ThreadTuning::LockComputePipeline(0, false);

        const wchar_t* modelPath = L"mock_model.bin";
        HANDLE hTemp = CreateFileW(modelPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hTemp != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER li;
            li.QuadPart = sliceSize * 256;
            SetFilePointerEx(hTemp, li, NULL, FILE_BEGIN);
            SetEndOfFile(hTemp);
            CloseHandle(hTemp);
        }

        Deep2StorageRing storageRing(modelPath, sliceSize);
        storageRing.SetTrafficAccounting(&traffic);
        Deep2ExpertAuditor auditor(totalModelLayers);
        
        float* outActivations = static_cast<float*>(VirtualAlloc(NULL, matrixDimension * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        float* inActivations = static_cast<float*>(VirtualAlloc(NULL, matrixDimension * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        
        // Zero memory for activations
        for (uint64_t i = 0; i < matrixDimension; ++i) inActivations[i] = 0.05f;

        uint64_t currentOffset = 0;
        bool useOverlap = (config == RunConfig::IOCPOverlap || config == RunConfig::Sustained || config == RunConfig::ColdCache);

        traffic.BeginEvaluation();

        profiler.StartPromptIngestion(1000000);
        storageRing.PrimeBackgroundPrefetch(currentOffset);
        storageRing.SynchronizeRingRotation();
        currentOffset += sliceSize;
        profiler.EndPromptIngestion();

        profiler.StartTokenGeneration();
        for (uint32_t t = 0; t < tokensToGen; ++t) {
            if (useOverlap) {
                storageRing.SynchronizeRingRotation();
            } else {
                storageRing.PrimeBackgroundPrefetch(currentOffset);
                storageRing.SynchronizeRingRotation();
            }

            traffic.RecordExpertSelection(37000000000ULL / totalModelLayers, sliceSize, true);
            uint32_t mockExperts[2] = {1, 2};
            auditor.LogRouterSelection(mockExperts, 2, matrixDimension * matrixDimension, static_cast<uint64_t>(matrixDimension * matrixDimension * 0.4));
            
            const auto* weights = reinterpret_cast<const Deep2Quantization::QuantizedBlock512*>(storageRing.GetActiveComputePointer());
            Deep2MatrixWrapper::ComputeAsymmetricLayerGEMV(weights, static_cast<uint32_t>(matrixDimension), static_cast<uint32_t>(matrixDimension), outActivations);

            if (useOverlap) {
                currentOffset += sliceSize;
                storageRing.PrimeBackgroundPrefetch(currentOffset);
            } else {
                currentOffset += sliceSize;
            }
            traffic.RecordTokenComplete();
        }
        profiler.EndTokenGeneration();
        traffic.EndEvaluation();

        RawPrint("\n--- RUN COMPLETE: ");
        RawPrint(label);
        RawPrint(" ---\n");
        
        auto snapshot = traffic.Snapshot();
        RawPrintInt("Tokens generated: ", snapshot.tokensGenerated);
        
        VirtualFree(outActivations, 0, MEM_RELEASE);
        VirtualFree(inActivations, 0, MEM_RELEASE);
        DeleteFileW(modelPath);

    } catch (...) {
        RawPrint("[-] Run failed.\n");
    }
}

void ExecuteUltimatePerformanceSweep() {
    RawPrint("============================================================\n");
    RawPrint("   SOVEREIGN_ASYNC_RING_E2E_001: COMPREHENSIVE SWEEP       \n");
    RawPrint("============================================================\n");

    ExecuteParameterizedSweep(RunConfig::Sync, "RUN A: SYNCHRONOUS CONTROL");
    ExecuteParameterizedSweep(RunConfig::IOCPOverlap, "RUN C: IOCP RING OVERLAP");

    RawPrint("\n[✔] Multi-stage sweep complete.\n");
}
