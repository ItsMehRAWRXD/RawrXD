#pragma once
#include "RawrStreamerCompletion.hpp"
#include "RawrStreamerExtNames.hpp"
#include "ActualE2EGenerationLaw.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

inline void ActualE2E_WriteGate(const RawrCompletionReceipt& r,
                               const char* term, size_t textBytes) {
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\ACTUAL_E2E_GENERATION_001", nullptr);
#endif
    std::ofstream g(
        "G:\\~dev\\rawrxd\\evidence\\ACTUAL_E2E_GENERATION_001\\GATE_STATUS.txt");
    const bool pass = RawrIsProductionCompletion(r) && RawrHasCleanTeardown(r) &&
                      RawrRunsCorrectly(r);
    g << "ACTUAL_E2E_GENERATION_001=" << (pass ? "PASS" : "OPEN") << "\n";
    g << "TERMINAL=" << term << "\n";
    g << "EXECUTION_SCOPE=" << RawrExecutionScopeName(r.execution_scope) << "\n";
    g << "TERMINATION_CLASS="
      << RawrTerminationClassName(r.termination_class) << "\n";
    g << "PRODUCTION_DECODE_PATH=" << r.production_decode_path << "\n";
    g << "MODEL_OUTPUT_PRODUCED=" << r.model_output_produced << "\n";
    g << "GENERATED_TOKENS=" << r.generated_tokens << "\n";
    g << "DETOKENIZED_TEXT_BYTES=" << textBytes << "\n";
    g << "TEARDOWN_WITNESS=" << r.teardown_witness << "\n";
    g << "CPU_F32_EXPANDS=" << r.cpu_f32_expands << "\n";
    g << "HOST_FORWARD_LAYER_CALLS=" << r.host_forward_layer_calls << "\n";
    g << "WALL_NS=" << r.wall_ns << "\n";
    g << "WALL_WITHIN_BUDGET=0\nPRODUCT_E2E=OPEN\n";
    g << "LAW=ACTUAL_E2E_GENERATION_ONLY\n";
}

inline void ActualE2E_Emit(const RawrCompletionReceipt& r, const char* term,
                           size_t textBytes, bool pass) {
    std::printf("ACTUAL_E2E_GENERATION_BEGIN=1\n");
    std::printf("PRODUCTION_DECODE_PATH=%u MODEL_OUTPUT_PRODUCED=%u "
                "GENERATED_TOKENS=%llu\n",
                r.production_decode_path, r.model_output_produced,
                (unsigned long long)r.generated_tokens);
    std::printf("DETOKENIZED_TEXT_BYTES=%zu\n", textBytes);
    std::printf("TERMINATION_CLASS=%s TEARDOWN_WITNESS=%u\n",
                RawrTerminationClassName(r.termination_class),
                r.teardown_witness);
    std::printf("TERMINAL=%s STREAM_COMPLETE=%u\n", term, pass ? 1u : 0u);
    std::printf("WALL_WITHIN_BUDGET=0\nRAWRXD_PRODUCT_E2E_001=OPEN\n");
    std::printf("ACTUAL_E2E_GENERATION_001=%s\n", pass ? "PASS" : "OPEN");
}
