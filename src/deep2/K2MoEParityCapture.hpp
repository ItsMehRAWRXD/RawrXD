// K2MoEParityCapture.hpp — opt-in bounded Kimi expert parity evidence.
// Never called without explicit DEEP2_MOE_PARITY_CAPTURE_DIR and diagnostic parity enabled.
// Evidence only; no changes to inference outputs, device state, or admission.
#pragma once
#include <cstdint>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <string>
#include <system_error>
#include <vector>

namespace Deep2 {
namespace k2_parity_capture {

inline bool WriteNew(const std::filesystem::path& path, const void* ptr,
                     size_t bytes) {
    // Exclusive-create mode closes the exists()/fopen() race; never truncate
    // prior evidence. The evidence directory must also be private to this run.
    if (!ptr || !bytes || std::filesystem::exists(path)) return false;
    FILE* f = std::fopen(path.string().c_str(), "wbx");
    if (!f) return false;
    bool ok = std::fwrite(ptr, 1, bytes, f) == bytes;
    if (std::fflush(f) != 0) ok = false;
    if (std::fclose(f) != 0) ok = false;
    if (!ok) {
        // Always remove a partial output, never count it as evidence.
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
    return ok;
}

inline bool WriteVector(const std::filesystem::path& path, const float* data,
                        size_t count) {
    if (!data || !count || std::filesystem::exists(path)) return false;
    for (size_t i = 0; i < count; ++i)
        if (!std::isfinite(data[i])) return false;
    FILE* f = std::fopen(path.string().c_str(), "wbx");
    if (!f) return false;
    bool ok = true;
    for (size_t i = 0; i < count; ++i) {
        if (std::fprintf(f, "%.9g\n", static_cast<double>(data[i])) < 0) {
            ok = false;
            break;
        }
    }
    if (std::fflush(f) != 0) ok = false;
    if (std::fclose(f) != 0) ok = false;
    if (!ok) {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
    return ok;
}

inline bool Capture(unsigned stick, unsigned layer, int expert,
                    int ggmlType, const uint8_t* downBytes, size_t downLen,
                    const float* postSwiGlu, size_t intermediate,
                    const float* cpuDown, const float* gpuDown, size_t hidden) {
    const char* raw = std::getenv("DEEP2_MOE_PARITY_CAPTURE_DIR");
    if (!raw || !*raw || expert < 0 || !downBytes || !postSwiGlu ||
        !cpuDown || !gpuDown || !intermediate || !hidden ||
        ggmlType != 14 || intermediate % 256u ||
        intermediate > 1048576u || hidden > 1048576u)
        return false;
    const size_t expected = hidden * (intermediate / 256u) * 210u;
    if (downLen != expected) return false;
    std::filesystem::path dir(raw);
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) return false;
    // Run-local directory must preexist. Never create arbitrary directories.
    const std::string prefix = "k2_l" + std::to_string(layer) +
        "_e" + std::to_string(expert) + "_s" + std::to_string(stick);
    const auto manifest = dir / (prefix + ".manifest.txt");
    const auto packed = dir / (prefix + ".down_q6k.bin");
    const auto act = dir / (prefix + ".post_swiglu.txt");
    const auto cpu = dir / (prefix + ".cpu_down.txt");
    const auto gpu = dir / (prefix + ".gpu_down.txt");
    for (const auto& p : {manifest, packed, act, cpu, gpu})
        if (std::filesystem::exists(p, ec) || ec) return false;
    bool ok = WriteNew(packed, downBytes, downLen);
    if (ok) ok = WriteVector(act, postSwiGlu, intermediate);
    if (ok) ok = WriteVector(cpu, cpuDown, hidden);
    if (ok) ok = WriteVector(gpu, gpuDown, hidden);
    if (ok) {
        const std::string receipt =
            "schema=DEEP2_KIMI_MOE_EXPERT_CAPTURE_001\n"
            "layer=" + std::to_string(layer) + "\nexpert=" +
            std::to_string(expert) + "\nstick=" + std::to_string(stick) +
            "\nggml_type=14\nrows=" + std::to_string(hidden) +
            "\ncolumns=" + std::to_string(intermediate) +
            "\nweight_bytes=" + std::to_string(downLen) +
            "\nsource=GPU_EXPERT_PARITY_DIAGNOSTIC\n"
            "certified=0\n";
        ok = WriteNew(manifest, receipt.data(), receipt.size());
    }
    if (!ok) {
        // Cleanup only files created by this run (pre-existing files were
        // checked and would have caused an early return above).
        for (const auto& p : {manifest, packed, act, cpu, gpu})
            std::filesystem::remove(p, ec);
    }
    return ok;
}


/* Independent-oracle INPUT witness, not a GPU-output witness.
   Only captures a cold expert with host-accessible packed weights.
   Exclusive run-local directory is required; capture never certifies parity. */
inline bool CaptureScalarInputs(unsigned stick, unsigned layer, int expert,
                                int gt, const uint8_t* gate, size_t gateBytes,
                                int ut, const uint8_t* up, size_t upBytes,
                                int dt, const uint8_t* down, size_t downBytes,
                                const float* hidden, size_t H, size_t I) {
    const char* raw = std::getenv("DEEP2_MOE_PARITY_CAPTURE_DIR");
    if (!raw || !*raw || expert < 0 || !gate || !up || !down || !hidden ||
        gt != 12 || ut != 12 || dt != 14 || H == 0 || I == 0 ||
        H > 16384u || I > 16384u || H % 256u || I % 256u)
        return false;

    const size_t gateExpected = I * (H / 256u) * 144u;
    const size_t downExpected = H * (I / 256u) * 210u;
    if (gateBytes != gateExpected || upBytes != gateExpected ||
        downBytes != downExpected)
        return false;

    std::filesystem::path dir(raw);
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec) || ec) return false;
    const std::string stem = "k2_l" + std::to_string(layer) +
        "_e" + std::to_string(expert) + "_s" + std::to_string(stick) +
        "_scalar_inputs";
    const auto gatePath = dir / (stem + ".gate_q4k.bin");
    const auto upPath = dir / (stem + ".up_q4k.bin");
    const auto downPath = dir / (stem + ".down_q6k.bin");
    const auto hiddenPath = dir / (stem + ".hidden.txt");
    const auto manifestPath = dir / (stem + ".manifest.txt");
    for (const auto& path : {gatePath, upPath, downPath, hiddenPath, manifestPath}) {
        ec.clear();
        if (std::filesystem::exists(path, ec) || ec) return false;
    }

    std::vector<std::filesystem::path> created;
    auto saveBytes = [&](const std::filesystem::path& path,
                         const void* data, size_t count) {
        if (!WriteNew(path, data, count)) return false;
        created.push_back(path);
        return true;
    };
    auto saveVector = [&](const std::filesystem::path& path,
                          const float* values, size_t count) {
        if (!WriteVector(path, values, count)) return false;
        created.push_back(path);
        return true;
    };

    bool ok = saveBytes(gatePath, gate, gateBytes) &&
              saveBytes(upPath, up, upBytes) &&
              saveBytes(downPath, down, downBytes) &&
              saveVector(hiddenPath, hidden, H);
    if (ok) {
        const std::string receipt =
            "schema=DEEP2_KIMI_SCALAR_INPUTS_001\n"
            "layer=" + std::to_string(layer) +
            "\nexpert=" + std::to_string(expert) +
            "\nstick=" + std::to_string(stick) +
            "\nhidden_dim=" + std::to_string(H) +
            "\nintermediate_dim=" + std::to_string(I) +
            "\ngate_ggml_type=12\nup_ggml_type=12\ndown_ggml_type=14\n"
            "source=CPU_PACKED_SLICES_AND_NORMED_HIDDEN\n"
            "scope=SCALAR_INPUT_ONLY_NO_GPU_OUTPUT\ncertified=0\n";
        ok = saveBytes(manifestPath, receipt.data(), receipt.size());
    }
    if (!ok) {
        for (const auto& path : created) {
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }
    }
    return ok;
}


/* The completed fused stick aggregate and the independently recomputed
   CPU aggregate, not individual expert stage buffers. This is diagnostic
   evidence only: it cannot certify G05/G06 per-expert GPU parity. */
inline bool CaptureAggregateComparison(unsigned stick, unsigned layer,
                                       const float* gpu, const float* cpu,
                                       size_t hidden,
                                       const int* expertIds,
                                       const float* weights,
                                       size_t experts) {
    const char* raw = std::getenv("DEEP2_MOE_PARITY_CAPTURE_DIR");
    if (!raw || !*raw || !gpu || !cpu || !expertIds || !weights ||
        hidden == 0 || hidden > 16384u || experts == 0 || experts > 64u ||
        stick > 1u)
        return false;
    for (size_t i = 0; i < hidden; ++i)
        if (!std::isfinite(gpu[i]) || !std::isfinite(cpu[i])) return false;
    for (size_t i = 0; i < experts; ++i) {
        if (expertIds[i] < 0 || !std::isfinite(weights[i])) return false;
        for (size_t j = 0; j < i; ++j)
            if (expertIds[i] == expertIds[j]) return false;
    }
    std::filesystem::path dir(raw);
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec) || ec) return false;
    const std::string stem = "k2_l" + std::to_string(layer) +
        "_s" + std::to_string(stick) + "_aggregate_comparison";
    const auto gpuPath = dir / (stem + ".gpu.txt");
    const auto cpuPath = dir / (stem + ".cpu.txt");
    const auto receiptPath = dir / (stem + ".manifest.txt");
    for (const auto& path : {gpuPath, cpuPath, receiptPath}) {
        ec.clear();
        if (std::filesystem::exists(path, ec) || ec) return false;
    }
    if (!WriteVector(gpuPath, gpu, hidden)) return false;
    if (!WriteVector(cpuPath, cpu, hidden)) {
        std::filesystem::remove(gpuPath, ec);
        return false;
    }
    std::string manifest =
        "schema=DEEP2_KIMI_AGGREGATE_COMPARISON_001\n"
        "layer=" + std::to_string(layer) +
        "\nstick=" + std::to_string(stick) +
        "\nrows=" + std::to_string(hidden) +
        "\nexperts=" + std::to_string(experts) +
        "\nsource=POST_END_DEVICE_GPU_PARTIAL_AND_COMPLETE_CPU_REFERENCE\n"
        "scope=AGGREGATE_ONLY_NOT_PER_EXPERT_PARITY\n"
        "certified=0\n";
    for (size_t i = 0; i < experts; ++i) {
        manifest += "expert=" + std::to_string(expertIds[i]) +
            " weight=" + std::to_string(weights[i]) + "\n";
    }
    if (WriteNew(receiptPath, manifest.data(), manifest.size())) return true;
    // Only remove files created by this invocation.
    std::filesystem::remove(gpuPath, ec);
    std::filesystem::remove(cpuPath, ec);
    return false;
}

} // namespace k2_parity_capture
} // namespace Deep2
