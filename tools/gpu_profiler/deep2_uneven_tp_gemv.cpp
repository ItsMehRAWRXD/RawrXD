#include "vulkan_compute.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <memory>
#include <string>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

uint64_t nowNs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now().time_since_epoch()).count());
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

struct Device {
    Deep2::VulkanPhysicalInfo info;
    std::unique_ptr<Deep2::VulkanCompute> gpu;
};

struct Shard {
    uint32_t begin = 0;
    uint32_t cols = 0;
    uint64_t weightKey = 0;
    std::vector<float> weights;
    std::vector<float> input;
    std::vector<float> output;
};

struct DispatchSample {
    uint64_t wallNs = 0;
    uint64_t queueSubmitNs = 0;
    uint64_t fenceWaitNs = 0;
    uint64_t gpuNs = 0;
    bool calibrated = false;
    bool ok = false;
};

struct CaseResult {
    uint32_t globalCols = 0;
    std::vector<uint64_t> pairWallNs;
    std::vector<DispatchSample> perDevice[2];
    double cpuMaxAbsError = 0.0;
    double gpuMaxAbsError = 0.0;
    bool cpuParity = false;
    bool gpuParity = false;
};

uint64_t median(std::vector<uint64_t> values) {
    if (values.empty()) return 0;
    const size_t middle = values.size() / 2;
    std::nth_element(values.begin(), values.begin() + middle, values.end());
    return values[middle];
}

uint64_t minimum(const std::vector<uint64_t>& values) {
    return values.empty() ? 0 : *std::min_element(values.begin(), values.end());
}

uint64_t maximum(const std::vector<uint64_t>& values) {
    return values.empty() ? 0 : *std::max_element(values.begin(), values.end());
}

double maxAbsError(const std::vector<float>& a, const std::vector<float>& b) {
    if (a.size() != b.size()) return INFINITY;
    double result = 0.0;
    for (size_t i = 0; i < a.size(); ++i)
        result = std::max(result, std::abs(static_cast<double>(a[i]) - b[i]));
    return result;
}

bool ensureArena(Device& d, uint32_t width) {
    return d.gpu->EnsureForwardArena(width, width, 1, 1, 1, 1, 1, 1);
}

DispatchSample dispatch(Device& d, Shard& shard, uint32_t rows) {
    DispatchSample result{};
    auto& input = d.gpu->ArenaNormed();
    auto& output = d.gpu->ArenaResidual();
    const uint64_t begin = nowNs();
    result.ok = d.gpu->DispatchGemvDevice(
        shard.weights.data(), shard.weightKey, input, output, rows, shard.cols);
    const uint64_t end = nowNs();
    result.wallNs = end - begin;
    if (!result.ok) return result;

    const Deep2::GpuWorkInterval interval = d.gpu->LastInterval();
    result.queueSubmitNs = interval.queueSubmitCallNs;
    result.fenceWaitNs = interval.fenceWaitWallNs;
    result.gpuNs = interval.calibratedDurationNs();
    result.calibrated = interval.calibrated;
    return result;
}

bool uploadInput(Device& d, const std::vector<float>& input) {
    return d.gpu->UploadVector(d.gpu->ArenaNormed(), input.data(), input.size());
}

std::vector<float> makeWeights(uint32_t rows, uint32_t cols) {
    std::vector<float> weights(static_cast<size_t>(rows) * cols);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; ++c) {
            const int value = static_cast<int>((r * 131u + c * 197u + 17u) % 2003u) - 1001;
            weights[static_cast<size_t>(r) * cols + c] = static_cast<float>(value) / 131072.0f;
        }
    }
    return weights;
}

std::vector<float> makeInput(uint32_t cols) {
    std::vector<float> input(cols);
    for (uint32_t c = 0; c < cols; ++c) {
        const int value = static_cast<int>((c * 313u + 29u) % 1009u) - 504;
        input[c] = static_cast<float>(value) / 2048.0f;
    }
    return input;
}

std::vector<float> cpuGemv(const std::vector<float>& weights,
                           const std::vector<float>& input,
                           uint32_t rows, uint32_t cols) {
    std::vector<float> output(rows, 0.0f);
    for (uint32_t r = 0; r < rows; ++r) {
        double sum = 0.0;
        const size_t offset = static_cast<size_t>(r) * cols;
        for (uint32_t c = 0; c < cols; ++c)
            sum += static_cast<double>(weights[offset + c]) * input[c];
        output[r] = static_cast<float>(sum);
    }
    return output;
}

bool findTargetDevices(Device& r9700, Device& rx7800) {
    const auto physical = Deep2::VulkanCompute::EnumeratePhysicalDevices();
    bool haveR9700 = false;
    bool haveRx7800 = false;
    for (const auto& info : physical) {
        const std::string name = lower(info.name);
        if (!haveR9700 && name.find("radeon ai pro r9700") != std::string::npos) {
            r9700.info = info;
            haveR9700 = true;
        } else if (!haveRx7800 && name.find("radeon rx 7800 xt") != std::string::npos) {
            rx7800.info = info;
            haveRx7800 = true;
        }
    }
    if (!haveR9700 || !haveRx7800) {
        std::fprintf(stderr,
            "TARGET_DEVICES_MISSING R9700=%u RX7800XT=%u; refusing ordinal substitution\n",
            haveR9700 ? 1u : 0u, haveRx7800 ? 1u : 0u);
        return false;
    }

    r9700.gpu = std::make_unique<Deep2::VulkanCompute>(r9700.info.ordinal);
    rx7800.gpu = std::make_unique<Deep2::VulkanCompute>(rx7800.info.ordinal);
    if (!r9700.gpu->initialize() || !rx7800.gpu->initialize()) {
        std::fprintf(stderr, "TARGET_DEVICE_INITIALIZATION_FAILED\n");
        return false;
    }
    return true;
}

bool runCase(Device& devices0, Device& devices1, uint32_t rows,
             uint32_t globalCols, uint32_t repetitions, CaseResult& result) {
    result = {};
    result.globalCols = globalCols;

    const std::vector<float> fullWeights = makeWeights(rows, globalCols);
    const std::vector<float> fullInput = makeInput(globalCols);
    const std::vector<float> cpuReference = cpuGemv(fullWeights, fullInput, rows, globalCols);

    Shard shards[2];
    for (uint32_t rank = 0; rank < 2; ++rank) {
        Shard& shard = shards[rank];
        shard.begin = rank == 0 ? 0u : (globalCols + 1u) / 2u;
        const uint32_t end = rank == 0 ? (globalCols + 1u) / 2u : globalCols;
        shard.cols = end - shard.begin;
        shard.weightKey = 0x554e4556454e0000ull ^
            (static_cast<uint64_t>(globalCols) << 16) ^
            (static_cast<uint64_t>(rank) << 8) ^ rows;
        shard.input.assign(fullInput.begin() + shard.begin, fullInput.begin() + end);
        shard.output.resize(rows);
        shard.weights.resize(static_cast<size_t>(rows) * shard.cols);
        for (uint32_t r = 0; r < rows; ++r) {
            const size_t src = static_cast<size_t>(r) * globalCols + shard.begin;
            const size_t dst = static_cast<size_t>(r) * shard.cols;
            std::copy_n(fullWeights.begin() + src, shard.cols, shard.weights.begin() + dst);
        }
    }

    Device* devices[2] = {&devices0, &devices1};
    for (unsigned rank = 0; rank < 2; ++rank) {
        const uint32_t width = std::max(rows, shards[rank].cols);
        if (!ensureArena(*devices[rank], width) || !uploadInput(*devices[rank], shards[rank].input)) {
            std::fprintf(stderr, "ARENA_OR_INPUT_UPLOAD_FAILED rank=%u width=%u\n", rank, width);
            return false;
        }
        devices[rank]->gpu->SetWorkEpoch(globalCols);
    }

    // Warm the pipelines and weight caches before collecting timing samples.
    for (unsigned warm = 0; warm < 3; ++warm) {
        auto a = std::async(std::launch::async, [&] { return dispatch(*devices[0], shards[0], rows); });
        auto b = std::async(std::launch::async, [&] { return dispatch(*devices[1], shards[1], rows); });
        const DispatchSample sa = a.get();
        const DispatchSample sb = b.get();
        if (!sa.ok || !sb.ok) {
            std::fprintf(stderr, "WARMUP_DISPATCH_FAILED cols=%u\n", globalCols);
            return false;
        }
    }

    for (uint32_t iteration = 0; iteration < repetitions; ++iteration) {
        const uint64_t pairStart = nowNs();
        auto a = std::async(std::launch::async, [&] { return dispatch(*devices[0], shards[0], rows); });
        auto b = std::async(std::launch::async, [&] { return dispatch(*devices[1], shards[1], rows); });
        DispatchSample sa = a.get();
        DispatchSample sb = b.get();
        const uint64_t pairEnd = nowNs();
        if (!sa.ok || !sb.ok) {
            std::fprintf(stderr, "MEASURED_DISPATCH_FAILED cols=%u iteration=%u\n", globalCols, iteration);
            return false;
        }
        result.pairWallNs.push_back(pairEnd - pairStart);
        result.perDevice[0].push_back(sa);
        result.perDevice[1].push_back(sb);
    }

    std::vector<float> partial[2];
    for (unsigned rank = 0; rank < 2; ++rank) {
        partial[rank].resize(rows);
        if (!devices[rank]->gpu->DownloadVector(devices[rank]->gpu->ArenaResidual(),
                                                partial[rank].data(), rows)) {
            std::fprintf(stderr, "OUTPUT_DOWNLOAD_FAILED rank=%u\n", rank);
            return false;
        }
    }
    std::vector<float> sharded(rows);
    for (uint32_t row = 0; row < rows; ++row)
        sharded[row] = partial[0][row] + partial[1][row];

    result.cpuMaxAbsError = maxAbsError(sharded, cpuReference);
    const double cpuScale = std::max(1.0, maxAbsError(cpuReference, std::vector<float>(rows, 0.0f)));
    result.cpuParity = result.cpuMaxAbsError <= 2e-4 + 2e-3 * cpuScale;

    // A full-width GPU reference verifies the simulated gather/reduction path
    // against the same production Vulkan GEMV kernel on one device.
    if (!ensureArena(devices0, std::max(rows, globalCols)) || !uploadInput(devices0, fullInput)) {
        std::fprintf(stderr, "REFERENCE_ARENA_OR_UPLOAD_FAILED cols=%u\n", globalCols);
        return false;
    }
    Shard full{};
    full.cols = globalCols;
    full.weightKey = 0x5245464552454e43ull ^
        (static_cast<uint64_t>(globalCols) << 16) ^ rows;
    full.weights = fullWeights;
    if (!dispatch(devices0, full, rows).ok) {
        std::fprintf(stderr, "SINGLE_GPU_REFERENCE_DISPATCH_FAILED cols=%u\n", globalCols);
        return false;
    }
    std::vector<float> gpuReference(rows);
    if (!devices0.gpu->DownloadVector(devices0.gpu->ArenaResidual(), gpuReference.data(), rows)) {
        std::fprintf(stderr, "SINGLE_GPU_REFERENCE_DOWNLOAD_FAILED cols=%u\n", globalCols);
        return false;
    }
    result.gpuMaxAbsError = maxAbsError(sharded, gpuReference);
    const double gpuScale = std::max(1.0, maxAbsError(gpuReference, std::vector<float>(rows, 0.0f)));
    result.gpuParity = result.gpuMaxAbsError <= 2e-4 + 2e-3 * gpuScale;
    return true;
}

void emitCase(const CaseResult& result, const Device& r9700, const Device& rx7800,
              uint32_t rows, uint32_t repetitions, uint32_t caseIndex) {
    std::printf("CASE_INDEX=%u\n", caseIndex);
    std::printf("CASE_GLOBAL_COLS=%u\n", result.globalCols);
    std::printf("CASE_ROWS=%u\n", rows);
    std::printf("CASE_REPETITIONS=%u\n", repetitions);
    std::printf("SHARD0_BEGIN=0\nSHARD0_COLS=%u\n", (result.globalCols + 1u) / 2u);
    std::printf("SHARD1_BEGIN=%u\nSHARD1_COLS=%u\n",
                (result.globalCols + 1u) / 2u, result.globalCols / 2u);
    const Device* devices[2] = {&r9700, &rx7800};
    for (unsigned rank = 0; rank < 2; ++rank) {
        std::vector<uint64_t> wall, submit, fence, gpu;
        bool calibrated = true;
        for (const auto& sample : result.perDevice[rank]) {
            wall.push_back(sample.wallNs);
            submit.push_back(sample.queueSubmitNs);
            fence.push_back(sample.fenceWaitNs);
            if (sample.calibrated) gpu.push_back(sample.gpuNs);
            else calibrated = false;
        }
        std::printf("DEVICE%u_NAME=\"%s\"\n", rank, devices[rank]->info.name.c_str());
        std::printf("DEVICE%u_LOCAL_HEAP_BYTES=%llu\n", rank,
                    static_cast<unsigned long long>(devices[rank]->info.deviceLocalBytes));
        std::printf("DEVICE%u_UUID=", rank);
        for (uint8_t byte : devices[rank]->info.deviceUUID) std::printf("%02x", byte);
        std::printf("\nDEVICE%u_HOST_DISPATCH_MEDIAN_NS=%llu\n", rank,
                    static_cast<unsigned long long>(median(wall)));
        std::printf("DEVICE%u_HOST_DISPATCH_MIN_NS=%llu\n", rank,
                    static_cast<unsigned long long>(minimum(wall)));
        std::printf("DEVICE%u_HOST_DISPATCH_MAX_NS=%llu\n", rank,
                    static_cast<unsigned long long>(maximum(wall)));
        std::printf("DEVICE%u_QUEUE_SUBMIT_CALL_MEDIAN_NS=%llu\n", rank,
                    static_cast<unsigned long long>(median(submit)));
        std::printf("DEVICE%u_FENCE_WAIT_WALL_MEDIAN_NS=%llu\n", rank,
                    static_cast<unsigned long long>(median(fence)));
        std::printf("DEVICE%u_GPU_EXEC_MEDIAN_NS=%llu\n", rank,
                    static_cast<unsigned long long>(median(gpu)));
        std::printf("DEVICE%u_GPU_EXEC_MIN_NS=%llu\n", rank,
                    static_cast<unsigned long long>(minimum(gpu)));
        std::printf("DEVICE%u_GPU_EXEC_MAX_NS=%llu\n", rank,
                    static_cast<unsigned long long>(maximum(gpu)));
        std::printf("DEVICE%u_GPU_TIMESTAMPS_CALIBRATED=%u\n", rank, calibrated ? 1u : 0u);
        const uint32_t shardCols = rank == 0 ? (result.globalCols + 1u) / 2u : result.globalCols / 2u;
        std::printf("DEVICE%u_WEIGHT_BYTES=%llu\n", rank,
                    static_cast<unsigned long long>(static_cast<uint64_t>(rows) * shardCols * sizeof(float)));
        std::printf("DEVICE%u_INPUT_BYTES=%llu\n", rank,
                    static_cast<unsigned long long>(static_cast<uint64_t>(shardCols) * sizeof(float)));
        std::printf("DEVICE%u_OUTPUT_BYTES=%llu\n", rank,
                    static_cast<unsigned long long>(static_cast<uint64_t>(rows) * sizeof(float)));
    }
    std::printf("PAIR_WALL_MEDIAN_NS=%llu\n",
                static_cast<unsigned long long>(median(result.pairWallNs)));
    std::printf("HOST_REDUCTION=FLOAT_SUM\n");
    std::printf("CROSS_DEVICE_TRANSFER_PATH=HOST_STAGED\n");
    std::printf("DEVICE_ALLOCATOR_HIGH_WATER=NOT_INSTRUMENTED\n");
    std::printf("CPU_REFERENCE_MAX_ABS_ERROR=%.9g\n", result.cpuMaxAbsError);
    std::printf("SINGLE_GPU_REFERENCE_MAX_ABS_ERROR=%.9g\n", result.gpuMaxAbsError);
    std::printf("CPU_PARITY=%s\n", result.cpuParity ? "PASS" : "FAIL");
    std::printf("SINGLE_GPU_PARITY=%s\n", result.gpuParity ? "PASS" : "FAIL");
    std::printf("CERTIFICATION=MICROBENCH_ONLY\n\n");
}

} // namespace

int main(int argc, char** argv) {
    uint32_t rows = 1024;
    uint32_t repetitions = 15;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--rows" && i + 1 < argc)
            rows = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        else if (std::string(argv[i]) == "--reps" && i + 1 < argc)
            repetitions = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        else {
            std::fprintf(stderr, "usage: %s [--rows 64..2048] [--reps 3..100]\n", argv[0]);
            return 2;
        }
    }
    if (rows < 64 || rows > 2048 || repetitions < 3 || repetitions > 100) {
        std::fprintf(stderr, "rows/reps outside supported benchmark bounds\n");
        return 2;
    }

    Device r9700, rx7800;
    if (!findTargetDevices(r9700, rx7800)) return 3;
    std::printf("BENCHMARK=DEEP2_UNEVEN_TP_GEMV_V2\n");
    std::printf("BACKEND=VULKAN\nDEVICE_COUNT=2\nROWS=%u\nREPETITIONS=%u\n", rows, repetitions);
    std::printf("TIMING_NOTE=FENCE_WAIT_OVERLAPS_GPU_EXECUTION; DO_NOT_SUM_TIMINGS\n\n");

    const uint32_t shapes[] = {4096u, 4097u, 4098u, 4104u, 4096u};
    for (uint32_t caseIndex = 0; caseIndex < 5; ++caseIndex) {
        CaseResult result{};
        const uint32_t cols = shapes[caseIndex];
        if (!runCase(r9700, rx7800, rows, cols, repetitions, result)) return 4;
        emitCase(result, r9700, rx7800, rows, repetitions, caseIndex);
        if (!result.cpuParity || !result.gpuParity) return 5;
    }
    std::printf("OVERALL=PASS_MICROBENCH\nGATE_10=OPEN\n");
    return 0;
}
