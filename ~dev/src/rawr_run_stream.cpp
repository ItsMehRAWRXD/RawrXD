// ============================================================================
// rawr_run_stream.cpp — RAWR_RUN_STREAM_001
// Thin vertical adapter: `rawr run <alias> '<request>'` -> Deep2 Vulkan path.
//
// Lifted verbatim from the proven invocation sequence in
// tests/qwen32_40tps_gate.cpp + tests/deep2_standalone.cpp. No alternate
// tokenizer. No alternate Vulkan setup. No second scheduler. No CPU demo
// fallback. The product command uses the same execution path as the
// benchmark harness.
// ============================================================================

#include "rawr_run_stream.hpp"

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

// Strict-GPU violation counter owned by the embedding binary.
// Deep2Engine_Speculative.cpp increments this whenever a strict no-CPU-
// fallback constraint is violated; the gate executables define the same
// symbol. The product binary owns it now.
std::atomic<uint32_t> g_strictGpuViolations{0};

namespace rawrxd {
namespace runstream {

using Deep2::Deep2Engine;
using Deep2::EngineConfig;
using Deep2::GenerationOptions;
using Deep2::GenerationResult;

namespace {

const char* deviceName(DevicePolicy policy) {
    switch (policy) {
    case DevicePolicy::Gpu: return "gpu";
    case DevicePolicy::Cpu: return "cpu";
    case DevicePolicy::Auto: return "auto";
    }
    return "unknown";
}

std::string jsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (unsigned char c : value) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                char buf[7]{};
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out.push_back(static_cast<char>(c));
            }
        }
    }
    return out;
}

bool writeJsonReceipt(const std::string& path, const RunStreamReceipt& r) {
    if (path.empty()) return true;
    std::error_code ec;
    const std::filesystem::path receiptPath(path);
    if (!receiptPath.parent_path().empty())
        std::filesystem::create_directories(receiptPath.parent_path(), ec);
    if (ec) return false;
    std::ofstream out(receiptPath, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << "{\n"
        << "  \"schema\": \"RAWR_RUN_STREAM_003\",\n"
        << "  \"status\": \"" << jsonEscape(r.status) << "\",\n"
        << "  \"exit_code\": " << r.exitCode << ",\n"
        << "  \"model_resolved\": " << (r.modelResolved ? "true" : "false") << ",\n"
        << "  \"model_path\": \"" << jsonEscape(r.modelPath) << "\",\n"
        << "  \"engine_initialized\": " << (r.engineInitialized ? "true" : "false") << ",\n"
        << "  \"model_loaded\": " << (r.modelLoaded ? "true" : "false") << ",\n"
        << "  \"device\": \"" << jsonEscape(r.device) << "\",\n"
        << "  \"vulkan_inference\": " << (r.vulkanInference ? "true" : "false") << ",\n"
        << "  \"model_fallback\": " << (r.modelFallback ? "true" : "false") << ",\n"
        << "  \"context_admitted\": " << (r.contextAdmitted ? "true" : "false") << ",\n"
        << "  \"context_limit\": " << r.contextLimit << ",\n"
        << "  \"prompt_tokens\": " << r.promptTokens << ",\n"
        << "  \"generated_tokens\": " << r.generatedTokens << ",\n"
        << "  \"eos_reached\": " << (r.eosReached ? "true" : "false") << ",\n"
        << "  \"eos_token\": " << r.eosToken << ",\n"
        << "  \"stream_callback_used\": " << (r.streamCallbackUsed ? "true" : "false") << ",\n"
        << "  \"generation_ms\": " << r.generationMs << ",\n"
        << "  \"decode_tps\": " << r.decodeTps << ",\n"
        << "  \"unplanned_fallbacks\": " << r.unplannedFallbacks << ",\n"
        << "  \"strict_violation\": " << (r.strictViolation ? "true" : "false") << ",\n"
        << "  \"dual_row_dispatches\": " << r.dualRowDispatches << ",\n"
        << "  \"dual_row_slot_0\": " << r.dualRowSlot0 << ",\n"
        << "  \"dual_row_slot_1\": " << r.dualRowSlot1 << ",\n"
        << "  \"gpu_forward_layers\": " << r.gpuForwardLayers << ",\n"
        << "  \"dual_physical_gpu\": " << (r.dualPhysicalGpu ? "true" : "false") << ",\n"
        << "  \"timestamp_valid_slot_0\": " << (r.timestampValid0 ? "true" : "false") << ",\n"
        << "  \"timestamp_valid_slot_1\": " << (r.timestampValid1 ? "true" : "false") << ",\n"
        << "  \"gpu_kernel_ns_slot_0\": " << r.gpuKernelNs0 << ",\n"
        << "  \"gpu_kernel_ns_slot_1\": " << r.gpuKernelNs1 << ",\n"
        << "  \"queue_submits_slot_0\": " << r.queueSubmits0 << ",\n"
        << "  \"queue_submits_slot_1\": " << r.queueSubmits1 << ",\n"
        << "  \"weight_uploads_slot_0\": " << r.weightUploads0 << ",\n"
        << "  \"weight_uploads_slot_1\": " << r.weightUploads1 << ",\n"
        << "  \"weight_hits_slot_0\": " << r.weightHits0 << ",\n"
        << "  \"weight_hits_slot_1\": " << r.weightHits1 << ",\n"
        << "  \"submit_cpu_ns_slot_0\": " << r.submit_cpu_ns0 << ",\n"
        << "  \"submit_cpu_ns_slot_1\": " << r.submit_cpu_ns1 << ",\n"
        << "  \"wait_ns_slot_0\": " << r.wait_ns0 << ",\n"
        << "  \"wait_ns_slot_1\": " << r.wait_ns1 << ",\n"
        << "  \"error\": \"" << jsonEscape(r.error) << "\"\n"
        << "}\n";
    return static_cast<bool>(out);
}

static void populateGpuTelemetry(const Deep2Engine& engine,
                                 RunStreamReceipt& receipt) {
    const auto& counters = engine.gpuForwardCounters();
    receipt.dualRowDispatches = counters.dualRowSplitOps;
    receipt.dualRowSlot0 = counters.dualRowSlot[0];
    receipt.dualRowSlot1 = counters.dualRowSlot[1];
    receipt.gpuForwardLayers = counters.forwardLayers;
    receipt.dualPhysicalGpu = Deep2::Deep2GpuForward_DualPhysicalGpuReal(counters);
    if (const auto* slot0 = engine.getVulkanComputeSlot(0)) {
        receipt.timestampValid0 = slot0->calibratedTimestampsAvailable();
        receipt.gpuKernelNs0 = slot0->DenseRowGpuNs();
        receipt.queueSubmits0 = slot0->QueueSubmitCount();
        receipt.weightUploads0 = slot0->WeightUploadCount();
        receipt.weightHits0 = slot0->WeightHitCount();
        receipt.submit_cpu_ns0 = slot0->QueueSubmitCpuNs();
        receipt.wait_ns0 = slot0->QueueWaitNs();
    }
    if (const auto* slot1 = engine.getVulkanComputeSlot(1)) {
        receipt.timestampValid1 = slot1->calibratedTimestampsAvailable();
        receipt.gpuKernelNs1 = slot1->DenseRowGpuNs();
        receipt.queueSubmits1 = slot1->QueueSubmitCount();
        receipt.weightUploads1 = slot1->WeightUploadCount();
        receipt.weightHits1 = slot1->WeightHitCount();
        receipt.submit_cpu_ns1 = slot1->QueueSubmitCpuNs();
        receipt.wait_ns1 = slot1->QueueWaitNs();
    }
}

} // namespace

// ---------------------------------------------------------------------------
// RawrDeep2Runner — cold load, warm run. Class declared in the header.
// ---------------------------------------------------------------------------

bool RawrDeep2Runner::load(const std::string& modelPath,
                           RunStreamReceipt& receipt) {
    RunStreamOptions options;
    return load(modelPath, options, receipt);
}

bool RawrDeep2Runner::load(const std::string& modelPath,
                           const RunStreamOptions& options,
                           RunStreamReceipt& receipt) {
    receipt.modelPath = modelPath;
    receipt.device = deviceName(options.device);
    EngineConfig cfg{};
    cfg.maxSeqLen = options.contextTokens != 0 ? options.contextTokens : 4096;
    cfg.numThreads = 0;

    if (!engine_.initialize(cfg)) {
        std::fprintf(stderr, "[RAWR_RUN_STREAM_001] stage=initialize FAIL\n");
        receipt.error = "engine initialization failed";
        receipt.engineInitialized = false;
        return false;
    }
    receipt.engineInitialized = true;
    receipt.vulkanInference = false;

    if (!engine_.loadModel(modelPath)) {
        std::fprintf(stderr, "[RAWR_RUN_STREAM_001] stage=load FAIL path=%s\n",
                     modelPath.c_str());
        receipt.error = "model load failed";
        return false;
    }
    receipt.modelLoaded = true;
    loadedModel_ = modelPath;

    receipt.contextLimit = engine_.getConfig().maxSeqLen;

    if (options.device == DevicePolicy::Cpu) {
        engine_.setVulkanStrictNoCpuFallback(false);
        engine_.enableVulkan(false);
        receipt.device = "cpu";
        return true;
    }

    engine_.setVulkanStrictNoCpuFallback(options.device == DevicePolicy::Gpu);
    engine_.enableVulkan(true);
    if (!engine_.isVulkanInitialized() || !engine_.gpuResidentDecodeEnabled()) {
        if (options.device == DevicePolicy::Auto) {
            engine_.setVulkanStrictNoCpuFallback(false);
            engine_.enableVulkan(false);
            receipt.device = "cpu";
            receipt.modelFallback = true;
            std::fprintf(stderr,
                         "[RAWR_RUN_STREAM_001] stage=vulkan FALLBACK=cpu devices=%u\n",
                         engine_.vulkanDeviceCount());
            return true;
        }
        std::fprintf(stderr,
                     "[RAWR_RUN_STREAM_001] stage=vulkan FAIL devices=%u\n",
                     engine_.vulkanDeviceCount());
        receipt.error = "requested GPU is unavailable or failed initialization";
        return false;
    }
    receipt.vulkanInference = true;
    receipt.device = "gpu";
    return true;
}

bool RawrDeep2Runner::run(std::string_view prompt, uint32_t maxTokens,
                           const std::function<void(std::string_view)>& onToken,
                           RunStreamReceipt& receipt) {
    RunStreamOptions options;
    options.maxTokens = maxTokens;
    return run(prompt, options, onToken, receipt);
}

bool RawrDeep2Runner::run(std::string_view prompt,
                          const RunStreamOptions& options,
                          const std::function<void(std::string_view)>& onToken,
                          RunStreamReceipt& receipt) {
    receipt.error.clear();
    receipt.contextAdmitted = false;
    receipt.eosReached = false;
    receipt.eosToken = -1;
    reset();
    const std::vector<int> promptTokens = engine_.tokenize(std::string(prompt));
    receipt.promptTokens = promptTokens.size();
    receipt.contextLimit = engine_.getConfig().maxSeqLen;
    if (promptTokens.empty()) {
        receipt.error = "prompt tokenization produced no tokens";
        return false;
    }
    if (receipt.contextLimit == 0 || promptTokens.size() >= receipt.contextLimit) {
        receipt.error = "prompt does not fit admitted context";
        return false;
    }
    if (options.maxTokens == 0 ||
        options.maxTokens > receipt.contextLimit - promptTokens.size()) {
        receipt.error = "requested generation exceeds admitted context";
        return false;
    }
    receipt.contextAdmitted = true;

    GenerationOptions opts{};
    opts.maxTokens = options.maxTokens;
    opts.temperature = 0.0f;
    opts.topK = 1;
    opts.topP = 1.0f;
    opts.repeatPenalty = 1.0f;
    opts.seed = 1;

    bool streamed = false;
    GenerationResult result{};
    try {
        result = engine_.generateStream(
            std::string(prompt), opts,
            [&](int32_t, const std::string& piece) -> bool {
                streamed = true;
                if (onToken) {
                    onToken(std::string_view(piece));
                }
                return true;
            });
    } catch (const std::exception& ex) {
        receipt.error = ex.what();
        receipt.generatedTokens = 0;
        receipt.generationMs = 0.0;
        receipt.decodeTps = 0.0;
        receipt.streamCallbackUsed = streamed;
        receipt.unplannedFallbacks = engine_.vulkanUnplannedFallbacks();
        receipt.strictViolation = engine_.vulkanStrictViolation();
        populateGpuTelemetry(engine_, receipt);
        return false;
    }

    receipt.generatedTokens = result.generatedTokens;
    receipt.promptTokens = result.promptTokens;
    receipt.generationMs = result.generationTimeMs;
    receipt.decodeTps =
        result.generationTimeMs > 0.0
            ? static_cast<double>(result.generatedTokens) /
                  (result.generationTimeMs * 0.001)
            : 0.0;
    receipt.streamCallbackUsed = streamed;
    receipt.eosReached = result.eosReached;
    receipt.eosToken = result.eosToken;
    receipt.unplannedFallbacks = engine_.vulkanUnplannedFallbacks();
    receipt.strictViolation = engine_.vulkanStrictViolation();
    populateGpuTelemetry(engine_, receipt);
    if (receipt.generatedTokens == 0 && receipt.error.empty()) {
        receipt.error = result.cancelled
            ? "generation cancelled before a token was emitted"
            : "generation produced no tokens; inspect engine diagnostics";
    }
    return result.generatedTokens > 0;
}

// ---------------------------------------------------------------------------
// Persistent runner (RAWR_RUN_PERSISTENT_ENGINE_001 hook).
// The engine stays alive across requests: warm tokenizer, warm Vulkan
// pipelines, resident weights. Shared by run_rawr_run() and the agent loop
// (rawr_agent.cpp) so both surfaces drive one Deep2Engine.
// ---------------------------------------------------------------------------
static std::unique_ptr<RawrDeep2Runner> g_runner;
static std::string g_loadedModel;
static DevicePolicy g_loadedDevice = DevicePolicy::Gpu;
static uint32_t g_loadedContext = 0;

static void emitReceipt(const RunStreamReceipt& r) {
    std::fprintf(stderr,
                 "RAWR_RUN_STREAM_001_RECEIPT\n"
                 "MODEL_RESOLVED=%d\n"
                 "DEEP2_ENGINE=%d\n"
                 "VULKAN_INFERENCE=%d\n"
                 "CPU_DEMO_ENGINE=%d\n"
                 "MODEL_FALLBACK=%d\n"
                 "DEVICE=%s\n"
                 "CONTEXT_ADMITTED=%d\n"
                 "CONTEXT_LIMIT=%llu\n"
                 "STREAM_CALLBACK=%d\n"
                 "PROMPT_TOKENS=%llu\n"
                 "GENERATED_TOKENS=%llu\n"
                 "GENERATION_MS=%.3f\n"
                 "DECODE_TPS=%.3f\n"
                 "UNPLANNED_FALLBACKS=%llu\n"
                 "STRICT_GPU_VIOLATIONS=%d\n"
                 "GEN_EXIT=%d\n"
                 "RAWR_RUN_STREAM_001=%s\n",
                 r.modelResolved ? 1 : 0,
                 r.engineInitialized ? 1 : 0,
                 r.vulkanInference ? 1 : 0,
                 r.cpuDemoEngine ? 1 : 0,
                 r.modelFallback ? 1 : 0,
                 r.device.c_str(),
                 r.contextAdmitted ? 1 : 0,
                 static_cast<unsigned long long>(r.contextLimit),
                 r.streamCallbackUsed ? 1 : 0,
                 static_cast<unsigned long long>(r.promptTokens),
                 static_cast<unsigned long long>(r.generatedTokens),
                 r.generationMs,
                 r.decodeTps,
                 static_cast<unsigned long long>(r.unplannedFallbacks),
                 r.strictViolation ? 1 : 0,
                 r.exitCode,
                 r.status.c_str());
    if (!r.error.empty())
        std::fprintf(stderr, "ERROR=%s\n", r.error.c_str());
    std::fflush(stderr);
}

// Acquire the persistent shared runner, loading the model on first use or on
// model switch. Returns nullptr when load fails.
RawrDeep2Runner* acquireSharedRunner(const std::string& modelPath,
                                      RunStreamReceipt& receipt) {
    RunStreamOptions options;
    return acquireSharedRunner(modelPath, options, receipt);
}

RawrDeep2Runner* acquireSharedRunner(const std::string& modelPath,
                                     const RunStreamOptions& options,
                                     RunStreamReceipt& receipt) {
    if (g_runner && g_loadedModel == modelPath &&
        g_loadedDevice == options.device &&
        g_loadedContext == options.contextTokens) {
        receipt.modelPath = modelPath;
        receipt.engineInitialized = true;
        receipt.modelLoaded = true;
        receipt.contextLimit = g_runner->engine().getConfig().maxSeqLen;
        receipt.vulkanInference = g_runner->engine().isVulkanInitialized();
        receipt.device = receipt.vulkanInference ? "gpu" : "cpu";
        return g_runner.get();
    }
    g_runner.reset(new RawrDeep2Runner());
    g_loadedModel.clear();
    if (!g_runner->load(modelPath, options, receipt)) {
        g_runner.reset();
        return nullptr;
    }
    g_loadedModel = modelPath;
    g_loadedDevice = options.device;
    g_loadedContext = options.contextTokens;
    return g_runner.get();
}

// ---------------------------------------------------------------------------
// Top-level entry: full RAWR_RUN_STREAM_001 receipt.
// ---------------------------------------------------------------------------
int run_rawr_run(const std::string& modelPath, const std::string& prompt,
                 uint32_t maxTokens) {
    RunStreamOptions options;
    options.maxTokens = maxTokens;
    return run_rawr_run(modelPath, prompt, options);
}

int run_rawr_run(const std::string& modelPath, const std::string& prompt,
                 const RunStreamOptions& options) {
    RunStreamReceipt receipt{};

    if (modelPath.empty()) {
        receipt.modelResolved = false;
        receipt.error = "resolved model path is empty";
        std::fprintf(stderr, "[RAWR_RUN_STREAM_001] MODEL_RESOLVED=0\n");
        emitReceipt(receipt);
        writeJsonReceipt(options.receiptPath, receipt);
        return 1;
    }
    receipt.modelResolved = true;
    receipt.modelPath = modelPath;

    RawrDeep2Runner* runner = acquireSharedRunner(modelPath, options, receipt);
    if (!runner) {
        emitReceipt(receipt);
        writeJsonReceipt(options.receiptPath, receipt);
        return 1;
    }

    const bool ok = runner->run(prompt, options,
                                [](std::string_view text) {
                                    std::fwrite(text.data(), 1, text.size(),
                                                stdout);
                                    std::fflush(stdout);
                                },
                                receipt);

    const bool pass = ok &&
                      receipt.generatedTokens > 0 &&
                      receipt.streamCallbackUsed &&
                      receipt.contextAdmitted &&
                      receipt.unplannedFallbacks == 0 &&
                      !receipt.strictViolation;
    receipt.status = pass ? "PASS" : "FAIL";
    receipt.exitCode = pass ? 0 : 1;

    std::fwrite("\n", 1, 1, stdout);
    std::fflush(stdout);

    emitReceipt(receipt);
    if (!writeJsonReceipt(options.receiptPath, receipt)) {
        std::fprintf(stderr, "[RAWR_RUN_STREAM_001] receipt write failed path=%s\n",
                     options.receiptPath.c_str());
        return 1;
    }
    return receipt.exitCode;
}

int run_rawr_interactive(const std::string& modelPath,
                         const RunStreamOptions& options) {
    RunStreamReceipt loadReceipt{};
    loadReceipt.modelResolved = true;
    loadReceipt.modelPath = modelPath;
    RawrDeep2Runner* runner = acquireSharedRunner(modelPath, options, loadReceipt);
    if (!runner) {
        emitReceipt(loadReceipt);
        return 2;
    }

    std::string prompt;
    while (std::getline(std::cin, prompt)) {
        if (prompt == "/exit" || prompt == "/quit") break;
        RunStreamReceipt receipt{};
        receipt.modelResolved = true;
        receipt.modelPath = modelPath;
        const bool ok = runner->run(prompt, options,
                                    [](std::string_view text) {
                                        std::fwrite(text.data(), 1, text.size(), stdout);
                                        std::fflush(stdout);
                                    }, receipt);
        receipt.status = ok && receipt.generatedTokens > 0 &&
                                 receipt.contextAdmitted &&
                                 receipt.unplannedFallbacks == 0 &&
                                 !receipt.strictViolation
                             ? "PASS" : "FAIL";
        receipt.exitCode = receipt.status == "PASS" ? 0 : 1;
        std::fwrite("\n", 1, 1, stdout);
        std::fflush(stdout);
        emitReceipt(receipt);
        if (!writeJsonReceipt(options.receiptPath, receipt)) return 1;
        if (receipt.exitCode != 0) return receipt.exitCode;
    }
    return 0;
}

} // namespace runstream
} // namespace rawrxd
