// rawr_cmd_run.cpp ù product rawr run via Deep2StreamSession
#include "rawr_commands.hpp"
#include "rawr_output_router.hpp"
#include "rawr_model_registry.hpp"
#include "rawr_out_gate.hpp"
#include "../deep2/Deep2Engine.h"
#include "../deep2/daily/d2_stream_session.h"
#include "../deep2/daily/d2_deep2_binding.h"
#include "../deep2/daily/d2_session_engine.h"
#include "../deep2/lavapath/ProductStreamerPrep.hpp"
#include "../deep2/GpuPreflight.hpp"
#include "../deep2/RawrAutoBackendPolicy.hpp"
#include "../reap/ReapRuntime.hpp"
#include "../core/agent_wal.hpp"
#include <cstdio>
#include <cstdlib>
#include <string>

namespace rawr {
namespace {
int OnTok(void* user, uint32_t, const char* text, size_t n) {
    if (user) static_cast<OutGate*>(user)->emit(text, n);
    return 1;
}
} // namespace

int CmdRun(const CliArgs& a) {
    if (a.model.empty()) { PrintUsage(); return ExitCode::Usage; }
    if (a.verbose) _putenv_s("RAWRXD_D2_SESSION_TRACE", "1");

    // Live size target: --reap <params>/<experts>, or --size <params>/<experts>
    // as a compatibility alias. Plain --size without '/' remains fail-closed.
    std::string reapTarget = a.reapTarget;
    if (reapTarget.empty() && !a.sizeOnly.empty()) {
        if (a.sizeOnly.find('/') != std::string::npos) {
            reapTarget = a.sizeOnly;
            Diag("[REAP] --size %s accepted as live target alias for --reap\n",
                 a.sizeOnly.c_str());
        } else {
            Diag("MODEL_SIZE_REQUESTED=%s\n", a.sizeOnly.c_str());
            Diag("REAP_RUNTIME_UNAVAILABLE: use --reap <params>/<experts> "
                 "or --size <params>/<experts> "
                 "(e.g. --reap 30GB/8 or --size 1B/8); plain byte --size is rejected\n");
            return ExitCode::Usage;
        }
    }

    // Live REAP: non-destructive working-set + expert top-k, then usable run.
    if (!reapTarget.empty()) {
        RawrXD::Reap::RuntimeRequest req{};
        req.model = a.model;
        req.target = reapTarget;
        req.prompt = a.prompt;
        req.maxTokens = a.maxTokens ? a.maxTokens : 64u;
        req.receiptPath = a.reapReceiptPath;
        if (req.prompt.empty()) {
            Diag("rawr: --reap/--size target requires a prompt (-p/--prompt) "
                 "for usable E2E (or --receipt for load-only)\n");
            if (a.reapReceiptPath.empty()) return ExitCode::Usage;
        }
        if (!Deep2::ProductStreamerPrep()) return ExitCode::Runtime;
        const auto result = RawrXD::Reap::RunRuntime(req);
        std::fputs(result.receipt.c_str(), stdout);
        std::fflush(stdout);
        if (result.exitCode == 0) {
            rawrxd::agent_wal::Append(rawrxd::agent_wal::DefaultRoot(), 1,
                                      "CMD_RUN_REAP_OK", a.model.c_str());
            return ExitCode::Ok;
        }
        Diag("rawr: REAP runtime exit=%d\n", result.exitCode);
        if (result.exitCode == 2) return ExitCode::Usage;
        return ExitCode::Runtime;
    }

    auto& reg = ModelRegistry::instance();

    /* Announce resolution start so the user sees progress instead of a hang. */
    Diag("[MODEL_RESOLUTION] %s\n", a.model.c_str());

    reg.scan(a.refresh);
    ModelEntry ent;
    if (!reg.resolve(a.model, ent) || ent.path.empty()) {
        Diag("[ERROR] MODEL_NOT_FOUND\n");
        Diag("\nSearched:\n");
        for (const auto& r : reg.roots())
            Diag("  %s\n", r.c_str());
        Diag("\nAvailable:\n");
        bool any = false;
        for (const auto& e : reg.entries()) {
            if (!e.valid || e.path.empty()) continue;
            Diag("  %s:%s\n", e.name.c_str(), e.quantization.empty() ? "latest" : e.quantization.c_str());
            any = true;
        }
        if (!any) Diag("  (none)\n");
        Diag("\n");
        return ExitCode::ModelResolve;
    }
    if (a.prompt.empty()) {
        Diag("rawr: prompt required (-p/--prompt/stdin)\n");
        return ExitCode::Usage;
    }
    uint32_t maxTok = a.maxTokens ? a.maxTokens : 64u;
    if (const char* e = std::getenv("RAWRXD_RUN_MAX_TOKENS"))
        if (e[0] && !a.maxTokens) maxTok = (uint32_t)std::atoi(e);

    // ========================================================================
    // AUTO-BACKEND POLICY: inspect model, measure resources, select backend
    // ========================================================================
    Deep2::AutoBackendController abc;
    Deep2::ModelFit fit{};
    Deep2::DeviceBudget budget{};
    Deep2::ExecutionPolicy policy{};

    // CLI/env overrides ? GPU-first; CPU only on explicit opt-in.
    if (const char* e = std::getenv("RAWR_FORCE_CPU")) policy.forceCPU = (e[0] == '1');
    if (const char* e = std::getenv("RAWR_FORCE_GPU")) policy.forceGPU = (e[0] == '1');
    if (const char* e = std::getenv("RAWR_NO_CPU_FALLBACK"))
        policy.allowCPUFallback = (e[0] != '1');
    else if (const char* hd = std::getenv("RAWRXD_HOST_DECODE");
             hd && hd[0] == '1')
        policy.allowCPUFallback = true;
    else {
        policy.forceGPU = true;
        policy.allowCPUFallback = false;
    }
    if (const char* e = std::getenv("RAWR_MIN_CPU_TPS")) policy.minimumCpuTPS = std::atof(e);
    if (const char* e = std::getenv("RAWR_PREFILL_TIMEOUT_MS")) policy.prefillTimeoutMs = std::atof(e);
    if (const char* e = std::getenv("RAWR_DECODE_TIMEOUT_MS")) policy.decodeTimeoutMs = std::atof(e);

    // Inspect model
    if (!abc.InspectModel(ent.path, fit)) {
        Diag("[ERROR] MODEL_INSPECT_FAILED\n");
        return ExitCode::ModelLoad;
    }

    // Measure host budget
    abc.MeasureHostBudget(budget);

    // Measure GPU budget (preflight + Vulkan ICD)
    abc.MeasureGpuBudget(budget);

    // Select backend
    auto decision = abc.Decide(fit, budget, policy);
    Diag("[AUTO_BACKEND] decision=%s reason=%s\n",
        Deep2::BackendName(decision.backend), decision.reason.c_str());

    /* MiniMax REAP residency skip: historically forced CPU. GPU-required law:
       never CPU-override when RAWR_FORCE_GPU / RAWR_NO_CPU_FALLBACK / ALLOW_GPU. */
    if (decision.backend == Deep2::Backend::Reject) {
        const char* skip = std::getenv("RAWR_SKIP_AUTO_BACKEND");
        const char* reap = std::getenv("RAWRXD_REAP_RETAINED");
        const char* forceGpu = std::getenv("RAWR_FORCE_GPU");
        const char* noCpu = std::getenv("RAWR_NO_CPU_FALLBACK");
        const char* allowGpu = std::getenv("RAWRXD_ALLOW_GPU");
        const bool gpuRequired =
            (forceGpu && forceGpu[0] == '1') ||
            (noCpu && noCpu[0] == '1') ||
            (allowGpu && allowGpu[0] == '1' &&
             !(std::getenv("RAWRXD_HOST_DECODE") &&
               std::getenv("RAWRXD_HOST_DECODE")[0] == '1'));
        if (skip && skip[0] == '1' && reap && reap[0] && reap[0] != '0') {
            if (gpuRequired) {
                decision.backend = Deep2::Backend::VulkanPrimary;
                decision.reason =
                    "RAWR_SKIP_AUTO_BACKEND+REAP but GPU_REQUIRED "
                    "(FORCE_GPU/NO_CPU_FALLBACK/ALLOW_GPU)";
            } else {
                decision.backend = Deep2::Backend::CPU;
                decision.reason =
                    "RAWR_SKIP_AUTO_BACKEND=1 + RAWRXD_REAP_RETAINED "
                    "(host residency)";
            }
            Diag("[AUTO_BACKEND] override=%s reason=%s\n",
                 Deep2::BackendName(decision.backend), decision.reason.c_str());
        }
    }

    if (decision.backend == Deep2::Backend::Reject) {
        Diag("[ERROR] NO_FEASIBLE_BACKEND: %s\n", decision.reason.c_str());
        return ExitCode::Runtime;
    }

    // ========================================================================
    // Gate before ProductStreamerPrep ó prep/engine noise ? stderr.
    // ========================================================================
    OutGate gate;
    if (!Deep2::ProductStreamerPrep()) return ExitCode::Runtime;
    Deep2::Deep2Engine engine;

    // GPU health preflight first ù Code 31 DevNode reset before Vulkan open.
    if (!GpuPreflightCheck(!a.vulkan)) return ExitCode::Runtime;

    // Configure engine for selected backend
    if (decision.backend == Deep2::Backend::CPU) {
        engine.enableVulkan(false);
    } else if (decision.backend == Deep2::Backend::VulkanPrimary ||
               decision.backend == Deep2::Backend::VulkanDual ||
               decision.backend == Deep2::Backend::MoEStreaming) {
        engine.enableVulkan(true);
        // If explicit --vulkan was requested but policy selected CPU, reject
        if (a.vulkan && decision.backend == Deep2::Backend::CPU) {
            Diag("[ERROR] --vulkan requested but policy selected CPU\n");
            return ExitCode::Runtime;
        }
    }

    if (a.vulkan) engine.enableVulkan(true);
    Deep2StreamSession* s = d2_session_create();
    if (!s) return ExitCode::Runtime;
    if (a.verbose) d2_session_set_trace(s, 1);
    if (!d2_session_bind_deep2_engine_ptr(s, &engine) ||
        d2_session_backend_is_mock(s)) {
        Diag("rawr: REAL_BIND failed (mock backend)\n");
        d2_session_destroy(s);
        return ExitCode::Runtime;
    }
    if (!d2_session_open_model(s, ent.path.c_str())) {
        Diag("rawr: model open failed: %s\n", ent.path.c_str());
        d2_session_destroy(s);
        return ExitCode::ModelLoad;
    }
    D2GenerateRequest req{};
    req.prompt = a.prompt.c_str();
    req.max_tokens = maxTok;
    req.temperature = 0.f;
    req.seed = 42;
    int ok = d2_session_generate(s, &req, OnTok, &gate);
    d2_session_close_model(s);
    d2_session_destroy(s);
    if (!ok) { Diag("rawr: generate failed\n"); return ExitCode::Runtime; }
    rawrxd::agent_wal::Append(rawrxd::agent_wal::DefaultRoot(), 1, "CMD_RUN_OK",
                              ent.name.c_str());
    return ExitCode::Ok;
}
} // namespace rawr
