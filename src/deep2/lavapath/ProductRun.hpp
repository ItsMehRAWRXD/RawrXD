#pragma once
/* One production pipeline — adapters call ProductRun only. ≤99 lines. */
#include "ProductReceipt.hpp"
#include "ProductRequest.hpp"
#include "ProductRuntime.hpp"
#include "ProductRunDecode.hpp"
#include "ProductTokenBudget.hpp"
#include "RxRunStateHooks.hpp"
#include "../StreamCorrupt.hpp"
#include "../RawrAutoBackendPolicy.hpp"
#include <cstdio>
#include <cstring>
#include <memory>
#include <chrono>
#include <string>

namespace rawr::product_run {

using Request = ProductRequest;

inline Result ProductRun(const ProductRequest& req) {
    Result r{};
    ProductRuntime* rt = req.runtime ? req.runtime : &SharedProductRuntime();
    /* Never stack-construct an unused ProductRuntime: its Deep2Engine dtor
     * clears process-global LivePath/K2 binds and poisons SharedProductRuntime
     * reopen (R1 multi-model LOAD→GEN→UNLOAD→RELOAD). */
    std::unique_ptr<ProductRuntime> localOwner;
    if (!req.runtime && !req.keepOpen) {
        localOwner = std::make_unique<ProductRuntime>();
        rt = localOwner.get();
    }

    if (rt->alreadyGenerating.exchange(1) != 0) {
        r.failedStage = "BUSY";
        r.failedOwner = "CONCURRENT";
        r.exitReason = "BUSY";
        EmitReceipt(stderr, r);
        return r;
    }
    const char* alias =
        (req.modelAlias && req.modelAlias[0]) ? req.modelAlias
                                              : rt->modelAlias.c_str();
    if (!alias || !alias[0]) {
        r.failedStage = "RESOLVE";
        r.failedOwner = "MODEL_ALIAS";
        r.exitReason = "FAIL";
        rt->alreadyGenerating.store(0);
        EmitReceipt(stderr, r);
        return r;
    }
    // ========================================================================
    // AUTO-BACKEND POLICY: inspect model, measure resources, select backend
    // ========================================================================
    Deep2::AutoBackendController abc;
    Deep2::ModelFit fit{};
    Deep2::DeviceBudget budget{};
    Deep2::ExecutionPolicy policy{};

    // CLI/env overrides
    if (const char* e = std::getenv("RAWR_FORCE_CPU")) policy.forceCPU = (e[0] == '1');
    if (const char* e = std::getenv("RAWR_FORCE_GPU")) policy.forceGPU = (e[0] == '1');
    if (const char* e = std::getenv("RAWR_NO_CPU_FALLBACK")) policy.allowCPUFallback = (e[0] != '1');
    if (const char* e = std::getenv("RAWR_MIN_CPU_TPS")) policy.minimumCpuTPS = std::atof(e);
    if (const char* e = std::getenv("RAWR_PREFILL_TIMEOUT_MS")) policy.prefillTimeoutMs = std::atof(e);
    if (const char* e = std::getenv("RAWR_DECODE_TIMEOUT_MS")) policy.decodeTimeoutMs = std::atof(e);

    // Inspect model
    if (!abc.InspectModel(alias, fit)) {
        r.failedStage = "INSPECT";
        r.failedOwner = "GGUF_OPEN";
        r.exitReason = "FAIL";
        rt->alreadyGenerating.store(0);
        EmitReceipt(stderr, r);
        return r;
    }

    // Measure host budget
    abc.MeasureHostBudget(budget);

    // Measure GPU budget (preflight + Vulkan ICD)
    abc.MeasureGpuBudget(budget);

    // Select backend
    auto decision = abc.Decide(fit, budget, policy);
    fprintf(stderr,
        "[AUTO_BACKEND] decision=%s reason=%s\n",
        Deep2::BackendName(decision.backend), decision.reason.c_str());
    fflush(stderr);

    if (decision.backend == Deep2::Backend::Reject) {
        r.failedStage = "BACKEND_SELECT";
        r.failedOwner = "NO_FEASIBLE_BACKEND";
        r.exitReason = decision.reason.c_str();
        rt->alreadyGenerating.store(0);
        EmitReceipt(stderr, r);
        return r;
    }

    // Configure engine for selected backend
    if (decision.backend == Deep2::Backend::CPU) {
        rt->Eng().enableVulkan(false);
    } else if (decision.backend == Deep2::Backend::VulkanPrimary ||
               decision.backend == Deep2::Backend::VulkanDual ||
               decision.backend == Deep2::Backend::MoEStreaming) {
        rt->Eng().enableVulkan(true);
    }

    TokenBudget tokenBudget = ResolveTokenBudget(req.maxTokens);
    rxow::Reset();
    if (req.engine && !req.runtime) rt->BindExternal(req.engine, alias, nullptr);
    if (!rt->IsOpen() && !rt->OpenSession(alias)) {
        r.failedStage = "LOAD"; 
        r.failedOwner = "GGUF_OPEN";
        r.exitReason = "FAIL";
        rt->alreadyGenerating.store(0);
        EmitReceipt(stderr, r);
        return r;
    }
    rxow::OnProductRunRequested();
    r.modelResolved = 1;
    r.modelOpen = 1;
    r.tokenizerReady = 1;
    r.modelPath = rt->modelPath;
    r.modelName = rt->modelAlias;
    r.runtimeReady = 1;
    r.streamEnter = 1;
    const char* prompt = (req.prompt && req.prompt[0]) ? req.prompt : "hi";
    int userCancel = 0;
    Deep2::StreamCorrupt_Clear();
    RunDecodeStream(*rt, prompt, tokenBudget.effective, req.onPiece, r, userCancel);
    if (Deep2::StreamCorrupt()) {
        r.exitReason = "CORRUPT";
        r.productPass = 0;
        r.failedStage = Deep2::StreamCorrupt_Stage();
        r.failedOwner = Deep2::StreamCorrupt_Owner();
    } else if (userCancel || rt->Eng().isCancelRequested()) {
        r.exitReason = "CANCELLED";
        r.productPass = 0;
    } else {
        r.exitReason = r.firstToken ? "COMPLETE" : "FAIL";
        r.productPass = FunctionalComplete(r);
        if (!r.productPass) {
            r.failedStage = "GENERATE_STREAM";
            r.failedOwner = "FIRST_OWNER_RUNTIME";
        }
    }
    EmitReceipt(stderr, r);
    std::fprintf(stderr,
                 "REQUESTED_MAX_TOKENS=%u\nEFFECTIVE_MAX_TOKENS=%u\n"
                 "MAX_TOKENS_SOURCE=%s\n",
                 tokenBudget.requested, tokenBudget.effective,
                 MaxTokensSourceName(tokenBudget.source));
    rt->lastReceipt = r;
    rt->alreadyGenerating.store(0);
    if (!req.keepOpen) rt->CloseSession();
    return r;
}

} // namespace rawr::product_run
