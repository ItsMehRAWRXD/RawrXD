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
#include <new>
#include <stdexcept>

namespace rawr::product_run {

using Request = ProductRequest;

/* Peer A8: define RAWR_PRODUCT_RUN_NO_INLINE in ProductRun_a8_r76.cpp so a
 * strong /FORCE:MULTIPLE symbol can override frozen seh_r72 inline COMDAT. */
#if defined(RAWR_PRODUCT_RUN_NO_INLINE)
Result ProductRun(const ProductRequest& req) {
#else
inline Result ProductRun(const ProductRequest& req) {
#endif
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
    /* Live session: skip AutoBackend stack (A8 R76 — post-decode C0000409). */
    Deep2::BackendDecision decision{};
    decision.backend = Deep2::Backend::VulkanPrimary;
    decision.reason = "SESSION_ALREADY_OPEN";
    if (!rt->IsOpen()) {
        Deep2::AutoBackendController abc;
        Deep2::ModelFit fit{};
        Deep2::DeviceBudget budget{};
        Deep2::ExecutionPolicy policy{};
        if (const char* e = std::getenv("RAWR_FORCE_CPU"))
            policy.forceCPU = (e[0] == '1');
        if (const char* e = std::getenv("RAWR_FORCE_GPU"))
            policy.forceGPU = (e[0] == '1');
        if (const char* e = std::getenv("RAWR_NO_CPU_FALLBACK"))
            policy.allowCPUFallback = (e[0] != '1');
        else if (const char* hd = std::getenv("RAWRXD_HOST_DECODE");
                 hd && hd[0] == '1')
            policy.allowCPUFallback = true;
        else {
            policy.forceGPU = true;
            policy.allowCPUFallback = false;
        }
        if (const char* e = std::getenv("RAWR_MIN_CPU_TPS"))
            policy.minimumCpuTPS = std::atof(e);
        if (const char* e = std::getenv("RAWR_PREFILL_TIMEOUT_MS"))
            policy.prefillTimeoutMs = std::atof(e);
        if (const char* e = std::getenv("RAWR_DECODE_TIMEOUT_MS"))
            policy.decodeTimeoutMs = std::atof(e);
        if (!abc.InspectModel(alias, fit)) {
            r.failedStage = "INSPECT";
            r.failedOwner = "GGUF_OPEN";
            r.exitReason = "FAIL";
            rt->alreadyGenerating.store(0);
            EmitReceipt(stderr, r);
            return r;
        }
        abc.MeasureHostBudget(budget);
        abc.MeasureGpuBudget(budget);
        decision = abc.Decide(fit, budget, policy);
        fprintf(stderr, "[AUTO_BACKEND] decision=%s reason=%s\n",
                Deep2::BackendName(decision.backend), decision.reason.c_str());
        fflush(stderr);
        if (decision.backend == Deep2::Backend::Reject) {
            const char* skip = std::getenv("RAWR_SKIP_AUTO_BACKEND");
            const bool gpuReq = policy.forceGPU || !policy.allowCPUFallback;
            if (skip && skip[0] == '1' && gpuReq &&
                budget.vulkanInstanceCreated) {
                decision.backend = Deep2::Backend::VulkanPrimary;
                decision.reason = "RAWR_SKIP_AUTO_BACKEND+GPU_REQUIRED+ICD";
            }
        }
        if (decision.backend == Deep2::Backend::Reject) {
            r.failedStage = "BACKEND_SELECT";
            r.failedOwner = "NO_FEASIBLE_BACKEND";
            r.exitReason = "REJECT";
            rt->alreadyGenerating.store(0);
            EmitReceipt(stderr, r);
            return r;
        }
    } else {
        fprintf(stderr,
                "[AUTO_BACKEND] decision=VulkanPrimary reason=SESSION_ALREADY_OPEN\n");
        fflush(stderr);
    }
    /* Never flip Vulkan under a live OpenSession — tip INFER_STREAM_SEH. */
    TokenBudget tokenBudget = ResolveTokenBudget(req.maxTokens);
    if (req.engine && !req.runtime) rt->BindExternal(req.engine, alias, nullptr);
    if (!rt->IsOpen()) {
        if (decision.backend == Deep2::Backend::CPU) {
            rt->Eng().enableVulkan(false);
        } else if (decision.backend == Deep2::Backend::VulkanPrimary ||
                   decision.backend == Deep2::Backend::VulkanDual ||
                   decision.backend == Deep2::Backend::MoEStreaming) {
            rt->Eng().enableVulkan(true);
        }
        if (!rt->OpenSession(alias)) {
            r.failedStage = "LOAD";
            r.failedOwner = "GGUF_OPEN";
            r.exitReason = "FAIL";
            rt->alreadyGenerating.store(0);
            EmitReceipt(stderr, r);
            return r;
        }
    }
    rxow::OnProductRunRequested();
    r.modelResolved = 1;
    r.modelOpen = 1;
    r.tokenizerReady = 1;
    try {
        r.modelPath = rt->modelPath;
        r.modelName = rt->modelAlias;
    } catch (const std::bad_alloc&) {
        r.failedStage = "PRODUCT_RUN";
        r.failedOwner = "BAD_ALLOC_ASSIGN";
        r.exitReason = "FAIL";
        std::fprintf(stderr, "PRODUCT_RUN_BAD_ALLOC=1 stage=ASSIGN\n");
        rt->alreadyGenerating.store(0);
        EmitReceipt(stderr, r);
        return r;
    }
    r.runtimeReady = 1;
    r.streamEnter = 1;
    const char* prompt = (req.prompt && req.prompt[0]) ? req.prompt : "hi";
    int userCancel = 0;
    Deep2::StreamCorrupt_Clear();
    try {
        RunDecodeStream(*rt, prompt, tokenBudget.effective, req.onPiece, r,
                        userCancel);
    } catch (const std::bad_alloc&) {
        r.failedStage = "GENERATE_STREAM";
        r.failedOwner = "BAD_ALLOC";
        r.exitReason = "FAIL";
        r.productPass = 0;
        r.streamEnter = 0;
        std::fprintf(stderr, "PRODUCT_RUN_BAD_ALLOC=1 stage=DECODE\n");
        std::fflush(stderr);
    } catch (const std::exception& ex) {
        r.failedStage = "GENERATE_STREAM";
        r.failedOwner = "CXX_EX";
        r.exitReason = "FAIL";
        r.productPass = 0;
        r.streamEnter = 0;
        std::fprintf(stderr, "PRODUCT_RUN_CXX_EX=1 what=%s\n", ex.what());
        std::fflush(stderr);
    }
    if (Deep2::StreamCorrupt()) {
        r.exitReason = "CORRUPT";
        r.productPass = 0;
        r.failedStage = Deep2::StreamCorrupt_Stage();
        r.failedOwner = Deep2::StreamCorrupt_Owner();
    } else if (userCancel || rt->Eng().isCancelRequested()) {
        r.exitReason = "CANCELLED";
        r.productPass = 0;
    } else if (!(r.failedOwner &&
                 (std::strcmp(r.failedOwner, "BAD_ALLOC") == 0 ||
                  std::strcmp(r.failedOwner, "CXX_EX") == 0))) {
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
    std::fflush(stderr);
    /* A8: skip lastReceipt string copy — R75 C0000409 on ProductRun return. */
    const bool a8min = [] {
        const char* m = std::getenv("RAWRXD_A8_MIN_TEARDOWN");
        return m && m[0] == '1';
    }();
    if (!a8min) rt->lastReceipt = r;
    rt->alreadyGenerating.store(0);
    if (!req.keepOpen) rt->CloseSession();
    std::fprintf(stderr, "PRODUCT_RUN_RETURN=1 a8min=%d\n", a8min ? 1 : 0);
    std::fflush(stderr);
    return r;
}

} // namespace rawr::product_run
