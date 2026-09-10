#pragma once
/* One production pipeline — adapters call ProductRun only. ≤99 lines. */
#include "ProductReceipt.hpp"
#include "ProductRequest.hpp"
#include "ProductRuntime.hpp"
#include "ProductRunDecode.hpp"
#include "ProductTokenBudget.hpp"
#include "RxRunStateHooks.hpp"
#include "../StreamCorrupt.hpp"
#include <cstdio>
#include <memory>

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
    TokenBudget budget = ResolveTokenBudget(req.maxTokens);
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
    RunDecodeStream(*rt, prompt, budget.effective, req.onPiece, r, userCancel);
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
                 budget.requested, budget.effective,
                 MaxTokensSourceName(budget.source));
    rt->lastReceipt = r;
    rt->alreadyGenerating.store(0);
    if (!req.keepOpen) rt->CloseSession();
    return r;
}

} // namespace rawr::product_run
