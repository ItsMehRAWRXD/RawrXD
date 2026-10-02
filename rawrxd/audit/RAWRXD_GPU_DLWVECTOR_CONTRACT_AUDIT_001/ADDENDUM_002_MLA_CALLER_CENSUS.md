# RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT — ADDENDUM 002
# `RunMLAAttentionHost` CALLER CENSUS

    AUDIT   = RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT_001
    DATE    = 2026-10-01
    HEAD    = 17b035412efc
    SCOPE   = read-only. No source was modified.

    QUESTION_ASKED
        Is the confirmed unit error latent because execution never reaches it, or
        does the earlier upload failure propagate into observable behaviour?

    ANSWER
        It propagates. It is not dormant. For any MLA model the forward pass
        aborts with ForwardResult{ok=false, reason="committed_fallback_blocked"}
        and sets vulkanStrictViolation_=true.

---

## 1. One caller, and it propagates

`RunMLAAttentionHost` has exactly **one** production caller (the other five
matches are the five dead-copy headers and this audit's own documents).

    Deep2Engine_GpuMoEMLA.cpp:412-418
        if(!g0||!g0->RunMLAAttentionHost(...))
            return false;

No fallback, no retry, no `else`. The `false` is returned straight up.

## 2. The next level throws, and there is no CPU MLA path

    Deep2Engine.cpp:3679-3694   Deep2Engine::computeAttention
        if (lw.useMLA || modelWeights.useMLA) {
            if (computeMLAAttentionGpu(layer, input, output, seqLen))
                return;
            throw std::runtime_error(
                "attention: GPU MLA path failed or unsupported");
        }
        ... MHA/GQA implementation follows ...

The throw is **unconditional** on the MLA branch. A repository-wide census of
`lw.useMLA || modelWeights.useMLA` in the live `Deep2Engine*` sources returns
exactly one branch in the attention implementation, and it is this one:

    Deep2Engine.cpp:3689   the only attention-side MLA branch
    Deep2Engine.cpp:4705/4707/4726/4764/4769/4986   routing and logging only
    Deep2Engine_GpuMoEMLA.cpp:333                  a guard that returns false
    Deep2Engine_Speculative.cpp:59, 328            speculative decoding refuses MLA

There is no host MLA attention implementation. The MHA/GQA code below the branch
is unreachable for an MLA model, because an MLA model never falls through --
it throws.

## 3. Where the throw lands, and what the caller does with it

    Deep2Engine_GpuMoEMLA.cpp:430-447   forwardTokenGpuHybrid
        gpuFwdStateMutated_ = false;                 (:431)
        if (!hidden || ... || !vulkanInitialized_) return false;
        gpuFwdStateMutated_ = true;                  (:432)  <-- set before the loop
        try {
            for (...) forwardLayer(l, hidden, layerTemp, seqLen);   // throws here
        } catch (const std::exception& ex) {
            fprintf(stderr,"BATCH10_GPU_HYBRID_FAIL layer_math=%s\n",ex.what());
            return false;                            (:446)
        }

    Deep2Engine.cpp:4725-4734   the forward router
        if (vulkanEnabled_ && vulkanInitialized_ &&
            (modelWeights.isMoE || modelWeights.useMLA)) {
            if (forwardTokenGpuHybrid(hidden, seqLen))
                return ForwardResult{true, ExecutionRoute::VulkanMoeHybrid, true, nullptr};
            if (gpuFwdStateMutated_)
                return blockCommittedFallback("moe_hybrid", ExecutionRoute::VulkanMoeHybrid);
            ...
        }

    Deep2Engine.cpp:4710-4721   blockCommittedFallback
        fprintf(stderr,
            "COMMITTED_FALLBACK_BLOCKED=1 STRICT_NATIVE_ABORT=1 VERDICT=FAIL stage=%s\n",
            stage);
        vulkanStrictViolation_ = true;
        gpuFwdCommitted_ = false;
        return ForwardResult{false, route, false, "committed_fallback_blocked"};

`gpuFwdStateMutated_` is set `true` at `:432` *before* the layer loop, so the
`if (gpuFwdStateMutated_)` arm is always the one taken after a failure, and the
CPU fallback at `:4731-4734` is never reached. The abort is deliberate
fail-closed behaviour, not an oversight -- but it means the failure is
**observable**, not swallowed.

## 4. Full chain, each link file:line

    vulkan_compute.cpp:3987        UploadVector(qBuf, q, qElems*sizeof(float))
                                   -> element contract, 4x requested bytes
    vulkan_compute.cpp:1555        uploadToBuffer: bytes > dst.size -> false
    vulkan_compute.cpp:3990        return false        (:4024 never executes)
    Deep2Engine_GpuMoEMLA.cpp:418  return false        (propagated)
    Deep2Engine.cpp:3692           throw runtime_error (no CPU MLA branch)
    Deep2Engine_GpuMoEMLA.cpp:446  catch -> return false
    Deep2Engine.cpp:4730           blockCommittedFallback
    Deep2Engine.cpp:4720           ForwardResult{ok=false, "committed_fallback_blocked"}
    Deep2Engine.cpp:4718           vulkanStrictViolation_ = true

## 5. Classification, corrected

```ini
UNIT_BUG_PRESENT                = YES   (vulkan_compute.cpp:3987, and 3988, 3989, 4024)
4024_RUNTIME_EXECUTION          = NOT_REACHED
PRIMARY_FAILURE_SITE            = vulkan_compute.cpp:3987  (first upload)
4024_MASKED_BY_FALLBACK          = NO
4024_MASKED_BY_EARLIER_BUG      = YES   (:3987 fails first; :4024 is downstream of the same defect)

RUNMLATTENTIONHOST_RUNTIME_IMPACT = FATAL_FOR_ANY_MLA_MODEL
  ON_GPU_LANE                     = ForwardResult ok=false, "committed_fallback_blocked",
                                    vulkanStrictViolation_=true
  ON_CPU_ONLY_RUN                 = computeMLAAttentionGpu returns false at its first
                                    guard (:327-330) and :3692 throws anyway
  CPU_MLA_FALLBACK_EXISTS         = NO
  SILENT_WRONG_ANSWER             = NO   (fail-closed, not degraded)
```

One correction to the earlier framing: `MEMORY_CORRUPTION` was never `PROVEN`.
Both directions of the transfer are bounds-checked, and I recorded it as
`MEMORY_CORRUPTION_FROM_4024 = 0` / `NOT_OCCURRING`. The rest of the
classification above stands, and this census is what settles the open question it
left.

## 6. Second structural finding, independent of the unit bug

`computeAttention`'s MLA branch has **no non-GPU implementation**. Even with
`:3987` corrected, an MLA model on a machine where Vulkan is unavailable or
uninitialised still reaches `:3692` and throws, because
`computeMLAAttentionGpu` returns false at its first guard and the branch offers
no alternative. That is a design gap, not a units defect, and it is a separate
piece of work.

## 7. What is NOT established

    RUNTIME_REPRODUCED = 0
    MLA_MODEL_AVAILABLE = 0

No MLA-architecture model exists in `G:\~dev\rawrxd\models` (gemma3-1b-Q2_K,
llama3.2-3b-Q2_K, phi3-mini-Q2_K, tinyllama-1.1b x2, and a zero-byte
`model.gguf`). The server log from the Gate 1 smoke confirms the model used was
outside this path entirely:

    [Deep2Engine] admission OK arch=llama family=GENERIC_TRANSFORMER moe=0 mla=0
                  recurrent=0 slidingWindow=0 quant=Q4_K(type 12) tensors=201

So this chain is established by reading, not by execution. The decisive runtime
check, and the one thing that would raise this from a code-proven defect to an
observed failure, is:

    1. obtain any MLA model (DeepSeek-V2/V3 tier, or a `useMLA`-tensors model)
    2. load it, run one forward with vulkanEnabled_=true
    3. observe stderr:  BATCH10_GPU_HYBRID_FAIL layer_math=attention: GPU MLA path
                        failed or unsupported
       and             COMMITTED_FALLBACK_BLOCKED=1 STRICT_NATIVE_ABORT=1 VERDICT=FAIL
                        stage=moe_hybrid
    4. observe ForwardResult.ok == false, reason == "committed_fallback_blocked"

Until step 3 runs, the honest classification is `CODE_PROVEN_RUNTIME_UNOBSERVED`.

## 8. Ledger

    RUNMLATTENTIONHOST_PRODUCTION_CALLERS   = 1
    FALSE_RETURN_PROPAGATED                 = 1
    CPU_MLA_FALLBACK_EXISTS                 = 0
    OBSERVABLE_OUTCOME                      = ForwardResult ok=false,
                                            "committed_fallback_blocked",
                                            vulkanStrictViolation_=true
    SILENT_WRONG_ANSWER                     = 0
    RUNTIME_REPRODUCED                      = 0
    MLA_MODEL_AVAILABLE                     = 0
    EDITS_MADE                              = 0
    NEXT_DECISIVE_CHECK                     = load an MLA model, run one forward,
                                              capture the two stderr lines above