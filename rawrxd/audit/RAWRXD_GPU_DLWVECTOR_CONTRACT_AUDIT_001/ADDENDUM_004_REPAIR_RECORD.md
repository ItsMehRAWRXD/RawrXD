# RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT — ADDENDUM 004
# THE REPAIR, AND ITS BEFORE/AFTER RECORD

    AUDIT   = RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT_001
    DATE    = 2026-10-01
    HEAD    = 17b035412efc
    FILE    = src/deep2/vulkan_compute.cpp
    AUTHORIZED_BY = user, explicitly, before the MLA model was available

    REPAIRED = 4 call sites
    SCOPE    = 1 file, 1 function (VulkanCompute::RunMLAAttentionHost)
    NOTHING ELSE TOUCHED

---

## 1. Why this was repaired now rather than after end-to-end proof

The user's instruction was explicit: repair now, keep a before/after record, and
note that end-to-end proof is still pending. The reasoning behind that choice is
worth recording, because it is the opposite of "edit only if failure
reproduces":

    The mechanism is RUNTIME_PROVEN (ADDENDUM_003, real device, real rejection)
    The control flow is CODE_PROVEN at every link (ADDENDUM_002)
    The remaining link needs a 9.5 GB model that was not present

so the repair is being made against two independent lines of evidence rather
than one, and the pre-repair behaviour is preserved in this document plus in
`mla_upload_contract_cert`, which still passes and still measures the contract
independently of the caller.

## 2. Before / after, exactly

`vulkan_compute.cpp` sha256:

    before = 2639AB6EEEA35A5AD2F409A0BCC61D01702096F861EB3027FABDB22BF84C4CAA
    after  = C44F56BF547E24701130AA97A74437149CAFE6532575DB88AA6413398C90825E

Diff, complete:

    -    if(!UploadVector(qBuf,q,qElems*sizeof(float))||
    -       !UploadVector(kSlice,k,qElems*sizeof(float))||
    -       !UploadVector(vSlice,v,vElems*sizeof(float)))
    +    // RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT_001: the third parameter of
    +    // UploadVector/DownloadVector is a FLOAT ELEMENT count, not a byte count --
    +    // both apply count*sizeof(float) internally (and bounds-check it). These four
    +    // sites supplied bytes, so the first upload requested 4x the scratch buffer
    +    // and was refused before any staging or copy, which made
    +    // RunMLAAttentionHost return false unconditionally. Proven on a real device
    +    // by tools/mla_upload_contract_cert.cpp. Prior text: `qElems*sizeof(float)`
    +    // and `vElems*sizeof(float)`.
    +    if(!UploadVector(qBuf,q,qElems)||
    +       !UploadVector(kSlice,k,qElems)||
    +       !UploadVector(vSlice,v,vElems))
            return false;

    -    return DownloadVector(outBuf,output,qElems*sizeof(float));
    +    return DownloadVector(outBuf,output,qElems);

Four call sites, one argument each, no logic changed and no control flow changed.

## 3. Why the corrected arguments are correct, per site

Geometry in the same function, unchanged by the repair:

    :3976  qElems   = heads*keyLen
    :3977  vElems   = heads*valueLen
    :3978  EnsureScratch(40, qElems)                 -> qBuf
    :3979  EnsureScratch(41, layers*heads*keyLen)     -> kSlice
    :3980  EnsureScratch(42, layers*heads*valueLen)   -> vSlice
    :3981  EnsureScratch(43, qElems)                 -> outBuf

| Site | Buffer | Bytes after repair | Buffer bytes | Verdict |
|---|---|---|---|---|
| `UploadVector(qBuf,q,qElems)` | qBuf | qElems*4 | qElems*4 | exact fit |
| `UploadVector(kSlice,k,qElems)` | kSlice | qElems*4 | layers\*qElems\*4 | within budget |
| `UploadVector(vSlice,v,vElems)` | vSlice | vElems*4 | layers\*vElems\*4 | within budget |
| `DownloadVector(outBuf,output,qElems)` | outBuf | qElems*4 | qElems*4 | exact fit |

Two of the four are exact fits and two are well inside a larger buffer. The two
that were previously 4x oversized are now exact fits, which is the check the
bounds test was already enforcing.

## 4. Post-repair verification

    build  mla_upload_contract_cert : EXIT=0
    run    UPLOAD_WITH_ELEMENT_COUNT_OK=1
           UPLOAD_WITH_BYTE_COUNT_OK=0
           DOWNLOAD_WITH_ELEMENT_COUNT_OK=1
           DOWNLOAD_WITH_BYTE_COUNT_OK=0
           ELEMENT_COUNT_ROUNDTRIP_MAXDIFF=0
           VERDICT=PASS

The contract cert is deliberately independent of the caller, so it reports
identically before and after the repair. That is the point of it: it measures
the API, not the bug, and it therefore remains a valid regression check.

## 5. Harness validated before the MLA run

`tools/mla_forward_chain_cert.cpp` was run against a non-MLA model to prove the
harness can observe a SUCCESS, so that a later failure is attributable to the
model and not to the instrument:

    MODEL=G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
    INIT_OK=1
    [Deep2Engine] admission OK arch=llama family=GENERIC_TRANSFORMER
                  moe=0 mla=0 recurrent=0 slidingWindow=0 quant=Q4_K(type 12)
    [FWD_ALL] seqLen=1 numLayers=22 isMoE=0 useMLA=0 vulkan=1/1
    LOAD_OK=1
    HIDDEN_DIM=2048
    FORWARD_OK=1
    FORWARD_ROUTE=2
    FORWARD_GPU_COMMITTED=1
    FORWARD_FAILURE_STAGE=(none)

`vulkan=1/1` and `FORWARD_GPU_COMMITTED=1` establish that the Vulkan path is live
on this machine and that a committed GPU forward is observable. Without this
control, a failure on the MLA model would have been ambiguous between "the MLA
path is broken" and "the cert cannot drive the engine at all".

## 6. Still open after the repair

    MLA_FORWARD_CHAIN_RUNTIME_OBSERVED = 0

Repairing the unit bug removes the failure the analysis identified, but it does
NOT close the architectural finding, which is independent and unaffected:

    HOST_MLA_IMPLEMENTATION = NONE
    GPU_FAILURE_RECOVERY    = NONE

If the corrected uploads succeed and a LATER stage of the MLA path fails, the
throw at `Deep2Engine.cpp:3692` and the abort at `:4720` still apply. The MLA
forward run will show which, and the two findings stay separately tracked either
way.