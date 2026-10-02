# RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT — ADDENDUM 003
# RUNTIME CONFIRMATION OF THE PRIMARY FAILURE SITE

    AUDIT   = RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT_001
    DATE    = 2026-10-01
    HEAD    = 17b035412efc
    SCOPE   = added one new file, one new CMake target, no production source
              touched.

    RESULT
        The transfer contract is no longer CODE_PROVEN only. On a real Vulkan
        device, the exact argument shape used at vulkan_compute.cpp:3987 and
        :4024 is REJECTED, and the correct shape is accepted. The remaining
        unobserved link is the MLA model load and the full forward chain.

---

## 1. Why a model was not required for this half

The whole question at issue is a units disagreement between a caller and a
callee. That question is fully decidable at the transfer layer, with a device
buffer and a host array -- no weights, no architecture, no engine. Certifying it
there converts `:3987` from a read of the source into an observation.

Harness: `tools/mla_upload_contract_cert.cpp`, target `mla_upload_contract_cert`,
linked against the same `InferenceEngine` the product links. It is a cert, not
a product path: nothing in the product depends on it.

## 2. Device actually used

    PHYSICAL_DEVICES=2
    DEVICE name=AMD Radeon AI PRO R9700   ordinal=0 discrete=1 compute=1
           localBytes=34208743434 (34.2 GB)
    DEVICE name=Microsoft Direct3D12 (Microsoft Basic Render Driver)
           ordinal=1 discrete=0

    BATCH9_VK_DEVICE ordinal=0 name=AMD Radeon AI PRO R9700 vram=34208743424
                 compute_pipeline=1 qgemv_pipeline=1 batch4row=1 batch8row=1
                 calibrated=1

Ordinal 0 was selected, which is the same ordinal `getVulkanComputeSlot(0)`
targets on the MLA path. So the device in this certificate is the device the
defect would run on.

## 3. Measurements

Buffer: `EnsureScratch(0, 1024)` standing in for `qElems = heads*keyLen`.

    SCRATCH_ELEMENT_COUNT=1024
    SCRATCH_SIZE_BYTES=4096                              (1024 * 4)
    SCRATCH_BYTES_IF_ELEMENT_COUNT_WERE_SCALED=16384     (1024 * 4 * 4)

    UPLOAD_WITH_ELEMENT_COUNT_OK=1        <- the contract case
    UPLOAD_WITH_BYTE_COUNT_OK=0           <- the :3987 shape
    DOWNLOAD_WITH_ELEMENT_COUNT_OK=1      <- the contract case
    DOWNLOAD_WITH_BYTE_COUNT_OK=0         <- the :4024 shape
    ELEMENT_COUNT_ROUNDTRIP_MAXDIFF=0
    UNIT_ERROR_IS_RUNTIME_DECIDED=1
    VERDICT=PASS

The engine's own trace confirms the mechanism rather than inferring it:

    UPLOAD_STAGING bytes=4096
    UPLOAD_MEMCPY bytes=4096
    UPLOAD_BEGIN  bytes=4096
    UPLOAD_COPY   bytes=4096
    UPLOAD_ENDSUBMIT bytes=4096
    UPLOAD_OK bytes=4096

4096 bytes staged for the element-count call; the byte-count call produced no
`UPLOAD_*` trace at all, because `uploadToBuffer` returned at its bounds check
(`vulkan_compute.cpp:1555`) before any staging, any `memcpy` and any command
submission. That is why the earlier reading predicted "no memory corruption" as
well as "no transfer": the refusal happens before the first byte moves.

`ELEMENT_COUNT_ROUNDTRIP_MAXDIFF=0` matters for a second reason. It shows the
accepted path is exact, so the rejection is a real contract decision and not a
masking failure that happens to coincide with a broken path.

## 4. Confidence ledger, updated

```ini
TRANSFER_CONTRACT_IS_ELEMENTS         = RUNTIME_PROVEN (was code-proven)
3987_ARGUMENT_REJECTED_BY_BOUNDS      = RUNTIME_PROVEN
4024_ARGUMENT_REJECTED_BY_BOUNDS      = RUNTIME_PROVEN
CORRECT_PATH_ACCEPTED_AND_EXACT       = RUNTIME_PROVEN (maxdiff 0)
MEMORY_CORRUPTION                     = NOT_OCCURRING (transfer refused pre-memcpy)
PRIMARY_FAILURE_SITE                  = vulkan_compute.cpp:3987  RUNTIME_PROVEN

RUNMLATTENTIONHOST_RETURNS_FALSE      = INFERRED from 3987 (its first action)
ATTENTION_THROWS_RUNTIME_ERROR        = CODE_PROVEN (Deep2Engine.cpp:3692)
FORWARD_RETURNS_COMMITTED_FALLBACK_BLOCKED = CODE_PROVEN (Deep2Engine.cpp:4720)
MLA_FORWARD_CHAIN_RUNTIME_OBSERVED    = 0
```

The chain from `:3987` to `"committed_fallback_blocked"` is now
*code-proven at every link, with the first link runtime-proven on the exact
device the path would use.*

## 5. The one link still unobserved, and why

    MLA_MODEL_AVAILABLE = 0

`ModelRegistry.cpp:75-77, 113-115` admits MLA only for architecture ids
`deepseek2`, `deepseek32`, `deepseek4`, mapped from `deepseek-v2`, `deepseek-v3`
and `deepseek2-lite`. `ModelRegistry.cpp:250-258` additionally requires
`kvLoraRank != 0`, `qkNopeHeadDim != 0` and `qkRopeHeadDim != 0` for an MLA
admission.

Every model on this machine is non-MLA:

    G:\~dev\rawrxd\models   gemma3-1b-Q2_K, llama3.2-3b-Q2_K, phi3-mini-Q2_K,
                           tinyllama-1.1b-chat-v1.0.Q4_K_M, tinyllama, model.gguf(0)
    G:\~dev\...             gptoss20b.gguf, ministral3_q4_0.gguf,
                           Qwen3.5-40B-Q4_K_M.gguf  (all GQA, not MLA)
    F:\~dev\...             qwen2.5-coder-1.5b-base.gguf and test fixtures
    C:\Users\Garrett        none

The Gate 1 server log independently confirms the model exercised there was
outside this path: `admission OK arch=llama family=GENERIC_TRANSFORMER moe=0
mla=0`.

Synthesising a DeepSeek-2 GGUF was considered and rejected: the repository has no
GGUF authoring tooling (`tools/gguf_inspector.cpp` is a 25-byte stub, and no file
in `tools/` matches `GGUF_MAGIC` or `gguf_write`), so it would mean writing a
GGUF writer from scratch and then producing a synthetic fixture that could later
be mistaken for a real model. A real DeepSeek-2-lite conversion is the smallest
honest route, and it is a multi-gigabyte download, which is not an action to take
unilaterally.

### The single decisive experiment, still outstanding

    1. supply any GGUF whose arch is deepseek2 / deepseek32 (DeepSeek-V2-Lite
       is the smallest practical choice)
    2. load it, run one forward with vulkanEnabled_=true
    3. expect, in order:
         [Deep2Engine] admission OK arch=deepseek2 ... mla=1
         BATCH10_GPU_HYBRID_FAIL layer_math=attention: GPU MLA path failed or
             unsupported
         COMMITTED_FALLBACK_BLOCKED=1 STRICT_NATIVE_ABORT=1 VERDICT=FAIL
             stage=moe_hybrid
    4. expect ForwardResult.ok == false with reason "committed_fallback_blocked"

Anything other than that sequence would mean an additional runtime condition
alters the path, and the static analysis would need revisiting.

## 6. Also closed

    HEADER_DUPLICATE_AUTHORITY = CLOSED

Not only are the four duplicate headers absent from every source file's include
list, they are referenced in **no generated build file** either -- no `.vcxproj`,
no `CMakeFiles` entry, no `link.txt`, no `.tlog`. They cannot enter a product
build by any route.

## 7. Ledger

    CERT_BINARY          = build_ide_audit/bin/Release/mla_upload_contract_cert.exe
    CERT_BUILT_AT        = 2026-10-01 17:52:16
    DEVICE_UNDER_TEST    = AMD Radeon AI PRO R9700, ordinal 0, discrete, 34.2 GB
    UNIT_ERROR_RUNTIME_DECIDED = 1
    CORRECT_PATH_EXACT        = 1  (roundtrip maxdiff 0)
    MEMORY_CORRUPTION         = 0
    MLA_FORWARD_CHAIN_OBSERVED = 0
    PRODUCTION_SOURCE_EDITS   = 0
    STATIC_ANALYSIS           = HIGH
    RUNTIME_CONFIRMATION      = PARTIAL  (transfer layer confirmed; MLA load pending)