#pragma once
/* RuntimeEvidence512_IDEClaims.h - C/C++ ABI declarations, no third-party deps. */
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct EvidenceState512 {
    void*    Buffer;
    uint64_t Capacity;
    uint64_t WriteIndex;
    uint64_t Dropped;
    uint64_t RunId;
    uint32_t SeqCap;
    uint32_t Flags;
} EvidenceState512;

typedef struct EvidenceRecord512 {
    uint32_t Magic;
    uint16_t Version;
    uint16_t RecordBytes;
    uint32_t ClaimId;
    uint32_t Status;
    uint64_t RunId;
    uint64_t Ordinal;
    uint32_t SeqCap;
    uint32_t Reserved;
    uint64_t Arg0;
    uint64_t Arg1;
    uint64_t Commit;
} EvidenceRecord512;

typedef struct EvidenceIDESummary512 {
    uint64_t RunId;
    uint64_t ReservedRaw;
    uint64_t Capacity;
    uint64_t CommittedValid;
    uint64_t Dropped;
    uint64_t ClaimMaskLo;
    uint64_t ClaimMaskHi;
    uint64_t Invalid;
    uint64_t Incomplete;
    uint32_t SeqCap;
    uint32_t Flags;
    uint32_t MaxClaimId;
    uint32_t Reserved;
} EvidenceIDESummary512;

enum { RAWRXD_EVIDENCE_SEQ_CAP = 512, RAWRXD_EVIDENCE_IDE_CLAIM_MAX = 96 };

#define CLAIM_FIRST_TOKEN_BOUNDARY 1u
#define CLAIM_HIDDEN_PROBE 2u
#define CLAIM_HIDDEN_LAST 3u
#define CLAIM_BOUNDED 4u
#define CLAIM_VALID 5u
#define CLAIM_LOGITS_ENTRY 6u
#define CLAIM_LOGITS_COMPLETE 7u
#define CLAIM_ATTN_COMPLETE 8u
#define CLAIM_PATHB_COMPLETE 9u
#define CLAIM_STREAM_COMPLETE 10u
#define CLAIM_STREAM_ABORT 11u
#define CLAIM_TEARDOWN_ENTRY 12u
#define CLAIM_TEARDOWN_COMPLETE 13u
#define CLAIM_TEARDOWN_FAULT 14u
#define CLAIM_WALL_NS 15u
#define CLAIM_DECODE_TPS_Q32_32 16u
#define CLAIM_PARITY 17u
#define CLAIM_IDE_BOOT_ENTRY 18u
#define CLAIM_IDE_WINDOW_READY 19u
#define CLAIM_CORE_INIT_COMPLETE 20u
#define CLAIM_WORKSPACE_OPEN 21u
#define CLAIM_SESSION_RESTORE 22u
#define CLAIM_BACKEND_SELECTED 23u
#define CLAIM_MODEL_DISCOVERY 24u
#define CLAIM_MODEL_IDENTITY 25u
#define CLAIM_MODEL_LOAD_ENTRY 26u
#define CLAIM_MODEL_LOAD_COMPLETE 27u
#define CLAIM_SHARD_RESOLUTION 28u
#define CLAIM_ARCH_CONTRACT 29u
#define CLAIM_QUANT_CONTRACT 30u
#define CLAIM_TOKENIZER_CONTRACT 31u
#define CLAIM_TEMPLATE_EOG_CONTRACT 32u
#define CLAIM_TENSOR_SCHEMA 33u
#define CLAIM_DEEP2_SESSION_CREATE 34u
#define CLAIM_DEEP2_SESSION_READY 35u
#define CLAIM_REQUEST_ACCEPTED 36u
#define CLAIM_REQUEST_ROUTED 37u
#define CLAIM_TOKENIZE_COMPLETE 38u
#define CLAIM_PREFILL_ENTRY 39u
#define CLAIM_PREFILL_COMPLETE 40u
#define CLAIM_GENERATE_STREAM_ENTRY 41u
#define CLAIM_DECODE_STEP_ENTRY 42u
#define CLAIM_FORWARD_COMPLETE 43u
#define CLAIM_SAMPLE_COMPLETE 44u
#define CLAIM_TOKEN_CALLBACK 45u
#define CLAIM_TOKEN_DECODED 46u
#define CLAIM_UI_STREAM_APPEND 47u
#define CLAIM_UI_STREAM_FINALIZE 48u
#define CLAIM_END_REASON 49u
#define CLAIM_CANCEL_REQUEST 50u
#define CLAIM_CANCEL_COMPLETE 51u
#define CLAIM_STREAM_ERROR 52u
#define CLAIM_DEVICE_SELECTED 53u
#define CLAIM_DEVICE_EXECUTION 54u
#define CLAIM_WEIGHT_RANGE_READY 55u
#define CLAIM_KV_HOTSET_READY 56u
#define CLAIM_RESIDENCY_RELEASE 57u
#define CLAIM_RELOAD_ENTRY 58u
#define CLAIM_RELOAD_COMPLETE 59u
#define CLAIM_AGENT_LOOP_ENTRY 60u
#define CLAIM_AGENT_PLAN_READY 61u
#define CLAIM_AGENT_MODEL_RETURN 62u
#define CLAIM_TOOL_DISPATCH 63u
#define CLAIM_TOOL_COMPLETE 64u
#define CLAIM_FILE_READ 65u
#define CLAIM_FILE_WRITE 66u
#define CLAIM_EDIT_APPLIED 67u
#define CLAIM_UNDO_APPLIED 68u
#define CLAIM_TERMINAL_ENTRY 69u
#define CLAIM_TERMINAL_COMPLETE 70u
#define CLAIM_BUILD_ENTRY 71u
#define CLAIM_BUILD_COMPLETE 72u
#define CLAIM_TEST_ENTRY 73u
#define CLAIM_TEST_COMPLETE 74u
#define CLAIM_DEBUG_ENTRY 75u
#define CLAIM_DEBUG_STOP 76u
#define CLAIM_LSP_REQUEST 77u
#define CLAIM_LSP_RESULT 78u
#define CLAIM_GIT_ENTRY 79u
#define CLAIM_GIT_COMPLETE 80u
#define CLAIM_MCP_DISPATCH 81u
#define CLAIM_MCP_COMPLETE 82u
#define CLAIM_EXTENSION_DISPATCH 83u
#define CLAIM_EXTENSION_COMPLETE 84u
#define CLAIM_LOCAL_SERVER_REQUEST 85u
#define CLAIM_LOCAL_SERVER_RESPONSE 86u
#define CLAIM_SETTINGS_PERSIST 87u
#define CLAIM_SESSION_PERSIST 88u
#define CLAIM_AGENT_RESUME 89u
#define CLAIM_AGENT_COMPLETE 90u
#define CLAIM_MODEL_UNLOAD_ENTRY 91u
#define CLAIM_MODEL_UNLOAD_COMPLETE 92u
#define CLAIM_IDE_EXIT_ENTRY 93u
#define CLAIM_IDE_EXIT_COMPLETE 94u
#define CLAIM_PROCESS_FAULT 95u
#define CLAIM_E2E_PRODUCT_COMPLETE 96u

int EvidenceEmitIDEBootEntry(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitIDEWindowReady(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitCoreInitComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitWorkspaceOpen(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitSessionRestore(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitBackendSelected(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitModelDiscovery(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitModelIdentity(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitModelLoadEntry(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitModelLoadComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitShardResolution(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitArchContract(EvidenceState512* s, uint64_t arg0, uint64_t arg1, uint32_t passBool);
int EvidenceEmitQuantContract(EvidenceState512* s, uint64_t arg0, uint64_t arg1, uint32_t passBool);
int EvidenceEmitTokenizerContract(EvidenceState512* s, uint64_t arg0, uint64_t arg1, uint32_t passBool);
int EvidenceEmitTemplateEogContract(EvidenceState512* s, uint64_t arg0, uint64_t arg1, uint32_t passBool);
int EvidenceEmitTensorSchema(EvidenceState512* s, uint64_t arg0, uint64_t arg1, uint32_t passBool);
int EvidenceEmitDeep2SessionCreate(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitDeep2SessionReady(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitRequestAccepted(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitRequestRouted(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitTokenizeComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitPrefillEntry(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitPrefillComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitGenerateStreamEntry(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitDecodeStepEntry(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitForwardComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitSampleComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitTokenCallback(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitTokenDecoded(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitUIStreamAppend(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitUIStreamFinalize(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitEndReason(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitCancelRequest(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitCancelComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitStreamError(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitDeviceSelected(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitDeviceExecution(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitWeightRangeReady(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitKVHotsetReady(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitResidencyRelease(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitReloadEntry(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitReloadComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitAgentLoopEntry(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitAgentPlanReady(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitAgentModelReturn(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitToolDispatch(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitToolComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitFileRead(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitFileWrite(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitEditApplied(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitUndoApplied(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitTerminalEntry(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitTerminalComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitBuildEntry(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitBuildComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitTestEntry(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitTestComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitDebugEntry(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitDebugStop(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitLSPRequest(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitLSPResult(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitGitEntry(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitGitComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitMCPDispatch(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitMCPComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitExtensionDispatch(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitExtensionComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitLocalServerRequest(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitLocalServerResponse(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitSettingsPersist(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitSessionPersist(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitAgentResume(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitAgentComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitModelUnloadEntry(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitModelUnloadComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitIDEExitEntry(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitIDEExitComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitProcessFault(EvidenceState512* s, uint64_t arg0, uint64_t arg1);
int EvidenceEmitE2EProductComplete(EvidenceState512* s, uint64_t arg0, uint64_t arg1);

int EvidenceSummarizeIDE512(EvidenceState512* s, EvidenceIDESummary512* out);
const EvidenceRecord512* EvidenceFindIDEClaim512(EvidenceState512* s, uint32_t claimId);
uint64_t EvidenceCopyIDECommitted512(EvidenceState512* s, EvidenceRecord512* dst, uint64_t dstCapacity);

#ifdef __cplusplus
}
#endif

#if defined(__cplusplus)
static_assert(sizeof(EvidenceState512) == 48, "EvidenceState512 ABI");
static_assert(sizeof(EvidenceRecord512) == 64, "EvidenceRecord512 ABI");
static_assert(sizeof(EvidenceIDESummary512) == 88, "EvidenceIDESummary512 ABI");
#endif
