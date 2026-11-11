; RuntimeEvidence512_IDEEmit.asm
; x64 MASM / ml64.exe
; Zero CRT. Zero third-party dependencies.
;
; Adds claim-specific IDE/product emitters for ClaimId 18..96.
; It DOES NOT export a generic emitter.
; It shares the landed EvidenceState/EvidenceRecord ABI and can write into the
; same caller-owned buffer as RuntimeEvidence512_Core/Emit.
;
; ABI for fixed-status emitters:
;   rcx = EvidenceState*
;   rdx = Arg0
;   r8  = Arg1
;
; ABI for BOOL emitters:
;   rcx = EvidenceState*
;   rdx = Arg0
;   r8  = Arg1
;   r9d = bool (normalized to status FALSE/TRUE)
;
; Runtime law:
;   - SeqCap MUST equal 512.
;   - Capacity exhaustion increments Dropped and emits no fake record.
;   - Payload is written before Commit.
;   - Commit is published LAST via XCHG.
;   - Each public export owns one ClaimId.
;
; Build:
;   ml64 /nologo /c /FoRuntimeEvidence512_IDEEmit.obj RuntimeEvidence512_IDEEmit.asm

OPTION CASEMAP:NONE
INCLUDE RuntimeEvidence512_IDEClaims.inc

EVS_BUFFER          EQU 0
EVS_CAPACITY        EQU 8
EVS_WRITE_INDEX     EQU 16
EVS_DROPPED         EQU 24
EVS_RUN_ID          EQU 32
EVS_SEQ_CAP         EQU 40

.code

; PRIVATE. Never PUBLIC.
; rcx=state, rdx=Arg0, r8=Arg1, r9d=Status, r10d=ClaimId
EvidenceIDEEmitCore512 PROC
    test rcx, rcx
    jz   idec_fail
    cmp  dword ptr [rcx+EVS_SEQ_CAP], SEQ_CAP_REQUIRED
    jne  idec_fail

    mov  r11, qword ptr [rcx+EVS_BUFFER]
    test r11, r11
    jz   idec_fail
    cmp  qword ptr [rcx+EVS_CAPACITY], 0
    je   idec_fail

    mov  rax, 1
    lock xadd qword ptr [rcx+EVS_WRITE_INDEX], rax
    cmp  rax, qword ptr [rcx+EVS_CAPACITY]
    jb   idec_slot

    lock inc qword ptr [rcx+EVS_DROPPED]
    xor  eax, eax
    ret

idec_slot:
    shl  rax, 6
    add  r11, rax
    shr  rax, 6

    mov  qword ptr [r11+56], 0
    mov  dword ptr [r11+0],  EVREC_MAGIC
    mov  word  ptr [r11+4],  EVREC_VERSION
    mov  word  ptr [r11+6],  EVREC_BYTES
    mov  dword ptr [r11+8],  r10d
    mov  dword ptr [r11+12], r9d

    mov  r10, qword ptr [rcx+EVS_RUN_ID]
    mov  qword ptr [r11+16], r10
    mov  qword ptr [r11+24], rax

    mov  eax, dword ptr [rcx+EVS_SEQ_CAP]
    mov  dword ptr [r11+32], eax
    mov  dword ptr [r11+36], 0

    mov  qword ptr [r11+40], rdx
    mov  qword ptr [r11+48], r8

    mov  rax, EVREC_COMMIT
    xchg qword ptr [r11+56], rax

    mov  eax, 1
    ret

idec_fail:
    xor  eax, eax
    ret
EvidenceIDEEmitCore512 ENDP

IDE_EMITTER_FIXED MACRO ProcName:req, ClaimId:req, FixedStatus:req
PUBLIC ProcName
ProcName PROC
    mov  r9d, FixedStatus
    mov  r10d, ClaimId
    jmp  EvidenceIDEEmitCore512
ProcName ENDP
ENDM

IDE_EMITTER_BOOL MACRO ProcName:req, ClaimId:req
PUBLIC ProcName
ProcName PROC
    test r9d, r9d
    setnz al
    movzx r9d, al
    mov  r10d, ClaimId
    jmp  EvidenceIDEEmitCore512
ProcName ENDP
ENDM

IDE_EMITTER_FIXED EvidenceEmitIDEBootEntry, CLAIM_IDE_BOOT_ENTRY, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitIDEWindowReady, CLAIM_IDE_WINDOW_READY, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitCoreInitComplete, CLAIM_CORE_INIT_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitWorkspaceOpen, CLAIM_WORKSPACE_OPEN, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitSessionRestore, CLAIM_SESSION_RESTORE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitBackendSelected, CLAIM_BACKEND_SELECTED, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitModelDiscovery, CLAIM_MODEL_DISCOVERY, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitModelIdentity, CLAIM_MODEL_IDENTITY, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitModelLoadEntry, CLAIM_MODEL_LOAD_ENTRY, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitModelLoadComplete, CLAIM_MODEL_LOAD_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitShardResolution, CLAIM_SHARD_RESOLUTION, EV_STATUS_COMPLETE
IDE_EMITTER_BOOL  EvidenceEmitArchContract, CLAIM_ARCH_CONTRACT
IDE_EMITTER_BOOL  EvidenceEmitQuantContract, CLAIM_QUANT_CONTRACT
IDE_EMITTER_BOOL  EvidenceEmitTokenizerContract, CLAIM_TOKENIZER_CONTRACT
IDE_EMITTER_BOOL  EvidenceEmitTemplateEogContract, CLAIM_TEMPLATE_EOG_CONTRACT
IDE_EMITTER_BOOL  EvidenceEmitTensorSchema, CLAIM_TENSOR_SCHEMA
IDE_EMITTER_FIXED EvidenceEmitDeep2SessionCreate, CLAIM_DEEP2_SESSION_CREATE, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitDeep2SessionReady, CLAIM_DEEP2_SESSION_READY, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitRequestAccepted, CLAIM_REQUEST_ACCEPTED, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitRequestRouted, CLAIM_REQUEST_ROUTED, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitTokenizeComplete, CLAIM_TOKENIZE_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitPrefillEntry, CLAIM_PREFILL_ENTRY, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitPrefillComplete, CLAIM_PREFILL_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitGenerateStreamEntry, CLAIM_GENERATE_STREAM_ENTRY, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitDecodeStepEntry, CLAIM_DECODE_STEP_ENTRY, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitForwardComplete, CLAIM_FORWARD_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitSampleComplete, CLAIM_SAMPLE_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitTokenCallback, CLAIM_TOKEN_CALLBACK, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitTokenDecoded, CLAIM_TOKEN_DECODED, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitUIStreamAppend, CLAIM_UI_STREAM_APPEND, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitUIStreamFinalize, CLAIM_UI_STREAM_FINALIZE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitEndReason, CLAIM_END_REASON, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitCancelRequest, CLAIM_CANCEL_REQUEST, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitCancelComplete, CLAIM_CANCEL_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitStreamError, CLAIM_STREAM_ERROR, EV_STATUS_ABORT
IDE_EMITTER_FIXED EvidenceEmitDeviceSelected, CLAIM_DEVICE_SELECTED, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitDeviceExecution, CLAIM_DEVICE_EXECUTION, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitWeightRangeReady, CLAIM_WEIGHT_RANGE_READY, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitKVHotsetReady, CLAIM_KV_HOTSET_READY, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitResidencyRelease, CLAIM_RESIDENCY_RELEASE, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitReloadEntry, CLAIM_RELOAD_ENTRY, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitReloadComplete, CLAIM_RELOAD_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitAgentLoopEntry, CLAIM_AGENT_LOOP_ENTRY, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitAgentPlanReady, CLAIM_AGENT_PLAN_READY, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitAgentModelReturn, CLAIM_AGENT_MODEL_RETURN, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitToolDispatch, CLAIM_TOOL_DISPATCH, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitToolComplete, CLAIM_TOOL_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitFileRead, CLAIM_FILE_READ, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitFileWrite, CLAIM_FILE_WRITE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitEditApplied, CLAIM_EDIT_APPLIED, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitUndoApplied, CLAIM_UNDO_APPLIED, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitTerminalEntry, CLAIM_TERMINAL_ENTRY, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitTerminalComplete, CLAIM_TERMINAL_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitBuildEntry, CLAIM_BUILD_ENTRY, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitBuildComplete, CLAIM_BUILD_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitTestEntry, CLAIM_TEST_ENTRY, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitTestComplete, CLAIM_TEST_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitDebugEntry, CLAIM_DEBUG_ENTRY, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitDebugStop, CLAIM_DEBUG_STOP, EV_STATUS_OBSERVED
IDE_EMITTER_FIXED EvidenceEmitLSPRequest, CLAIM_LSP_REQUEST, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitLSPResult, CLAIM_LSP_RESULT, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitGitEntry, CLAIM_GIT_ENTRY, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitGitComplete, CLAIM_GIT_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitMCPDispatch, CLAIM_MCP_DISPATCH, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitMCPComplete, CLAIM_MCP_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitExtensionDispatch, CLAIM_EXTENSION_DISPATCH, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitExtensionComplete, CLAIM_EXTENSION_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitLocalServerRequest, CLAIM_LOCAL_SERVER_REQUEST, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitLocalServerResponse, CLAIM_LOCAL_SERVER_RESPONSE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitSettingsPersist, CLAIM_SETTINGS_PERSIST, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitSessionPersist, CLAIM_SESSION_PERSIST, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitAgentResume, CLAIM_AGENT_RESUME, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitAgentComplete, CLAIM_AGENT_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitModelUnloadEntry, CLAIM_MODEL_UNLOAD_ENTRY, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitModelUnloadComplete, CLAIM_MODEL_UNLOAD_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitIDEExitEntry, CLAIM_IDE_EXIT_ENTRY, EV_STATUS_ENTER
IDE_EMITTER_FIXED EvidenceEmitIDEExitComplete, CLAIM_IDE_EXIT_COMPLETE, EV_STATUS_COMPLETE
IDE_EMITTER_FIXED EvidenceEmitProcessFault, CLAIM_PROCESS_FAULT, EV_STATUS_FAULT
IDE_EMITTER_FIXED EvidenceEmitE2EProductComplete, CLAIM_E2E_PRODUCT_COMPLETE, EV_STATUS_COMPLETE

END
