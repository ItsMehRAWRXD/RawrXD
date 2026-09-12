option casemap:none

SS_OK                       equ 0
SS_E_INVALID                equ 20
SS_E_OPEN                   equ 21
SS_E_SIZE                   equ 22
SS_E_READ                   equ 23
SS_E_RANGE                  equ 24
SS_E_FORMAT                 equ 25
SS_E_NOT_FOUND              equ 26
SS_E_OVERFLOW               equ 27
SS_E_BACKEND                equ 28
SS_E_GPU_PROOF              equ 29
SS_E_DEEP2_INTEROP          equ 100
SS_E_PRIMITIVE_HOLD         equ 102
SS_E_LOGITS_HOLD            equ 103
SS_E_LMHEAD_HOLD            equ 104
SS_E_OUTPUT_NORM_HOLD       equ 105
SS_DEEP2_IMPORTED           equ 2
SS_DEEP2_CONSUMED           equ 3
SS_DEEP2_MODEL_OP           equ 4
SS_DEEP2_BLOCK_OP           equ 5

SS_PROVIDER_FILE            equ 1
SS_PROVIDER_MEM             equ 2

SS_DEEP2_CONSUME_NOT_RUN    equ 1
SS_TOKEN_COMMIT_NOT_RUN     equ 1

GENERIC_READ                equ 80000000h
FILE_SHARE_READ             equ 00000001h
OPEN_EXISTING               equ 3
FILE_ATTRIBUTE_NORMAL       equ 00000080h
INVALID_HANDLE_VALUE        equ -1
FILE_BEGIN                  equ 0

MEM_COMMIT                  equ 00001000h
MEM_RESERVE                 equ 00002000h
MEM_RELEASE                 equ 00008000h
PAGE_READWRITE              equ 04h

SSFileCtx STRUCT
    handle                   QWORD ?
    file_bytes               QWORD ?
SSFileCtx ENDS

SSMemCtx STRUCT
    base                     QWORD ?
    bytes                    QWORD ?
SSMemCtx ENDS

SSProviderRef STRUCT
    kind                     DWORD ?
    reserved                 DWORD ?
    ctx                      QWORD ?
SSProviderRef ENDS

SSTensorDesc STRUCT
    found                    QWORD ?
    which_name               QWORD ?
    relative_offset          QWORD ?
    absolute_offset          QWORD ?
    storage_bytes            QWORD ?
    element_count            QWORD ?
    data_base                QWORD ?
    alignment                QWORD ?
    tensor_type              DWORD ?
    n_dims                   DWORD ?
    dim0                     QWORD ?
    dim1                     QWORD ?
SSTensorDesc ENDS

SSDeviceMaterialization STRUCT
    completed                QWORD ?
    gpu                      QWORD ?
    readback_parity          QWORD ?
    device_id                QWORD ?
    allocation_generation    QWORD ?
    device_handle            QWORD ?
    bytes                    QWORD ?
    pci_device               QWORD ?
    tensor_type              QWORD ?
    dim0                     QWORD ?
    dim1                     QWORD ?
    which_name               QWORD ?
    element_count            QWORD ?
SSDeviceMaterialization ENDS

; First-party device backend bridge.
; promote_fn ABI:
;   int fn(ctx, host_ptr, bytes, source_residency_generation, out_materialization)
; release_fn ABI:
;   int fn(ctx, device_handle, allocation_generation)
; consume_fn ABI:
;   int fn(ctx, SSDeviceMaterialization*)
;   2=import 3=consume 4=imported model op
SSGpuBackend STRUCT
    ctx                      QWORD ?
    promote_fn               QWORD ?
    release_fn               QWORD ?
    consume_fn               QWORD ?
SSGpuBackend ENDS

SSPhaseArgs STRUCT
    shard1_path              QWORD ?
    model_id                 QWORD ?
    model_generation         QWORD ?
    op_ticket                QWORD ?
    owner_cookie             QWORD ?
    host_budget              QWORD ?
    gpu_budget               QWORD ?
    gpu_backend              QWORD ?
SSPhaseArgs ENDS

SSPhaseResult STRUCT
    phase_rc                 QWORD ?
    full_model_init_bypassed QWORD ?
    gguf_anchor_found        QWORD ?
    anchor_which             QWORD ?
    file_offset              QWORD ?
    region_bytes             QWORD ?
    warm_pass                QWORD ?
    hot_pass                 QWORD ?
    gpu                      QWORD ?
    pci_device               QWORD ?
    readback_parity          QWORD ?
    physical_reads           QWORD ?
    physical_bytes           QWORD ?
    mg_loads                 QWORD ?
    mg_bytes                 QWORD ?
    hot_hits                 QWORD ?
    deep2_consume_status     QWORD ?
    token_commit_status      QWORD ?
SSPhaseResult ENDS

ss_file_open PROTO
ss_file_close PROTO
ss_file_read_exact PROTO

ss_mem_init PROTO
ss_mem_read_exact PROTO

ss_provider_read_exact PROTO

ss_gguf_find_tensor2 PROTO
ss_find_anchor_tensor PROTO

ss_product_split_phase PROTO
