option casemap:none

USR_OK                     equ 0
USR_E_INVALID              equ 1
USR_E_STALE                equ 2
USR_E_BUSY                 equ 3
USR_E_DUP                  equ 4
USR_E_RANGE                equ 5
USR_E_BUDGET               equ 6
USR_E_STATE                equ 7
USR_E_TIMEOUT              equ 8
USR_E_PARTIAL_ALIAS        equ 9

USR_COLD                   equ 0
USR_MG_IN_PROGRESS         equ 1
USR_WARM                   equ 2
USR_HOT                    equ 3

USR_REQ_CURRENT_STATIC     equ 1
USR_REQ_DYNAMIC_OBSERVED   equ 2
USR_REQ_DEVICE_PROMOTION   equ 3

USR_PREP_CLAIM_WIN         equ 10
USR_PREP_JOIN              equ 11
USR_PREP_WARM_HIT          equ 12
USR_PREP_HOT_HIT           equ 13

USRContext STRUCT
    current_model_id          QWORD ?
    current_model_generation  QWORD ?
    current_op_ticket         QWORD ?
    current_owner             QWORD ?
    current_epoch             QWORD ?
    dynamic_ticket            QWORD ?
    dynamic_cookie            QWORD ?
    host_budget               QWORD ?
    host_used                 QWORD ?
    gpu_budget                QWORD ?
    gpu_used                  QWORD ?
    stale_request_rejects     QWORD ?
    speculative_rejects       QWORD ?
    batch_validations         QWORD ?
    batch_rejects             QWORD ?
    model_switches            QWORD ?
USRContext ENDS

USRRegion STRUCT
    model_id                  QWORD ?
    model_generation          QWORD ?
    region_id                 QWORD ?
    provider_id               QWORD ?
    file_offset               QWORD ?
    byte_length               QWORD ?
    state                     DWORD ?
    request_reason            DWORD ?
    residency_generation      QWORD ?
    pin_count                 QWORD ?
    host_ptr                  QWORD ?
    host_bytes                QWORD ?
    device_handle             QWORD ?
    device_id                 QWORD ?
    device_alloc_generation   QWORD ?
    waiters                   QWORD ?
    joins                     QWORD ?
    mg_claim_winners          QWORD ?
    duplicate_first_touch     QWORD ?
    physical_reads            QWORD ?
    physical_bytes            QWORD ?
    mg_loads                  QWORD ?
    mg_bytes                  QWORD ?
    warm_hits                 QWORD ?
    hot_hits                  QWORD ?
    evictions                 QWORD ?
    stale_generation_faults   QWORD ?
    alias_hits                QWORD ?
    alias_partial_rejects     QWORD ?
    gpu_copy_bytes            QWORD ?
    gpu_uploads               QWORD ?
    duplicate_gpu_uploads     QWORD ?
USRRegion ENDS

USRHotIdentity STRUCT
    model_id                  QWORD ?
    model_generation          QWORD ?
    region_id                 QWORD ?
    residency_generation      QWORD ?
    device_id                 QWORD ?
    allocation_generation     QWORD ?
    device_handle             QWORD ?
    byte_length               QWORD ?
USRHotIdentity ENDS

USRReceipt STRUCT
    pass                      QWORD ?
    mg_bytes                  QWORD ?
    physical_bytes            QWORD ?
    physical_reads            QWORD ?
    mg_loads                  QWORD ?
    duplicate_first_touch     QWORD ?
    stale_generation_faults   QWORD ?
USRReceipt ENDS

usr_ctx_init PROTO
usr_begin_op PROTO
usr_end_op PROTO
usr_switch_model PROTO
usr_validate_current PROTO
usr_dynamic_observed PROTO
usr_validate_dynamic PROTO

usr_region_prepare PROTO
usr_commit_warm PROTO
usr_fail_mg PROTO
usr_join_wait PROTO
usr_pin PROTO
usr_unpin PROTO
usr_evict PROTO

usr_alias_acquire PROTO
usr_alias_release PROTO

usr_host_reserve PROTO
usr_host_release PROTO
usr_gpu_reserve PROTO
usr_gpu_release PROTO

usr_hot_commit PROTO
usr_hot_reset PROTO
usr_hot_identity PROTO

usr_batch_validate PROTO
usr_receipt_region PROTO
