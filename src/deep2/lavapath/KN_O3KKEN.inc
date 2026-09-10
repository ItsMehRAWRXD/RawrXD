option casemap:none

KN_OK                  EQU 1
KN_ERR_NULL            EQU -1
KN_ERR_OBJECT          EQU -2
KN_ERR_GENERATION      EQU -3
KN_ERR_BUSY            EQU -4
KN_ERR_OWNER           EQU -5
KN_ERR_NOT_READY       EQU -6
KN_ERR_PREFETCH        EQU -7
KN_ERR_CONSUMER        EQU -8
KN_ERR_CLOCK           EQU -9

KN_STATE_READY         EQU 0000000000000001h
KN_STATE_HANDED_OFF    EQU 0000000000000002h
KN_STATE_CONSUMED      EQU 0000000000000004h
KN_STATE_FAILED        EQU 0000000000000008h
KN_BUSY_BIT            EQU 63

KN_FLAG_PREFETCH_HOST  EQU 0000000000000001h

KN_CHAIR STRUCT
    object_id          QWORD ?
    generation         QWORD ?
    owner              QWORD ?
    state              QWORD ?
    payload_ptr        QWORD ?
    payload_bytes      QWORD ?
    ready_qpc          QWORD ?
KN_CHAIR ENDS

KN_VENTI STRUCT
    chair_ptr          QWORD ?
    object_id          QWORD ?
    generation         QWORD ?
    owner_from         QWORD ?
    owner_to           QWORD ?
    consumer_fn        QWORD ?
    src_ptr            QWORD ?
    copy_bytes         QWORD ?
    need_qpc           QWORD ?
    flags              QWORD ?
KN_VENTI ENDS

KN_RECEIPT STRUCT
    status             QWORD ?
    result             QWORD ?
    start_qpc          QWORD ?
    ready_qpc          QWORD ?
    handoff_qpc        QWORD ?
    consumer_start_qpc QWORD ?
    consumer_end_qpc   QWORD ?
    commit_qpc         QWORD ?
    qpc_freq           QWORD ?
    token_wall_ns      QWORD ?
    exposed_wait_ns    QWORD ?
    object_id          QWORD ?
    generation         QWORD ?
    owner_to           QWORD ?
KN_RECEIPT ENDS

KN_O3KKEN PROTO
