option casemap:none

OWNER_FREE          EQU 0
OWNER_HOST          EQU 1
OWNER_K3C           EQU 2
OWNER_TRANSIT       EQU 0FFFFFFFEh

CHAIR_FREE          EQU 0
CHAIR_PREFETCH      EQU 1
CHAIR_RESIDENT      EQU 2
CHAIR_CONSUMING     EQU 3
CHAIR_RELEASED      EQU 4

KN_OK               EQU 0
KN_E_NULL           EQU 1
KN_E_CAPACITY       EQU 2
KN_E_OWNER          EQU 3
KN_E_GENERATION     EQU 4
KN_E_RELEASE        EQU 5
KN_E_CLOCK          EQU 6

KN_CHAIR STRUCT
    owner           DWORD ?
    state           DWORD ?
    generation      QWORD ?
    object_id       QWORD ?
    bytes           QWORD ?
    capacity        QWORD ?
    data_ptr        QWORD ?
KN_CHAIR ENDS

KN_VENTI STRUCT
    source_ptr      QWORD ?
    bytes           QWORD ?

    chair_ptr       QWORD ?
    object_id       QWORD ?
    generation      QWORD ?

    owner_from      DWORD ?
    owner_to        DWORD ?

    consumer_ptr    QWORD ?
    consumer_ctx    QWORD ?

    qpf_hz          QWORD ?

    token_start_qpc QWORD ?
    prefetch_qpc    QWORD ?
    ready_qpc       QWORD ?
    handoff_qpc     QWORD ?
    consume_qpc     QWORD ?
    release_qpc     QWORD ?

    prefetch_ns     QWORD ?
    handoff_ns      QWORD ?
    consume_ns      QWORD ?
    token_wall_ns   QWORD ?

    token_receipt   QWORD ?
    status          DWORD ?
    reserved        DWORD ?
KN_VENTI ENDS

KN_O3KKEN PROTO
KN_TicksToNs PROTO
