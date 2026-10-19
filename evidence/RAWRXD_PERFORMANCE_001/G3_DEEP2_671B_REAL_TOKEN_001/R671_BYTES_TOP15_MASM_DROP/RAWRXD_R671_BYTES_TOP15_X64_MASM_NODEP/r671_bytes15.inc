option casemap:none

RB_NOT_RUN equ 0
RB_FAIL    equ 1
RB_PASS    equ 2

RB01_GENERATION_BOUND         equ 0
RB02_FILE_RANGE_VALID         equ 1
RB03_BYTE_LENGTH_NONZERO      equ 2
RB04_LEASE_ACTIVE             equ 3
RB05_LEASE_OFFSET_MATCH       equ 4
RB06_LEASE_BYTE_COVERAGE      equ 5
RB07_POINTER_PROVENANCE       equ 6
RB08_MAPPING_BOUND            equ 7
RB09_EXACT_BYTE_CONSUMPTION   equ 8
RB10_NO_FAILED_ACQUIRE        equ 9
RB11_NO_FULL_TENSOR_FALLBACK  equ 10
RB12_CHECKSUM_OBSERVED        equ 11
RB13_NONFINITE_FREE           equ 12
RB14_RELEASE_CLOSURE          equ 13
RB15_AUTH_DERIVATION          equ 14

RB_WITNESS_COUNT              equ 15

R671BytesRaw STRUCT
    generation_id              QWORD ?
    lease_generation_id        QWORD ?

    file_bytes                 QWORD ?
    file_offset                QWORD ?
    requested_bytes            QWORD ?

    lease_active               QWORD ?
    lease_request_offset       QWORD ?
    lease_bytes                QWORD ?
    lease_ptr                  QWORD ?
    lease_view_base            QWORD ?
    lease_delta                QWORD ?
    lease_view_bytes           QWORD ?

    configured_mapped_bound    QWORD ?
    mapped_bytes_live          QWORD ?

    primitive_bytes_consumed   QWORD ?
    acquire_count              QWORD ?
    failed_acquires            QWORD ?
    full_tensor_fallback_count QWORD ?

    checksum_u64               QWORD ?
    checksum_observed          QWORD ?
    nonfinite_count            QWORD ?

    release_count              QWORD ?
    live_leases_after_release  QWORD ?

    run_observed               QWORD ?
R671BytesRaw ENDS

R671BytesResult STRUCT
    witness_state              QWORD RB_WITNESS_COUNT dup(?)
    pass_count                 QWORD ?
    fail_count                 QWORD ?
    notrun_count               QWORD ?
    bytes_authorized           QWORD ?
R671BytesResult ENDS

R671BytesEvaluate PROTO
