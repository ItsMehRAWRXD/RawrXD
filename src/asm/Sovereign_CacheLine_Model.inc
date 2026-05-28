; ==============================================================================
; Sovereign_CacheLine_Model.inc - False Sharing Elimination Layer
; ==============================================================================
; Eliminates false sharing among hot properties by enforcing precise memory bounds.
; Modern CPUs utilize a 64-byte cache line structure. Variables heavily accessed
; by multithreaded or SIMD workloads must be isolated.

CACHE_ALIGN MACRO
    ALIGN 64
ENDM

ISOLATED_QWORD MACRO name, value
    ALIGN 64
    name DQ value
    ORG $ + 56 ; Pad out the remainder of the 64-byte cache line
ENDM

ISOLATED_DWORD MACRO name, value
    ALIGN 64
    name DD value
    ORG $ + 60
ENDM

ISOLATED_STRUCT MACRO name, struct_type
    ALIGN 64
    name struct_type <>
ENDM
