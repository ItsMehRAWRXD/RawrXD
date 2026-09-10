; r25_productopen_masm.inc
; no-dep x64 MASM ProductOpen GGUF tensor proof ABI
; All output fields are caller-owned. No CRT. No heap.

option casemap:none

R25_PRODUCTOPEN_OK              EQU 0
R25_PRODUCTOPEN_ERR_ARG         EQU 1
R25_PRODUCTOPEN_ERR_OPEN        EQU 2
R25_PRODUCTOPEN_ERR_MAP         EQU 3
R25_PRODUCTOPEN_ERR_MAGIC       EQU 4
R25_PRODUCTOPEN_ERR_VERSION     EQU 5
R25_PRODUCTOPEN_ERR_BOUNDS      EQU 6
R25_PRODUCTOPEN_ERR_UNSUPPORTED EQU 7
R25_PRODUCTOPEN_ERR_TENSORS0    EQU 8
R25_PRODUCTOPEN_ERR_EMBED0      EQU 9
R25_PRODUCTOPEN_ERR_HEAD0       EQU 10

R25_GGUF_PROOF STRUCT
    status              QWORD ?
    version             QWORD ?
    tensor_count        QWORD ?
    kv_count            QWORD ?
    tensors_scanned     QWORD ?
    token_embed_found   QWORD ?
    lm_head_found       QWORD ?
    product_open        QWORD ?
    file_size           QWORD ?
    tensor_info_off     QWORD ?
R25_GGUF_PROOF ENDS

; No typed PROTO — PROC uses register ABI (rcx=path, rdx=proof).
R25_ProductOpenGguf PROTO
R25_CloseLastMapping PROTO
