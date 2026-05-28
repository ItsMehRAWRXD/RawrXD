; ==================================================================================
; SOVEREIGN GGUF SCHEMA RUNTIME
; File: Sovereign_GGUF_Schema_Runtime.inc
; Role: GGUF Format Types, Offsets, and Layouts
; ==================================================================================

GGUF_MAGIC          EQU 046554747h

; GGUF Value Types
GGUF_TYPE_UINT8     EQU 0
GGUF_TYPE_INT8      EQU 1
GGUF_TYPE_UINT16    EQU 2
GGUF_TYPE_INT16     EQU 3
GGUF_TYPE_UINT32    EQU 4
GGUF_TYPE_INT32     EQU 5
GGUF_TYPE_FLOAT32   EQU 6
GGUF_TYPE_BOOL      EQU 7
GGUF_TYPE_STRING    EQU 8
GGUF_TYPE_ARRAY     EQU 9
GGUF_TYPE_UINT64    EQU 10
GGUF_TYPE_INT64     EQU 11
GGUF_TYPE_FLOAT64   EQU 12
