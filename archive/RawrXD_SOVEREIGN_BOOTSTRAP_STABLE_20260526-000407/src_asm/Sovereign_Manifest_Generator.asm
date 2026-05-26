; Sovereign_Manifest_Generator.asm - Binary Format Specification
; ABI: Standardized SOVN v1.0 Manifest Layout
; Purpose: Structural definition and generation of the binary graph manifest

.CONST
SOVN_MAGIC         EQU 0534F564Eh ; "SOVN"
NODE_SIZE          EQU 48         ; 64-bit aligned XR_Binary_Node size

.DATA
; The binary graph manifest represents a strictly contiguous memory-mapped 
; array of nodes. The structure is designed for direct casting into the 
; XR_Binary_Node layout for zero-copy hydration.

PUBLIC test_graph_binary
align 16
test_graph_binary:
    ; --- Header ---
    dd SOVN_MAGIC                 ; Magic Number
    dd 3                          ; Node Count
    dq 0                          ; Entry Point (Root)

    ; --- Node Registry (Linearized) ---
    ; Node 0: Input Transformation
    dq 0000000000001000h          ; Kernel Offset
    dq 10000000                   ; Deadline (TSC)
    dd 0                          ; State Flags
    dd 0                          ; Reserved
    dq 0000000040000000h          ; OutputAddr (KV_Slot_A)
    dq 0000000000000000h          ; InputAddr (NULL/Root)

    ; Node 1: Attention Fusion
    dq 0000000000002000h          ; Kernel Offset
    dq 20000000                   ; Deadline
    dd 1                          ; State Flags (XR_NODE_FUSE_BIT set)
    dd 0                          ; Reserved
    dq 0000000040001000h          ; OutputAddr (KV_Slot_B)
    dq 0000000040000000h          ; InputAddr (KV_Slot_A)

    ; Node 2: Output Projection
    dq 0000000000003000h          ; Kernel Offset
    dq 15000000                   ; Deadline
    dd 0                          ; State Flags
    dd 0                          ; Reserved
    dq 0000000040002000h          ; OutputAddr (Final)
    dq 0000000040001000h          ; InputAddr (KV_Slot_B)

.CODE
; XR_Export_Manifest: Copies the manifest to the requested buffer
; RCX = DestinationBuffer
PUBLIC XR_Export_Manifest
XR_Export_Manifest PROC
    push rsi
    push rdi
    lea rsi, test_graph_binary
    mov rdi, rcx
    mov rcx, 160                  ; Total bytes: Header(16) + 3*Node(48) = 160
    rep movsb                     ; Atomic copy to target buffer
    pop rdi
    pop rsi
    ret
XR_Export_Manifest ENDP

; XR_Verify_Magic: Ensures the manifest adheres to the SOVN contract
; PUBLIC XR_Verify_Magic
XR_Verify_Magic PROC
    mov eax, [rcx]
    cmp eax, SOVN_MAGIC
    je valid
    mov eax, 0BADF00Dh
    ret
valid:
    mov eax, 0CAFEBABEh
    ret
XR_Verify_Magic ENDP

END
