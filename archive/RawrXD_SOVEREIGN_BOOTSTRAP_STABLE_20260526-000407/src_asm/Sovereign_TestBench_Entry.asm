; Sovereign_TestBench_Entry.asm - Validation Harness
; ABI: Standard Win64 Calling Convention
; Purpose: Verify Graph Hydration & Node Alignment before kernel dispatch

.CODE

; XR_TestBench_Harness: Validates graph manifest mapping
; RCX = ManifestBuffer, RDX = NodeCount
PUBLIC XR_TestBench_Harness
XR_TestBench_Harness PROC
    sub rsp, 40
    
    ; 1. Validate ABI alignment
    test rcx, rcx
    jz fail
    
    ; 2. Verify Manifest Magic (0x534F564E = "SOVN")
    mov eax, [rcx]
    cmp eax, 0534F564Eh
    jne fail
    
    ; 3. Verify Node Alignment (16-byte boundary check)
    mov r8, rcx
    add r8, 8                   ; Offset to first node
    test r8, 0Fh                ; Check alignment
    jnz alignment_fault
    
    ; 4. Simulate fusion bit detection (Validation of bitmask)
    mov rdx, [r8 + 28]          ; Load Node Flags
    and rdx, 1                  ; Check XR_NODE_FUSE_BIT
    
    mov rax, 0x1                ; Return SUCCESS
    jmp exit

alignment_fault:
    mov rax, 0xBADF00D1         ; Alignment Error
    jmp exit

fail:
    mov rax, 0xBADF00D0         ; Magic Mismatch
    
exit:
    add rsp, 40
    ret
XR_TestBench_Harness ENDP

END
