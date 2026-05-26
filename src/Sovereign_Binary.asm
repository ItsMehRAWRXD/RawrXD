; Sovereign_Binary.asm
; Production-grade LEB128 Decoder (Protobuf/GGUF Metadata)
; RCX = In: Buffer Pointer, Out: Updated Buffer Pointer
; RAX = Out: Decoded 64-bit Value

.code
PUBLIC Sovereign_ReadVarint
Sovereign_ReadVarint proc
    xor rax, rax        ; Accumulator
    xor r8, r8          ; Shift amount (0, 7, 14...)
    
@next_byte:
    movzx r9, byte ptr [rcx]
    inc rcx
    
    mov r10, r9
    and r10, 7Fh        ; Mask 7 bits
    
    push rcx            ; Preserve RCX
    mov cl, r8b         ; RCX/CL used for shift
    shl r10, cl
    pop rcx             ; Restore RCX
    
    or  rax, r10        ; Merge into result
    
    test r9, 80h        ; MSB set?
    jz @done            ; No, termination byte reached
    
    add r8, 7           ; Next 7-bit chunk
    cmp r8, 64          ; Overflow safety
    jl @next_byte
    
@done:
    ret
Sovereign_ReadVarint endp
end
