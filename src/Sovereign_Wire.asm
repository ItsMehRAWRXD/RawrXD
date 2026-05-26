; Sovereign_Wire.asm ? Production
SOVEREIGN_WIRE_MODULE equ 1
; Sovereign_Wire.asm ? gRPC and Varint Engine
; x64 MASM | NO DEPS | Performance Hardened
include Sovereign_Common.inc
.code

; -----------------------------------------------------------------------------
; Varint_Decode (LEB128)
; RCX: Pointer to encoded byte stream
; Returns: RAX = Decoded value, RCX = Updated pointer
; -----------------------------------------------------------------------------
PUBLIC Varint_Decode
Varint_Decode PROC
    xor     rax, rax          ; Accumulator
    xor     r8, r8            ; Shift = 0
    
@loop:
    movzx   rdx, byte ptr [rcx]
    inc     rcx
    
    mov     r9, rdx
    and     r9, 7Fh           ; Mask payload
    
    ; Shift r9 by r8 (0, 7, 14...)
    push    rcx               ; Preserve RCX
    mov     cl, r8b
    shl     r9, cl
    pop     rcx               ; Restore RCX
    
    or      rax, r9
    
    test    rdx, 80h
    jz      @done
    
    add     r8, 7
    cmp     r8, 63            ; Max safe shift for 64-bit
    jbe     @loop
    
@done:
    ret
Varint_Decode ENDP

; -----------------------------------------------------------------------------
; GRPC_Encode_Header
; RCX: Pointer to output buffer
; RDX: Message length (DWORD)
; -----------------------------------------------------------------------------
PUBLIC GRPC_Encode_Header
GRPC_Encode_Header PROC
    ; 1. Byte Flag (0 for data)
    mov byte ptr [rcx], 0
    
    ; 2. Length (Big-Endian)
    mov eax, edx
    bswap eax               ; Convert Little-Endian to Big-Endian
    mov [rcx + 1], eax      ; Write 4 bytes at offset 1
    
    lea rax, [rcx + 5]      ; Return pointer to payload start
    ret
GRPC_Encode_Header ENDP
end
