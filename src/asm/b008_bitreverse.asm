;=============================================================================
; B008 Bit-Reversal Runtime
; Transforms 800B (hex) -> B008 (hex) at register level
; Zero-dependency x64 MASM for tensor header indexing
;=============================================================================

;-----------------------------------------------------------------------------
; Section: Code
;-----------------------------------------------------------------------------
.code

;=============================================================================
; Reverse16Bit
; Input:  CX = 16-bit value (e.g., 0x800B)
; Output: AX = Reversed value (e.g., 0xB008)
; Clobbers: CX, BX
; Flags: Preserved except CF
;=============================================================================
Reverse16Bit PROC
    mov     ax, 0           ; Clear result register
    mov     bx, 16          ; Loop counter (16 bits to reverse)

.loop:
    shr     cx, 1           ; Shift LSB of source into Carry Flag
    rcr     ax, 1           ; Rotate Carry Flag into MSB of destination
    dec     bx              ; Decrement counter
    jnz     .loop           ; Continue until all bits processed
    
    ret
Reverse16Bit ENDP

;=============================================================================
; Reverse16Bit_Unrolled
; Unrolled version for hot paths - no loop overhead
; Input:  CX = 16-bit value
; Output: AX = Reversed value
;=============================================================================
Reverse16Bit_Unrolled PROC
    mov     ax, 0           ; Clear result
    
    ; Unrolled 16 iterations
    ; Each iteration: shift source right, rotate result right through carry
    
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    shr     cx, 1
    rcr     ax, 1
    
    ret
Reverse16Bit_Unrolled ENDP

;=============================================================================
; Reverse16Bit_Lookup
; Table-based O(1) version for maximum speed
; Input:  CX = 16-bit value
; Output: AX = Reversed value
;=============================================================================
.data
align 16
BitReverseTable BYTE \
    00h, 80h, 40h, 0C0h, 20h, 0A0h, 60h, 0E0h, \
    10h, 90h, 50h, 0D0h, 30h, 0B0h, 70h, 0F0h, \
    08h, 88h, 48h, 0C8h, 28h, 0A8h, 68h, 0E8h, \
    18h, 98h, 58h, 0D8h, 38h, 0B8h, 78h, 0F8h, \
    04h, 84h, 44h, 0C4h, 24h, 0A4h, 64h, 0E4h, \
    14h, 94h, 54h, 0D4h, 34h, 0B4h, 74h, 0F4h, \
    0Ch, 8Ch, 4Ch, 0CCh, 2Ch, 0ACh, 6Ch, 0ECh, \
    1Ch, 9Ch, 5Ch, 0DCh, 3Ch, 0BCh, 7Ch, 0FCh, \
    02h, 82h, 42h, 0C2h, 22h, 0A2h, 62h, 0E2h, \
    12h, 92h, 52h, 0D2h, 32h, 0B2h, 72h, 0F2h, \
    0Ah, 8Ah, 4Ah, 0CAh, 2Ah, 0AAh, 6Ah, 0EAh, \
    1Ah, 9Ah, 5Ah, 0DAh, 3Ah, 0BAh, 7Ah, 0FAh, \
    06h, 86h, 46h, 0C6h, 26h, 0A6h, 66h, 0E6h, \
    16h, 96h, 56h, 0D6h, 36h, 0B6h, 76h, 0F6h, \
    0Eh, 8Eh, 4Eh, 0CEh, 2Eh, 0AEh, 6Eh, 0EEh, \
    1Eh, 9Eh, 5Eh, 0DEh, 3Eh, 0BEh, 7Eh, 0FEh, \
    01h, 81h, 41h, 0C1h, 21h, 0A1h, 61h, 0E1h, \
    11h, 91h, 51h, 0D1h, 31h, 0B1h, 71h, 0F1h, \
    09h, 89h, 49h, 0C9h, 29h, 0A9h, 69h, 0E9h, \
    19h, 99h, 59h, 0D9h, 39h, 0B9h, 79h, 0F9h, \
    05h, 85h, 45h, 0C5h, 25h, 0A5h, 65h, 0E5h, \
    15h, 95h, 55h, 0D5h, 35h, 0B5h, 75h, 0F5h, \
    0Dh, 8Dh, 4Dh, 0CDh, 2Dh, 0ADh, 6Dh, 0EDh, \
    1Dh, 9Dh, 5Dh, 0DDh, 3Dh, 0BDh, 7Dh, 0FDh, \
    03h, 83h, 43h, 0C3h, 23h, 0A3h, 63h, 0E3h, \
    13h, 93h, 53h, 0D3h, 33h, 0B3h, 73h, 0F3h, \
    0Bh, 8Bh, 4Bh, 0CBh, 2Bh, 0ABh, 6Bh, 0EBh, \
    1Bh, 9Bh, 5Bh, 0DBh, 3Bh, 0BBh, 7Bh, 0FBh, \
    07h, 87h, 47h, 0C7h, 27h, 0A7h, 67h, 0E7h, \
    17h, 97h, 57h, 0D7h, 37h, 0B7h, 77h, 0F7h, \
    0Fh, 8Fh, 4Fh, 0CFh, 2Fh, 0AFh, 6Fh, 0EFh, \
    1Fh, 9Fh, 5Fh, 0DFh, 3Fh, 0BFh, 7Fh, 0FFh

.code

Reverse16Bit_Lookup PROC
    ; Split 16-bit value into two bytes
    movzx   eax, cl         ; Low byte
    movzx   edx, ch         ; High byte
    
    ; Look up reversed bytes
    movzx   eax, BYTE PTR [BitReverseTable + rax]
    movzx   edx, BYTE PTR [BitReverseTable + rdx]
    
    ; Combine: reversed high byte becomes low, reversed low becomes high
    shl     edx, 8          ; Shift reversed high byte to high position
    or      eax, edx        ; Combine with reversed low byte
    
    ret
Reverse16Bit_Lookup ENDP

;=============================================================================
; B008_TransformTensorID
; Transforms tensor ID using bit-reversal for B008 addressing
; Input:  RCX = tensor_id (64-bit)
; Output: RAX = B008-transformed ID
;=============================================================================
B008_TransformTensorID PROC
    ; Process each 16-bit chunk
    mov     r8, rcx         ; Save original
    
    ; Process low 16 bits
    mov     cx, r8w
    call    Reverse16Bit_Lookup
    movzx   r9, ax          ; Save result
    
    ; Process bits 16-31
    shr     r8, 16
    mov     cx, r8w
    call    Reverse16Bit_Lookup
    shl     rax, 16
    or      r9, rax
    
    ; Process bits 32-47
    shr     r8, 16
    mov     cx, r8w
    call    Reverse16Bit_Lookup
    shl     rax, 32
    or      r9, rax
    
    ; Process bits 48-63
    shr     r8, 16
    mov     cx, r8w
    call    Reverse16Bit_Lookup
    shl     rax, 48
    or      rax, r9
    
    ret
B008_TransformTensorID ENDP

;=============================================================================
; B008_GetBlockAddress
; Calculates physical block address from B008-transformed tensor ID
; Input:  RCX = tensor_id
;         RDX = block_size (power of 2)
; Output: RAX = block address
;=============================================================================
B008_GetBlockAddress PROC
    push    rbx
    
    ; Transform tensor ID
    call    B008_TransformTensorID
    
    ; Calculate block index: transformed_id / block_size
    ; For power-of-2 block sizes, use shift
    bsr     rcx, rdx        ; Get bit position of block_size
    dec     cl
    shr     rax, cl         ; Divide by block_size
    
    ; Multiply back to get aligned address
    shl     rax, cl
    
    pop     rbx
    ret
B008_GetBlockAddress ENDP

;=============================================================================
; Export symbols for C++ linkage
;=============================================================================
PUBLIC Reverse16Bit
PUBLIC Reverse16Bit_Unrolled
PUBLIC Reverse16Bit_Lookup
PUBLIC B008_TransformTensorID
PUBLIC B008_GetBlockAddress

END
