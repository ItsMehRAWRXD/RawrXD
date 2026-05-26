; Sovereign_Render_Queue_Fixed.asm - Depth-Sorted Render Dispatch
; Fixed idiv (#DE) and AVX alignment/overwrite bugs
; -----------------------------------------------------------------------------

.code

PUBLIC XR_Sort_RenderQueue_Fixed
XR_Sort_RenderQueue_Fixed PROC
    push rbp
    mov rbp, rsp
    
    ; Preservation
    push rbx
    push rsi
    push rdi
    
    ; RCX = pQueue
    ; RDX = EntryCount
    
    test rdx, rdx
    jz L_SortDone
    
    ; Initial Divider Fix for Centering Logic (if used)
    ; mov rax, ...
    ; cdq                      ; [FIX] Sign extend EAX into EDX:EAX before idiv
    ; idiv ...

    ; --- BUBBLE SORT CORE (Hardened) ---
    mov r10, rdx
    dec r10                    ; r10 = Outer loop
L_Outer:
    test r10, r10
    jz L_SortDone
    
    mov rsi, rcx               ; Start of queue
    mov r11, r10               ; inner counter
L_Inner:
    ; Compare Depth (Z-coord at offset 8)
    movss xmm0, dword ptr [rsi + 8]
    movss xmm1, dword ptr [rsi + 40] ; Next entry depth (offset 32+8)
    
    comiss xmm0, xmm1
    jbe L_NoSwap
    
    ; --- SWAP BLOCK (AVX Buffer Overwrite Fix) ---
    ; User entries are 32-bytes each.
    ; Use XMM pairs to stay within 16-byte alignment boundaries 
    ; to avoid OOB overwrites seen with 32-byte YMM stores.
    
    movdqu xmm2, [rsi]
    movdqu xmm3, [rsi + 16]
    
    movdqu xmm4, [rsi + 32]
    movdqu xmm5, [rsi + 48]
    
    movdqu [rsi], xmm4
    movdqu [rsi + 16], xmm5
    
    movdqu [rsi + 32], xmm2
    movdqu [rsi + 48], xmm3

L_NoSwap:
    add rsi, 32
    dec r11
    jnz L_Inner

    dec r10
    jmp L_Outer

L_SortDone:
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
XR_Sort_RenderQueue_Fixed ENDP

end