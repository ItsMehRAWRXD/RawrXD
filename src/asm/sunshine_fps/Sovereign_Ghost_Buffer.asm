; =========================================================================================
; Sovereign_Ghost_Buffer.asm
; SPSC Lock-Free Ring Buffer (4096 bytes)
; MASM-to-C++ Boundary for the Ghost Text rendering validation.
; =========================================================================================

.data
    ALIGN 16
    Sovereign_Ghost_Ring      DB 4096 DUP(0)
    Sovereign_Ghost_Head      DD 0
    Sovereign_Ghost_Tail      DD 0

.code

; -----------------------------------------------------------------------------------------
; void Sovereign_Ghost_PushToken(const char* token)
; RCX = pointer to null-terminated token string
; Called from high-priority simulation ticks.
; -----------------------------------------------------------------------------------------
align 16
Sovereign_Ghost_PushToken PROC
    push rbx
    push rsi
    push rdi

    mov rsi, rcx
    mov edi, [Sovereign_Ghost_Head]
    
L_Push_Loop:
    mov al, byte ptr [rsi]
    test al, al
    jz L_Push_Done
    
    ; write byte to ring[head]
    lea rdx, Sovereign_Ghost_Ring
    mov byte ptr [rdx + rdi], al
    
    ; head = (head + 1) & 4095
    inc edi
    and edi, 4095
    
    inc rsi
    jmp L_Push_Loop

L_Push_Done:
    ; commit head (atomic release semantics on x64 aligned stores)
    mov [Sovereign_Ghost_Head], edi

    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Ghost_PushToken ENDP

; -----------------------------------------------------------------------------------------
; bool Sovereign_Ghost_ReadFrame(char* outBuffer, int maxLen, int* outBytesRead)
; RCX = outBuffer
; RDX = maxLen
; R8  = outBytesRead
; Called from NORMAL_PRIORITY UI polling thread.
; -----------------------------------------------------------------------------------------
align 16
Sovereign_Ghost_ReadFrame PROC
    push rbx
    push rsi
    push rdi

    mov esi, [Sovereign_Ghost_Tail]
    mov edi, [Sovereign_Ghost_Head]
    
    xor r9, r9 ; bytes read
    
L_Read_Loop:
    cmp esi, edi
    je L_Read_Done  ; tail == head -> empty
    
    cmp r9, rdx
    jge L_Read_Done ; outBuffer full
    
    ; read byte
    lea r10, Sovereign_Ghost_Ring
    mov al, byte ptr [r10 + rsi]
    
    ; write to outBuffer
    mov byte ptr [rcx + r9], al
    
    ; tail = (tail + 1) & 4095
    inc esi
    and esi, 4095
    
    inc r9
    jmp L_Read_Loop

L_Read_Done:
    ; commit tail
    mov [Sovereign_Ghost_Tail], esi
    
    ; null terminate
    mov byte ptr [rcx + r9], 0
    
    ; optional: store bytes read
    test r8, r8
    jz L_Skip_Out
    mov dword ptr [r8], r9d
L_Skip_Out:
    
    ; return true if we read anything
    mov rax, r9
    test rax, rax
    setnz al
    movzx eax, al

    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Ghost_ReadFrame ENDP

END
