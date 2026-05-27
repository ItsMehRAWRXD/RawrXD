; Sovereign_Math_HUD.asm
; 16-Lane Float Projection & Predictor HUD over OpenGL
; 00.00000000 Precision (Pure x64 MASM - No CRT)

extrn glRasterPos2i:PROC
extrn glCallLists:PROC

.data
    Float_1e8       REAL8 100000000.0
    Abs_Mask        DQ 7FFFFFFFFFFFFFFFh
    
    Str_Tokens      DB "Tokens: ", 0
    Str_Pred        DB " | Predicted: ", 0
    Str_Act         DB " | Actual: ", 0
    Str_Diff        DB " | Difference: ", 0

    HUD_Tokens      DD 40
    HUD_Predicted   REAL8 13.40000000
    HUD_Actual      REAL8 48.71000000
    HUD_Diff        REAL8 35.31000000
    HUD_Buffer      DB 256 DUP(0)
    
.code

; Fast String Copy
; RCX = Source, RDX = Destination
; Returns RAX = number of bytes written
strcpy proc
    push rsi
    push rdi
    mov rsi, rcx
    mov rdi, rdx
    xor rax, rax
write_char:
    mov cl, [rsi]
    test cl, cl
    jz done_strcpy
    mov [rdi], cl
    inc rdi
    inc rsi
    inc rax
    jmp write_char
done_strcpy:
    pop rdi
    pop rsi
    ret
strcpy endp

; Integer to ASCII
; RAX = Integer, RCX = Buffer
; Returns RAX = number of bytes written
itoa proc
    push rbx
    push r8
    push rdx
    push rdi

    mov rdi, rcx      ; Setup destination
    mov r8, 10
    mov rbx, rsp
div_loop_itoa:
    xor rdx, rdx
    div r8
    add dl, '0'
    push rdx
    test rax, rax
    jnz div_loop_itoa

    xor rax, rax      ; Byte counter
pop_loop_itoa:
    pop rdx
    mov [rdi], dl
    inc rdi
    inc rax
    cmp rsp, rbx
    jne pop_loop_itoa

    pop rdi
    pop rdx
    pop r8
    pop rbx
    ret
itoa endp

; Float to ASCII (8 Decimals)
; XMM0 = float, RCX = Buffer, AL = forced '+' toggle (1 = true)
ftoa_8 proc
    push rbx
    push rdx
    push r8
    push rdi
    
    mov rdi, rcx      ; Setup destination

    
    ; Sign evaluation
    movmskpd ecx, xmm0
    test ecx, 1
    jz positive
negative:
    mov byte ptr [rdi], '-'
    inc rdi
    jmp do_abs
positive:
    cmp al, 1
    jne do_abs
    mov byte ptr [rdi], '+'
    inc rdi
do_abs:
    ; Absolute logic
    mov rcx, Abs_Mask
    movq xmm1, rcx
    andpd xmm0, xmm1
    
    ; Integer serialization
    mov rcx, rdi                ; Setup buffer for itoa
    cvttsd2si rax, xmm0         ; Truncate
    call itoa
    add rdi, rax                ; Advance RDI by bytes written
    
    mov byte ptr [rdi], '.'     ; Decimal marker
    inc rdi
    
    ; Fraction serialization
    cvtsi2sd xmm1, rax
    subsd xmm0, xmm1            ; Extract remainder delta
    movsd xmm1, [Float_1e8]
    mulsd xmm0, xmm1            ; Upscale delta
    cvtsd2si rax, xmm0          ; Round to nearest digit
    
    ; Render strictly 8 fractional characters
    mov rcx, 10
    mov r8, 8
    mov rbx, rsp
fdiv_loop:
    xor rdx, rdx
    div rcx
    add dl, '0'
    push rdx
    dec r8
    jnz fdiv_loop
fpop_loop:
    pop rdx
    mov [rdi], dl
    inc rdi
    cmp rsp, rbx
    jne fpop_loop
    
    mov rax, rdi
    pop rdi
    sub rax, rdi
    
    pop r8
    pop rdx
    pop rbx
    ret
ftoa_8 endp

; --- Renders the HUD ---
Sovereign_Format_HUD proc
    sub rsp, 88h
    
    lea rdi, [HUD_Buffer]
    
    ; Tokens Block
    lea rcx, [Str_Tokens]
    mov rdx, rdi
    call strcpy
    add rdi, rax
    
    mov eax, [HUD_Tokens]
    mov rcx, rdi
    call itoa
    add rdi, rax
    
    ; Predicted Block
    lea rcx, [Str_Pred]
    mov rdx, rdi
    call strcpy
    add rdi, rax
    
    movsd xmm0, [HUD_Predicted]
    xor al, al                  ; Disable forced '+' sign
    mov rcx, rdi
    call ftoa_8
    add rdi, rax
    
    ; Actual Block
    lea rcx, [Str_Act]
    mov rdx, rdi
    call strcpy
    add rdi, rax
    
    movsd xmm0, [HUD_Actual]
    xor al, al
    mov rcx, rdi
    call ftoa_8
    add rdi, rax
    
    ; Difference Block
    lea rcx, [Str_Diff]
    mov rdx, rdi
    call strcpy
    add rdi, rax
    
    movsd xmm0, [HUD_Diff]
    mov al, 1                   ; Force '+' sign for positive diffs
    mov rcx, rdi
    call ftoa_8
    add rdi, rax
    
    mov byte ptr [rdi], 0       ; Null terminator edge boundary
    
    ; Calculate exact byte length delta
    lea rcx, [HUD_Buffer]
    sub rdi, rcx
    
    ; OpenGL Rendering Target Offset
    mov ecx, 10
    mov edx, 10
    call glRasterPos2i
    
    mov rcx, rdi
    mov rdx, 1401h              ; GL_UNSIGNED_BYTE mapping explicitly
    lea r8, [HUD_Buffer]
    call glCallLists

    add rsp, 88h
    ret
Sovereign_Format_HUD endp
end
