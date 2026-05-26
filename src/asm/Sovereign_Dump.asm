; ==============================================================================
; Sovereign_Dump.asm
; Sovereign In-Memory PE Inspector (Runtime Module Walker)
; Implementation of "Elite" Suite Component #2
; Pure x64 MASM / Zero Dependencies / Zero IAT
; ==============================================================================

option casemap:none
include Sovereign_Common.inc

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_GetModuleBase
; Input:  RCX = Pointer to WideString (Module Name) - if NULL, returns current EXE
; Output: RAX = Module Base Address
; ------------------------------------------------------------------------------
Sovereign_GetModuleBase PROC
    mov rax, gs:[60h]           ; RAX = PEB
    mov rax, [rax + 18h]        ; RAX = PEB->Ldr
    mov r8, [rax + 10h]         ; R8 = Ldr->InLoadOrderModuleList (Head)
    mov rdx, r8                 ; RDX = Current Entry

    test rcx, rcx
    jz return_current_exe

next_module:
    mov r9, [rdx + 60h]         ; R9 = FullModuleName.Buffer (UNICODE_STRING)
    test r9, r9
    jz check_next

    ; Minimalistic Unicode Compare (Stub-like but functional for literal matches)
    push rsi
    push rdi
    mov rsi, rcx                ; Target
    mov rdi, r9                 ; Candidate
compare_name:
    mov ax, [rsi]
    mov bx, [rdi]
    ; Case insensitive simple (A-Z)
    cmp ax, 'A'
    jl @no_upper_a
    cmp ax, 'Z'
    jg @no_upper_a
    add ax, 20h
@no_upper_a:
    cmp bx, 'A'
    jl @no_upper_b
    cmp bx, 'Z'
    jg @no_upper_b
    add bx, 20h
@no_upper_b:
    cmp ax, bx
    jne diff_name
    test ax, ax
    jz match_found
    add rsi, 2
    add rdi, 2
    jmp compare_name

diff_name:
    pop rdi
    pop rsi
    
check_next:
    mov rdx, [rdx]              ; Flink
    cmp rdx, r8                 ; Back at head?
    jne next_module
    xor rax, rax
    ret

match_found:
    pop rdi
    pop rsi
    mov rax, [rdx + 30h]        ; DllBase
    ret
    
return_current_exe:
    mov rax, [rdx + 30h]        ; DllBase
    ret
Sovereign_GetModuleBase ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_ResolveExport
; Input:  RCX = Module Base Address, RDX = Pointer to Name string (C-style)
; Output: RAX = Actual Address
; ------------------------------------------------------------------------------
Sovereign_ResolveExport PROC
    push rbx
    push rsi
    push rdi
    
    mov r8, rcx                 ; R8 = ModuleBase
    mov eax, [r8 + 3Ch]         ; PE Header Offset
    add rax, r8                 ; PE Header VA
    
    mov eax, [rax + 88h]        ; Export Directory RVA
    test eax, eax
    jz export_not_found
    
    add rax, r8                 ; Export Directory VA
    mov r9, rax                 ; R9 = Export Directory
    
    mov r10d, [r9 + 20h]        ; AddressOfNames RVA
    add r10, r8                 ; AddressOfNames VA
    
    mov r11d, [r9 + 18h]        ; NumberOfNames
    xor r14, r14                ; Index counter
    
find_name_loop:
    cmp r14d, r11d
    jae export_not_found
    
    mov edi, [r10 + r14 * 4]    ; Name RVA
    add rdi, r8                 ; Name String
    
    mov rsi, rdx                ; Target string
compare_str:
    mov bl, [rsi]
    cmp bl, [rdi]
    jne next_name
    test bl, bl
    jz match_found
    inc rsi
    inc rdi
    jmp compare_str

next_name:
    inc r14
    jmp find_name_loop

match_found:
    mov r10d, [r9 + 24h]        ; AddressOfNameOrdinals RVA
    add r10, r8                 ; VA
    movzx eax, word ptr [r10 + r14 * 2] ; EAX = Ordinal
    
    mov r11d, [r9 + 1Ch]        ; AddressOfFunctions RVA
    add r11, r8                 ; VA
    mov eax, [r11 + rax * 4]    ; Function RVA
    add rax, r8                 ; Final VA
    jmp @done

export_not_found:
    xor rax, rax
@done:
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_ResolveExport ENDP

END
