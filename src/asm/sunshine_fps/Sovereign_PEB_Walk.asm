; ==============================================================================
; SOVEREIGN_PEB_WALK.ASM
; Hardware-native kernel32 resolver using PEB walk
; ==============================================================================
_TEXT SEGMENT 'CODE'
PUBLIC Sovereign_GetKernel32
PUBLIC Sovereign_GetProcAddress

Sovereign_GetKernel32 PROC
    mov rax, gs:[60h]        ; PEB
    mov rax, [rax + 18h]     ; PEB_LDR_DATA
    mov rax, [rax + 20h]     ; InMemoryOrderModuleList.Flink (1st: exe)

@@ModuleLoop:
    mov rax, [rax]           ; Next node
    ; Read BaseDllName.Buffer (at offset 50h in LDR_DATA_TABLE_ENTRY for InMemoryOrder)
    mov r8, [rax + 50h]      ; Pointer to wide string
    test r8, r8
    jz @@ModuleLoop

    movzx r9, word ptr [r8]
    or r9, 20h               ; to lower
    cmp r9, 6bh              ; 'k'
    jne @@ModuleLoop

    movzx r9, word ptr [r8 + 2]
    or r9, 20h               ; to lower
    cmp r9, 65h              ; 'e'
    jne @@ModuleLoop
    
    ; check 7th char for '3'
    movzx r9, word ptr [r8 + 12]
    cmp r9, 33h              ; '3'
    jne @@ModuleLoop

    ; Found kernel32!
    mov rax, [rax + 20h]     ; DllBase
    ret
Sovereign_GetKernel32 ENDP

; RCX = Module Base, RDX = String Name
Sovereign_GetProcAddress PROC
    push rbx
    push rsi
    push rdi
    push rbp
    
    mov r8, rcx          ; R8 = Base
    mov ebx, [rcx + 3Ch] ; e_lfanew
    add rbx, rcx         ; NT Headers 
    mov ebx, [rbx + 88h] ; Export Directory RVA
    add rbx, rcx         ; Export Directory Address
    
    mov ecx, [rbx + 18h] ; NumberOfNames
    mov edi, [rbx + 20h] ; AddressOfNames RVA
    add rdi, r8          ; AddressOfNames Array
    
    xor rax, rax         ; Loop counter
@@FindLoop:
    test ecx, ecx
    jz @@NotFound
    dec ecx
    
    mov esi, [rdi + rcx * 4] ; RVA of current string
    add rsi, r8          ; Address of current string
    
    mov rbp, rdx         ; target string pointer
@@StrCmp:
    mov r9b, byte ptr [rsi] ; use r9b instead of al to preserve rax which holds 0
    mov r10b, byte ptr [rbp] ; use r10b instead of ah
    cmp r9b, r10b
    jne @@FindLoop       ; Next name
    test r9b, r9b
    jz @@Found           ; Reached null terminator matching!
    inc rsi
    inc rbp
    jmp @@StrCmp

@@Found:
    ; RCX is exact index
    mov edi, [rbx + 24h] 
    add rdi, r8
    movzx eax, word ptr [rdi + rcx * 2] ; Ordinal Array Offset
    
    mov edi, [rbx + 1Ch]
    add rdi, r8
    mov edi, [rdi + rax * 4] ; Function RVA
    add rdi, r8              ; Absolute Function Address
    mov rax, rdi
    jmp @@End

@@NotFound:
    xor rax, rax

@@End:
    pop rbp
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_GetProcAddress ENDP

_TEXT ENDS
END