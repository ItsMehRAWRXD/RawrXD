; ==============================================================================
; Sovereign_PEB_Loader.asm - Verified Zero-IAT API Resolver
; ==============================================================================

include Sovereign_Common.inc

.CODE

; DJB2 Hashes (Verified)
HASH_LoadLibraryA         EQU 05FBFF0FBh
HASH_GetProcAddress       EQU 0CF31BB1Fh
HASH_VirtualAlloc         EQU 0382C0F97h
HASH_CreateFileA          EQU 0EB96C5FAh
HASH_CloseHandle          EQU 03870CA07h
HASH_GetFileSizeEx        EQU 0E417967Dh
HASH_CreateFileMappingA   EQU 0F33FFC86h
HASH_MapViewOfFile        EQU 011DEB0B3h
HASH_GetStdHandle         EQU 0F178843Ch
HASH_WriteFile            EQU 0663CECB0h
HASH_ExitProcess          EQU 0B769339Eh
HASH_GetTickCount64       EQU 0614DB023h

EXTERN g_ApiTable : SOVEREIGN_API_TABLE

PUBLIC Sovereign_PEB_Loader
Sovereign_PEB_Loader PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 64

    mov rax, gs:[60h]
    mov rax, [rax + 18h]
    mov r12, [rax + 10h]
    mov r15, r12

@@ModLoop:
    mov rbx, [r12 + 30h]
    test rbx, rbx
    jz @@NextMod
    
    mov rdi, [r12 + 60h]
    test rdi, rdi
    jz @@NextMod

    movzx eax, word ptr [rdi]
    and eax, 0FFDFh
    cmp eax, 'K'
    je @@ProcessModule
    cmp eax, 'N'
    je @@ProcessModule
    jmp @@NextMod

@@ProcessModule:
    mov eax, [rbx + 3Ch]
    add rax, rbx
    mov r11d, [rax + 88h]
    test r11d, r11d
    jz @@NextMod
    
    mov r10d, [rax + 8Ch]
    mov r13, r11
    add r13, rbx
    
    mov [rbp-48], r11d
    add r11d, r10d
    mov [rbp-56], r11d

    mov r14d, [r13 + 18h]
    mov r8d, [r13 + 20h]
    add r8, rbx
    
    xor rsi, rsi
@@NameLoop:
    cmp esi, r14d
    jae @@NextMod
    
    mov edi, [r8 + rsi*4]
    add rdi, rbx
    
    push rsi
    mov edx, 5381
@@HashLoop:
    movzx eax, byte ptr [rdi]
    test al, al
    jz @@HashDone
    mov ecx, edx
    shl ecx, 5
    add edx, ecx
    add edx, eax
    inc rdi
    jmp @@HashLoop
@@HashDone:
    pop rsi

    xor r9, r9
    lea rax, g_ApiTable
    
    cmp edx, HASH_GetStdHandle
    je @@Found_GSH
    cmp edx, HASH_WriteFile
    je @@Found_WF
    cmp edx, HASH_ExitProcess
    je @@Found_EP
    cmp edx, HASH_LoadLibraryA
    je @@Found_LL
    cmp edx, HASH_GetProcAddress
    je @@Found_GPA
    cmp edx, HASH_VirtualAlloc
    je @@Found_VA
    cmp edx, HASH_CreateFileA
    je @@Found_CFA
    cmp edx, HASH_CloseHandle
    je @@Found_CH
    cmp edx, HASH_GetFileSizeEx
    je @@Found_GFSE
    cmp edx, HASH_CreateFileMappingA
    je @@Found_CFMA
    cmp edx, HASH_MapViewOfFile
    je @@Found_MVOF
    cmp edx, HASH_GetTickCount64
    je @@Found_GTC
    jmp @@ContinueName

@@Found_GSH:  lea r9, [rax + SOVEREIGN_API_TABLE.pGetStdHandle]
    jmp @@CheckSlot
@@Found_WF:   lea r9, [rax + SOVEREIGN_API_TABLE.pWriteFile]
    jmp @@CheckSlot
@@Found_EP:   lea r9, [rax + SOVEREIGN_API_TABLE.pExitProcess]
    jmp @@CheckSlot
@@Found_LL:   lea r9, [rax + SOVEREIGN_API_TABLE.pLoadLibraryA]
    jmp @@CheckSlot
@@Found_GPA:  lea r9, [rax + SOVEREIGN_API_TABLE.pGetProcAddress]
    jmp @@CheckSlot
@@Found_VA:   lea r9, [rax + SOVEREIGN_API_TABLE.pVirtualAlloc]
    jmp @@CheckSlot
@@Found_CFA:  lea r9, [rax + SOVEREIGN_API_TABLE.pCreateFileA]
    jmp @@CheckSlot
@@Found_CH:   lea r9, [rax + SOVEREIGN_API_TABLE.pCloseHandle]
    jmp @@CheckSlot
@@Found_GFSE: lea r9, [rax + SOVEREIGN_API_TABLE.pGetFileSizeEx]
    jmp @@CheckSlot
@@Found_CFMA: lea r9, [rax + SOVEREIGN_API_TABLE.pCreateFileMappingA]
    jmp @@CheckSlot
@@Found_MVOF: lea r9, [rax + SOVEREIGN_API_TABLE.pMapViewOfFile]
    jmp @@CheckSlot
@@Found_GTC:  lea r9, [rax + SOVEREIGN_API_TABLE.pGetTickCount64]
    jmp @@CheckSlot

@@CheckSlot:
    cmp qword ptr [r9], 0
    jnz @@ContinueName

    mov r11d, [r13 + 24h]
    add r11, rbx
    movzx eax, word ptr [r11 + rsi*2]
    mov r11d, [r13 + 1Ch]
    add r11, rbx
    mov eax, [r11 + rax*4]
    
    cmp eax, [rbp-48]
    jb @@NotForward
    cmp eax, [rbp-56]
    jae @@NotForward
    jmp @@ContinueName

@@NotForward:
    add rax, rbx
    mov [r9], rax

@@ContinueName:
    inc rsi
    jmp @@NameLoop

@@NextMod:
    mov r12, [r12]
    cmp r12, r15
    jne @@ModLoop

    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Sovereign_PEB_Loader ENDP
END
