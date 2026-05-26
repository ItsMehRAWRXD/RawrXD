; ==============================================================================
; Sovereign_PEB_Loader.asm - Stealth API Resolution (PEB/ROR13)
; ==============================================================================

include Sovereign_Common.inc

; --- API Hashes ---
H_GetProcAddress    equ 07C0DFCAAh
H_LoadLibraryA      equ 0EC0E4E8Eh
H_VirtualProtect    equ 07946C61Bh
H_GetStdHandle      equ 04E49FB92h
H_WriteFile         equ 04F698947h
H_NtQueryInformationProcess equ 0F7696666h ; Placeholder hash

API_TABLE STRUCT
    pGetProcAddress     dq 0
    pLoadLibraryA       dq 0
    pVirtualProtect     dq 0
    pGetStdHandle       dq 0
    pWriteFile          dq 0
    pNtQueryInformationProcess dq 0
API_TABLE ENDS

.DATA
    ; Instance of the table
    PUBLIC g_Apis
    g_Apis API_TABLE <0>

.CODE

; ------------------------------------------------------------------------------
; Sovereign_Resolve_Core_APIs
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Resolve_Core_APIs
Sovereign_Resolve_Core_APIs PROC
    push rbx
    push rsi
    push rdi
    push r12

    ; 1. Get PEB -> Ldr -> InLoadOrderModuleList
    mov rax, gs:[60h]        ; RAX = PEB
    mov rax, [rax + 18h]     ; RAX = PEB_LDR_DATA
    mov rsi, [rax + 10h]     ; RSI = InLoadOrderModuleList (Head)
    mov rbx, rsi             ; RBX = Sentinel

@@WalkModules:
    mov rdx, [rsi + 60h]     ; RDX = BaseDllName (UNICODE_STRING)
    mov rdi, [rdx + 8h]      ; RDI = Buffer (Raw PWSTR)
    test rdi, rdi
    jz @@NextModule

    ; Custom Hash (ROR13) of the DLL name
    xor r8, r8               ; R8 = Current Hash
@@HashDll:
    movzx rax, byte ptr [rdi]
    test al, al
    jz @@HashDone
    cmp al, 'a'
    jb @@NotLower
    cmp al, 'z'
    ja @@NotLower
    sub al, 20h              ; To Upper
@@NotLower:
    ror r8d, 13
    add r8d, eax
    add rdi, 2               ; UNICODE
    jmp @@HashDll

@@HashDone:
    ; Real check for Kernel32 base:
    mov rax, [rsi + 30h]     ; RAX = DllBase
    mov r12, rax             ; Save potential base

    ; 2. Parse Export Table of Kernel32
    mov eax, [r12 + 3Ch]     ; EAX = e_lfanew
    mov eax, [r12 + rax + 88h] ; EAX = Export Data Directory RVA
    test eax, eax
    jz @@NextModule
    add rax, r12             ; RAX = IMAGE_EXPORT_DIRECTORY

    mov r9d, [rax + 18h]     ; R9D = NumberOfNames
    mov r10d, [rax + 20h]    ; R10D = AddressOfNames RVA
    add r10, r12
    mov r11d, [rax + 24h]    ; R11D = AddressOfNameOrdinals RVA
    add r11, r12
    mov ebx, [rax + 1Ch]     ; EBX = AddressOfFunctions RVA
    add rbx, r12

@@NameLoop:
    dec r9d
    js @@NextModule
    mov edi, [r10 + r9 * 4]  ; EDI = Name RVA
    add rdi, r12             ; RDI = Name String
    
    ; Hash the function name
    xor r8, r8
@@HashFunc:
    movzx eax, byte ptr [rdi]
    test al, al
    jz @@FuncHashDone
    ror r8d, 13
    add r8d, eax
    inc rdi
    jmp @@HashFunc

@@FuncHashDone:
    ; Match against required hashes
    cmp r8d, H_GetProcAddress
    je @@FoundGPA
    cmp r8d, H_LoadLibraryA
    je @@FoundLLA
    cmp r8d, H_GetStdHandle
    je @@FoundGSH
    cmp r8d, H_WriteFile
    je @@FoundWF
    cmp r8d, H_NtQueryInformationProcess
    je @@FoundNQIP
    jmp @@NameLoop

@@FoundGPA:
    call @@ExtractAddress
    mov [g_Apis.pGetProcAddress], rax
    jmp @@NameLoop
@@FoundLLA:
    call @@ExtractAddress
    mov [g_Apis.pLoadLibraryA], rax
    jmp @@NameLoop
@@FoundGSH:
    call @@ExtractAddress
    mov [g_Apis.pGetStdHandle], rax
    jmp @@NameLoop
@@FoundWF:
    call @@ExtractAddress
    mov [g_Apis.pWriteFile], rax
    jmp @@NameLoop
@@FoundNQIP:
    call @@ExtractAddress
    mov [g_Apis.pNtQueryInformationProcess], rax
    jmp @@NameLoop

@@NextModule:
    mov rsi, [rsi]           ; Next Link
    cmp rsi, rbx
    je @@Done
    jmp @@WalkModules

@@ExtractAddress:
    movzx eax, word ptr [r11 + r9 * 2] ; Ordinal
    mov eax, [rbx + rax * 4]           ; Function RVA
    add rax, r12                       ; Function VA
    ret

; ------------------------------------------------------------------------------
; Sovereign_Detect_Debugger
; Output: RAX = 1 if detected, 0 otherwise
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Detect_Debugger
Sovereign_Detect_Debugger PROC
    ; 1. NtGlobalFlag Check
    mov rax, gs:[60h]               ; RAX = PEB
    mov eax, dword ptr [rax + 0BCh] ; NtGlobalFlag (Win10/11)
    and eax, 70h                    ; FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    jnz @@Detected

    ; 2. Heap Flags Check
    mov rax, gs:[60h]
    mov rax, [rax + 30h]            ; ProcessHeap
    mov eax, dword ptr [rax + 70h]  ; Heap Flags (Win10/11)
    cmp eax, 2                      ; HEAP_GROWABLE (2) is expected. Debuggers change this.
    jne @@Detected

    ; 3. BeingDebugged Check (Basic) - Keep as fallback
    mov rax, gs:[60h]
    movzx eax, byte ptr [rax + 2]
    test al, al
    jnz @@Detected

    xor rax, rax
    ret

@@Detected:
    mov rax, 1
    ret
Sovereign_Detect_Debugger ENDP

; ------------------------------------------------------------------------------
; Resolve_Symbol
; RCX = Hash, RDX = DLL_Base
; ------------------------------------------------------------------------------
PUBLIC Resolve_Symbol
Resolve_Symbol PROC
    ; RCX = Hash, RDX = DLL_Base
    mov r8, [rdx + 3Ch]      ; PE Header (e_lfanew)
    mov r8, [rdx + r8 + 88h] ; Export Directory RVA
    add r8, rdx
    mov r9, [r8 + 20h]       ; Name Pointers RVA
    add r9, rdx
    
    xor rax, rax
@@HashLoop:
    mov r10d, [r9 + rax * 4]
    add r10, rdx             ; r10 = Function Name
    
    push rax
    push rcx
    push rdx
    mov rcx, r10
    call ROR13_Hash_Routine
    pop rdx
    pop rcx
    
    cmp eax, ecx
    je @@Found
    pop rax
    inc rax
    jmp @@HashLoop
    
@@Found:
    pop rax
    mov r10, [r8 + 24h]      ; Ordinals
    add r10, rdx
    movzx rax, word ptr [r10 + rax * 2]
    mov r10, [r8 + 1Ch]      ; Functions
    add r10, rdx
    mov eax, [r10 + rax * 4]
    add rax, rdx
    ret
Resolve_Symbol ENDP

; ------------------------------------------------------------------------------
; ROR13_Hash
; RCX = String
; Returns: EAX = Hash
; ------------------------------------------------------------------------------
PUBLIC ROR13_Hash
ROR13_Hash PROC
    xor rax, rax
@@Loop:
    movzx edx, byte ptr [rcx]
    test dl, dl
    jz @@Done
    ror eax, 13
    add eax, edx
    inc rcx
    jmp @@Loop
@@Done:
    ret
ROR13_Hash ENDP

END
