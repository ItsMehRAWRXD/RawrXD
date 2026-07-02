; ==============================================================================
; Sovereign_Switch.asm - No-Dependency API/Syscall Dispatcher
; ==============================================================================
; Purpose: Bare-metal MASM dispatcher that resolves Windows APIs via EAT hashing
;          and executes raw syscalls by extracting IDs from ntdll stubs.
;          Bypasses user-mode hooks (AMD/OBS overlays) by skipping the hooked
;          entry point and calling the kernel directly.
;
; Build:   ml64.exe /c /W3 /nologo /Zi /Fo Sovereign_Switch.obj Sovereign_Switch.asm
; Link:    link.exe /SUBSYSTEM:WINDOWS /NODEFAULTLIB /OUT:Sovereign_Switch.exe ...
; ==============================================================================

option casemap:none
option prologue:none
option epilogue:none

; ==============================================================================
; Data Section
; ==============================================================================
.data
ALIGN 16

; --- Global Mode Toggle ---
; 0 = Hybrid (standard API call via import table / EAT resolution)
; 1 = Manual (direct syscall, bypasses all user-mode hooks)
g_Mode              DQ 1

; --- Cached ntdll base address ---
g_NtdllBase         DQ 0

; --- Precomputed FNV-1a hashes for common APIs ---
HASH_NtCreateFile   DQ 0DEADBEEFh       ; Placeholder - compute at init
HASH_NtReadFile     DQ 0CAFEBABEh       ; Placeholder - compute at init
HASH_NtWriteFile    DQ 0BADDCAFEh       ; Placeholder - compute at init
HASH_NtClose        DQ 0FEEDFACEh       ; Placeholder - compute at init

; --- String literals for hash initialization ---
str_NtCreateFile    db "NtCreateFile", 0
str_NtReadFile      db "NtReadFile", 0
str_NtWriteFile     db "NtWriteFile", 0
str_NtClose         db "NtClose", 0

; ==============================================================================
; Code Section
; ==============================================================================
.code

; ==============================================================================
; 1. FNV-1a Hash (64-bit)
; RCX = null-terminated string pointer
; Returns: RAX = hash value
; ==============================================================================
PUBLIC Sovereign_Hash
Sovereign_Hash PROC
    mov rax, 14695981039346656037     ; FNV offset basis
    mov rdx, 1099511628211            ; FNV prime
@@loop_hash:
    movzx r11, byte ptr [rcx]
    test r11, r11
    jz @@done
    xor rax, r11
    mul rdx
    inc rcx
    jmp @@loop_hash
@@done:
    ret
Sovereign_Hash ENDP

; ==============================================================================
; 2. PEB Walker: Find ntdll.dll base address
; Returns: RAX = ntdll base (cached in g_NtdllBase)
; ==============================================================================
PUBLIC Sovereign_FindNtdll
Sovereign_FindNtdll PROC
    push rbx
    push rsi
    push rdi

    ; Check cache first
    mov rax, [g_NtdllBase]
    test rax, rax
    jnz @@cached

    ; TEB at GS:[0], PEB at TEB+0x60
    mov rax, gs:[60h]                 ; PEB
    mov rax, [rax + 18h]              ; PEB->Ldr
    mov rax, [rax + 20h]              ; Ldr->InMemoryOrderModuleList (first = ntdll)
    mov rax, [rax + 20h]              ; BaseAddress of ntdll
    mov [g_NtdllBase], rax

@@cached:
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_FindNtdll ENDP

; ==============================================================================
; 3. Resolve Export via EAT (Export Address Table)
; RCX = FNV-1a hash of function name
; Returns: RAX = function address, 0 if not found
; ==============================================================================
PUBLIC Sovereign_GetExport
Sovereign_GetExport PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14

    ; Ensure ntdll base is cached
    call Sovereign_FindNtdll
    mov rbx, rax                      ; RBX = ntdll base

    ; Parse PE header
    mov r8, [rbx + 3Ch]               ; PE header offset
    mov r8, [rbx + r8 + 88h]          ; Export Directory RVA (DataDirectory[0])
    add r8, rbx                       ; R8 = Export Directory VA

    ; Get array pointers
    mov r9, [r8 + 20h]                ; AddressOfNames RVA
    add r9, rbx                       ; R9 = Names array
    mov r10, [r8 + 18h]               ; NumberOfNames
    xor r14, r14                      ; R14 = index counter

@@find_name:
    cmp r14, r10
    jae @@not_found

    ; Get name RVA
    mov eax, [r9 + r14*4]
    add rax, rbx                      ; RAX = name string VA

    ; Hash the name
    push rcx
    push r8
    push r9
    push r10
    push r14
    mov rcx, rax
    call Sovereign_Hash               ; RAX = hash of current name
    pop r14
    pop r10
    pop r9
    pop r8
    pop rcx

    ; Compare with target hash
    cmp rax, rcx
    je @@found

    inc r14
    jmp @@find_name

@@found:
    ; Get ordinal
    mov r11, [r8 + 24h]               ; AddressOfNameOrdinals RVA
    add r11, rbx                      ; R11 = Ordinals array
    movzx r11, word ptr [r11 + r14*2] ; R11 = ordinal

    ; Get function address
    mov r12, [r8 + 1Ch]               ; AddressOfFunctions RVA
    add r12, rbx                      ; R12 = Functions array
    mov eax, [r12 + r11*4]            ; EAX = function RVA
    add rax, rbx                      ; RAX = function VA
    jmp @@done

@@not_found:
    xor rax, rax

@@done:
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_GetExport ENDP

; ==============================================================================
; 4. Stub Detection: Extract Syscall ID from ntdll function stub
; RCX = function address (from ntdll)
; Returns: RAX = syscall ID, 0 if stub pattern not recognized
; ==============================================================================
PUBLIC Sovereign_GetSyscallID
Sovereign_GetSyscallID PROC
    push rbx
    mov rbx, rcx

    ; Check for 'mov r10, rcx' pattern: 4C 8B D1
    cmp word ptr [rbx], 0D18Bh
    jne @@check_alt
    cmp byte ptr [rbx+2], 4Ch
    jne @@check_alt

    ; Check for 'mov eax, ID' pattern: B8 XX XX XX XX
    cmp byte ptr [rbx+3], 0B8h
    jne @@check_alt

    ; Extract syscall ID
    mov eax, [rbx + 4]
    jmp @@done

@@check_alt:
    ; Alternative pattern check for different Windows builds
    ; Some stubs use: 4C 8B D1 B8 XX XX XX XX 0F 05
    cmp dword ptr [rbx], 0B8D18B4Ch
    jne @@error
    mov eax, [rbx + 4]
    jmp @@done

@@error:
    xor rax, rax

@@done:
    pop rbx
    ret
Sovereign_GetSyscallID ENDP

; ==============================================================================
; 5. The Sovereign Switch - Unified Dispatcher
; RCX = Symbol hash
; RDX = Arg1 (preserved through call)
; R8  = Arg2 (preserved through call)
; R9  = Arg3 (preserved through call)
; Returns: RAX = API return value / syscall result
; ==============================================================================
PUBLIC Sovereign_Call
Sovereign_Call PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 28h                      ; ABI shadow space + alignment

    ; Save arguments (volatile registers)
    mov r12, rcx                      ; R12 = symbol hash
    mov r13, rdx                      ; R13 = arg1
    mov r14, r8                       ; R14 = arg2
    ; R9 (arg3) is preserved by x64 ABI in non-volatile regs

    ; Resolve function address
    mov rcx, r12
    call Sovereign_GetExport          ; RAX = function address
    test rax, rax
    jz @@fail

    ; Check mode
    cmp [g_Mode], 0
    je @@do_hybrid

@@do_manual:
    ; --- MANUAL SYSCALL PATH ---
    ; Extract syscall ID from stub
    mov rcx, rax
    call Sovereign_GetSyscallID     ; RAX = syscall ID
    test rax, rax
    jz @@fallback_hybrid              ; If stub detection fails, fall back

    ; Setup syscall arguments
    ; Windows syscall convention: RCX, RDX, R8, R9, R10, R11
    mov r10, r12                      ; R10 = arg0 (symbol hash - not used by kernel)
    mov rdx, r13                      ; RDX = arg1
    mov r8, r14                       ; R8 = arg2
    ; R9 already = arg3
    mov eax, eax                      ; EAX = syscall ID (zero-extend)

    ; Execute direct kernel transition
    syscall
    jmp @@finish

@@fallback_hybrid:
    ; Stub detection failed, fall through to hybrid path
    nop

@@do_hybrid:
    ; --- HYBRID API CALL PATH ---
    ; Restore original arguments
    mov rcx, r12                      ; RCX = symbol hash (function identifier)
    mov rdx, r13                      ; RDX = arg1
    mov r8, r14                       ; R8 = arg2
    ; R9 already = arg3

    ; Call the resolved function
    call rax
    jmp @@finish

@@fail:
    mov rax, 0FFFFFFFFFFFFFFFFh     ; Return -1 on failure

@@finish:
    add rsp, 28h
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Call ENDP

; ==============================================================================
; 6. Mode Toggle Helpers
; ==============================================================================
PUBLIC Sovereign_SetMode
Sovereign_SetMode PROC
    ; RCX = mode (0 = hybrid, 1 = manual)
    mov [g_Mode], rcx
    ret
Sovereign_SetMode ENDP

PUBLIC Sovereign_GetMode
Sovereign_GetMode PROC
    mov rax, [g_Mode]
    ret
Sovereign_GetMode ENDP

; ==============================================================================
; 7. Precomputed Hash Initializer (optional)
; Call at startup to populate known hashes
; ==============================================================================
PUBLIC Sovereign_InitHashes
Sovereign_InitHashes PROC
    push rcx

    ; Hash "NtCreateFile"
    lea rcx, [str_NtCreateFile]
    call Sovereign_Hash
    mov [HASH_NtCreateFile], rax

    ; Hash "NtReadFile"
    lea rcx, [str_NtReadFile]
    call Sovereign_Hash
    mov [HASH_NtReadFile], rax

    ; Hash "NtWriteFile"
    lea rcx, [str_NtWriteFile]
    call Sovereign_Hash
    mov [HASH_NtWriteFile], rax

    ; Hash "NtClose"
    lea rcx, [str_NtClose]
    call Sovereign_Hash
    mov [HASH_NtClose], rax

    pop rcx
    ret

Sovereign_InitHashes ENDP

end
