; ==============================================================================
; Sovereign_Monolith.asm - Pure x64 MASM Stealth Monolith (1,000 Line Constraint)
; Unified Reverse Engineering Framework: Zero IAT, Zero CRT, Direct PEB
; ==============================================================================

OPTION CASEMAP:NONE

; --- Hash Definitions ---
H_Kernel32          equ 06D24E0BDh
H_Ntdll             equ 01ED054E6h
H_LoadLibraryA      equ 0EC0E4E8Eh
H_GetProcAddress    equ 07C0DFCAAh
H_NtTerminate       equ 0A59546E8h ; NtTerminateProcess
H_NtGetContext      equ 04D65F5F0h ; NtGetContextThread
H_NtSetContext      equ 0F5D5E5F0h ; NtSetContextThread
H_NtReadVirtual     equ 06555F5E0h ; NtReadVirtualMemory

; --- Structural Offsets ---
PEB_BEING_DEBUGGED  equ 2
PEB_LDR_DATA        equ 18h
LDR_MODULE_LIST     equ 10h
DLL_BASE_OFFSET     equ 30h
DLL_NAME_OFFSET     equ 60h

; --- Structures ---
HOTPATCH_TASK STRUCT
    Status      dq 0
    Callback    dq 0
    Context     dq 0
HOTPATCH_TASK ENDS

SOVEREIGN_REGISTRY STRUCT
    PeakCycles      dq 0
    TaskID          dq 0
    pNtTerminate    dq 0
    pNtGetContext   dq 0
    pNtSetContext   dq 0
    pNtReadVirtual  dq 0
    Tasks           HOTPATCH_TASK 64 dup(<>)
SOVEREIGN_REGISTRY ENDS

.DATA
    g_Registry      SOVEREIGN_REGISTRY <>
    g_Kernel32Base  dq 0
    g_NtdllBase     dq 0
    g_pLoadLibraryA dq 0
    g_pGetProcAddress dq 0
    
    g_Scan_Pattern  db 64 dup(0)
    g_Scan_Buffer   db 4096 dup(0)

.CODE

; ------------------------------------------------------------------------------
; Sovereign_Entry (Entry Point)
; ------------------------------------------------------------------------------
PUBLIC mainCRTStartup
mainCRTStartup PROC
    sub rsp, 40h
    
    ; 1. Resolve System Dependencies (Zero-IAT)
    call Sovereign_Bootstrap_Resolver
    
    ; 2. Initialize Internal Engine
    xor rax, rax
    mov [g_Registry.PeakCycles], rax
    
    ; 3. Enter TITAN_LOOP
    call Sovereign_Monolith_MainLoop
    
    add rsp, 40h
    ret
mainCRTStartup ENDP

; ------------------------------------------------------------------------------
; Sovereign_Monolith_MainLoop (TITAN_LOOP)
; ------------------------------------------------------------------------------
Sovereign_Monolith_MainLoop PROC
@@Loop:
    ; 1. Integrity Check (Non-featured Anti-Debug)
    call Sovereign_Shield_Verify
    test rax, rax
    jnz @@Panic
    
    ; 2. Braid Task Execution
    call Sovereign_Monolith_Step_Tasks
    
    ; 3. Telemetry Heartbeat
    rdtsc
    shl rdx, 32
    or rax, rdx
    
    pause
    jmp @@Loop

@@Panic:
    mov rcx, -1
    mov rdx, 0C0000005h
    call [g_Registry.pNtTerminate]
    ret
Sovereign_Monolith_MainLoop ENDP

; ------------------------------------------------------------------------------
; Sovereign_Bootstrap_Resolver
; Performs ROR13 hashing via PEB to resolve Kernel32/Ntdll and core APIs.
; ------------------------------------------------------------------------------
Sovereign_Bootstrap_Resolver PROC
    push rbx
    push rsi
    push rdi
    
    mov rax, gs:[60h]
    mov rax, [rax + PEB_LDR_DATA]
    mov rsi, [rax + LDR_MODULE_LIST]
    mov rbx, rsi

@@ModuleLoop:
    mov rdx, [rsi + DLL_NAME_OFFSET] ; BaseDllName (UNICODE)
    mov rdi, [rdx + 8h]             ; Buffer
    test rdi, rdi
    jz @@NextModule

    call Sovereign_Hash_Dll_Name     ; Result in R8
    
    ; Check for Kernel32
    cmp r8d, H_Kernel32
    jne @@NotK32
    mov rax, [rsi + DLL_BASE_OFFSET]
    mov [g_Kernel32Base], rax
    mov rdx, rax
    mov ecx, H_LoadLibraryA
    call Sovereign_Resolve_Export
    mov [g_pLoadLibraryA], rax
    mov rdx, [g_Kernel32Base]
    mov ecx, H_GetProcAddress
    call Sovereign_Resolve_Export
    mov [g_pGetProcAddress], rax
    jmp @@NextModule

@@NotK32:
    cmp r8d, H_Ntdll
    jne @@NextModule
    mov rax, [rsi + DLL_BASE_OFFSET]
    mov [g_NtdllBase], rax
    mov rdx, rax
    
    ; Resolve Native APIs
    mov ecx, H_NtTerminate
    call Sovereign_Resolve_Export
    mov [g_Registry.pNtTerminate], rax
    
    mov rdx, [g_NtdllBase]
    mov ecx, H_NtGetContext
    call Sovereign_Resolve_Export
    mov [g_Registry.pNtGetContext], rax
    
    mov rdx, [g_NtdllBase]
    mov ecx, H_NtSetContext
    call Sovereign_Resolve_Export
    mov [g_Registry.pNtSetContext], rax
    
    mov rdx, [g_NtdllBase]
    mov ecx, H_NtReadVirtual
    call Sovereign_Resolve_Export
    mov [g_Registry.pNtReadVirtual], rax

@@NextModule:
    mov rsi, [rsi]
    cmp rsi, rbx
    jne @@ModuleLoop
    
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Bootstrap_Resolver ENDP

; ------------------------------------------------------------------------------
; Sovereign_Hash_Dll_Name (ROR13)
; ------------------------------------------------------------------------------
Sovereign_Hash_Dll_Name PROC
    xor r8d, r8d
@@Loop:
    movzx rax, word ptr [rdi]
    test ax, ax
    jz @@Done
    cmp al, 'a'
    jb @@Sk
    cmp al, 'z'
    ja @@Sk
    sub al, 20h
@@Sk:
    ror r8d, 13
    add r8d, eax
    add rdi, 2
    jmp @@Loop
@@Done:
    ret
Sovereign_Hash_Dll_Name ENDP

; ------------------------------------------------------------------------------
; Sovereign_Resolve_Export
; RCX = Target Hash, RDX = DLL Base
; ------------------------------------------------------------------------------
Sovereign_Resolve_Export PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    mov r8d, [rdx + 3Ch]
    mov r8d, [rdx + r8 + 88h]
    add r8, rdx
    
    mov r9d, [r8 + 18h] ; NumNames
    mov r10d, [r8 + 20h] ; Names RVA
    add r10, rdx
    mov r11d, [r8 + 24h] ; Ords RVA
    add r11, rdx
    mov r12d, [r8 + 1Ch] ; Funcs RVA
    add r12, rdx

@@Loop:
    dec r9d
    js @@NF
    mov edi, [r10 + r9 * 4]
    add rdi, rdx
    
    push rcx
    push rdx
    mov rcx, rdi
    call Sovereign_Hash_String
    pop rdx
    pop rcx
    
    cmp eax, ecx
    je @@F
    jmp @@Loop
@@F:
    movzx eax, word ptr [r11 + r9 * 2]
    mov eax, [r12 + rax * 4]
    add rax, rdx
    jmp @@E
@@NF:
    xor rax, rax
@@E:
    add rsp, 20h
    pop rbp
    ret
Sovereign_Resolve_Export ENDP

Sovereign_Hash_String PROC
    xor eax, eax
@@L:
    movzx edx, byte ptr [rcx]
    test dl, dl
    jz @@D
    ror eax, 13
    add eax, edx
    inc rcx
    jmp @@L
@@D: ret
Sovereign_Hash_String ENDP

; ------------------------------------------------------------------------------
; Sovereign_Shield_Verify (Direct PEB + TSC Jitter)
; ------------------------------------------------------------------------------
Sovereign_Shield_Verify PROC
    mov rax, gs:[60h]
    movzx ecx, byte ptr [rax + 2]                ; BeingDebugged
    test ecx, ecx
    jnz @@Bad
    
    mov eax, [rax + 0BCh]                        ; NtGlobalFlag
    and eax, 70h                                 ; HEAP_FLAGS
    jnz @@Bad

    ; TSC Jitter check
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rsi, rax
    mov rcx, 1000                                ; Calibrated loop
@@J: pause
    loop @@J
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, rsi
    cmp rax, 200000h                             ; Threshold for debug latency
    ja @@Bad
    
    ; --- Dynamic Integrity Check (Self-Scan) ---
    ; Scans for 0xCC (soft-breakpoints) in core logic area
    lea rdi, [mainCRTStartup]
    mov rcx, 512                                 ; Scan first 512 bytes
    mov al, 0CCh
    repne scasb
    je @@Bad

    xor rax, rax
    ret
@@Bad: mov rax, 1
    ret
Sovereign_Shield_Verify ENDP

; ------------------------------------------------------------------------------
; Sovereign_Direct_Inspection
; RCX = Target VA, RDX = OutBuffer, R8 = Length
; Bypasses ReadProcessMemory using direct memory mapping logic.
; ------------------------------------------------------------------------------
Sovereign_Direct_Inspection PROC
    push rsi
    push rdi
    mov rsi, rcx
    mov rdi, rdx
    mov rcx, r8
    
    ; Use AVX-512 for high-speed, non-hookable direct copy
@@CopyLoop:
    cmp rcx, 64
    jl @@Tail
    vmovdqu64 zmm0, [rsi]
    vmovdqu64 [rdi], zmm0
    add rsi, 64
    add rdi, 64
    sub rcx, 64
    jmp @@CopyLoop
@@Tail:
    test rcx, rcx
    jz @@Done
    ; Masked tail to prevent page-edge AV
    mov rax, 1
    shl rax, cl
    dec rax
    kmovq k1, rax
    vmovdqu64 zmm0{k1}, [rsi]
    vmovdqu64 [rdi]{k1}, zmm0
@@Done:
    pop rdi
    pop rsi
    ret
Sovereign_Direct_Inspection ENDP

; ------------------------------------------------------------------------------
; Sovereign_Monolith_Step_Tasks
; ------------------------------------------------------------------------------
Sovereign_Monolith_Step_Tasks PROC
    ; O(1) Braid Dispatcher Logic
    lea rbx, [g_Registry.Tasks]
    mov rax, [g_Registry.TaskID]
    and rax, 63
    shl rax, 5 ; sizeof(HOTPATCH_TASK)
    add rbx, rax
    
    mov rdx, [rbx + HOTPATCH_TASK.Callback]
    test rdx, rdx
    jz @@Skip
    mov rcx, [rbx + HOTPATCH_TASK.Context]
    call rdx
@@Skip:
    inc qword ptr [g_Registry.TaskID]
    ret
Sovereign_Monolith_Step_Tasks ENDP

; ------------------------------------------------------------------------------
; Sovereign_Install_Hardware_Trap
; ------------------------------------------------------------------------------
Sovereign_Install_Hardware_Trap PROC
    sub rsp, 500h
    mov r8, rsp
    mov r10, rcx
    call [g_Registry.pNtGetContext]
    mov rax, rdx
    mov [rsp + 40h], rax
    or qword ptr [rsp + 58h], 1
    call [g_Registry.pNtSetContext]
    add rsp, 500h
    ret
Sovereign_Install_Hardware_Trap ENDP

; ------------------------------------------------------------------------------
; Sovereign_SIMD_Scanner_Hardened
; ------------------------------------------------------------------------------
Sovereign_SIMD_Scanner_Hardened PROC
    lea rax, [g_Scan_Pattern]
    vmovdqu64 zmm1, [rax]
@@L:
    cmp r8, 64
    jl @@T
    vmovdqu64 zmm0, [rcx]
    vpcmpeqb k1, zmm0, zmm1
    kortestw k1, k1
    jnz @@M
    add rcx, 64
    sub r8, 64
    jmp @@L
@@T:
    test r8, r8
    jz @@E
    mov rax, 1
    mov cl, r8b
    shl rax, cl
    dec rax
    kmovq k2, rax
    vmovdqu64 zmm0{k2}, [rcx]
    vpcmpeqb k1, zmm0, zmm1
    kandw k1, k1, k2
    kortestw k1, k1
    jnz @@M
@@E: xor rax, rax
    ret
@@M: mov rax, rcx
    ret
Sovereign_SIMD_Scanner_Hardened ENDP

END


    push rdi
    push rbx
    lea rbx, [g_SovereignHub]
    xor rsi, rsi
@@lp:
    lea rdi, [rbx + SOVEREIGN_HUB.Patch_Registry]
    mov rax, rsi
    shl rax, 5
    add rdi, rax
    cmp qword ptr [rdi + HOTPATCH_ENTRY.Status], ENTRY_ACTIVE
    jne @@Next
    mov rcx, rsi
    mov rdx, rbx
    call Sovereign_Watchdog_Profile_Lean_V2
@@Next:
    inc rsi
    cmp rsi, MAX_ASSETS
    jl @@lp
    pop rbx
    pop rdi
    pop rsi
    ret
Sovereign_Registry_Step_Lean ENDP
END
