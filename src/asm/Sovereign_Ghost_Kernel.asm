; ==============================================================================
; Sovereign_Ghost_Kernel.asm - Flat-Monolith Stealth Execution Core
; Architecture: Zero-Dependency, Zero-IAT, Raw PEB-Resolution
; ==============================================================================

include Sovereign_Common.inc

; --- Structural Sovereignty ---
SOVEREIGN_CORE STRUCT
    Patch_Table dq 64 DUP(0) ; 64 Active Hotpatch Entry Points
    GGUF_Arenas dq 64 DUP(0) ; 64 Active GGUF Base Addresses
    Peak_Cycles dq 0         ; Global Peak Telemetry
    Peak_ID     dq 0         ; Global Peak Owner
    Arena_Base  dq 0         ; 256MB Static Arena Base
SOVEREIGN_CORE ENDS

.DATA
    ALIGN 64
    g_Core SOVEREIGN_CORE <>
    
    ; Pre-allocated 256MB Static Block in .BSS / .DATA?
    ; Using a smaller 256KB placeholder here for workspace safety
    PUBLIC g_StaticArena
    g_StaticArena db 262144 dup(0)

.CODE

; ----------------------------------------------------------------------------
; Sovereign_Entry
; Bare-metal entry point (/NODEFAULTLIB /ENTRY:Sovereign_Entry)
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Entry
Sovereign_Entry PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40

    ; 1. Resolve Core Symbols via PEB (ntdll.dll usually at gs:[60h]+18h+10h)
    call Initialize_Core_Symbols

    ; 2. The "Titan" Execution Path
@@TitanLoop:
    ; A. Direct PEB Anti-Debug check (Bypass isDebuggerPresent)
    mov rax, gs:[60h]
    movzx eax, byte ptr [rax + 2]
    test eax, eax
    jnz @@Halt ; BeingDebugged flag set

    ; B. Execute Registered Hotpatches
    xor rbx, rbx
@@ExecuteTable:
    mov rax, [g_Core.Patch_Table + rbx*8]
    test rax, rax
    jz @@SkipPatch

    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r12, rax    ; r12 = Entry TSC

    call qword ptr [g_Core.Patch_Table + rbx*8]

    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r12    ; rax = Delta
    
    cmp rax, [g_Core.Peak_Cycles]
    jbe @@SkipPeak
    mov [g_Core.Peak_Cycles], rax
    mov [g_Core.Peak_ID], rbx
@@SkipPeak:

@@SkipPatch:
    inc rbx
    cmp rbx, 64
    jl @@ExecuteTable

    jmp @@TitanLoop

@@Halt:
    ; Silent Exit (NtTerminateProcess)
    mov rax, -1
    xor rcx, rcx
    ; In a real monolith, we'd use the resolved syscall or ntdll pointer
    ret
Sovereign_Entry ENDP

; ----------------------------------------------------------------------------
; Initialize_Core_Symbols
; Walks PEB -> Ldr -> InLoadOrderModuleList
; ----------------------------------------------------------------------------
Initialize_Core_Symbols PROC
    mov rax, gs:[60h]
    mov rax, [rax + 18h]    ; Ldr
    mov rax, [rax + 10h]    ; InLoadOrderModuleList
    mov rbx, [rax + 30h]    ; ntdll.dll Base (usually first)
    
    ; Setup static arena pointer
    lea rcx, [g_StaticArena]
    mov [g_Core.Arena_Base], rcx
    ret
Initialize_Core_Symbols ENDP

; ----------------------------------------------------------------------------
; Resolve_API_By_Hash (ROR13)
; RCX = Target Hash, RDX = DLL Base
; ----------------------------------------------------------------------------
Sovereign_Hash_Resolve PROC
    mov r8, [rdx + 3Ch]             ; PE Header
    mov r8, [rdx + r8 + 88h]        ; Export Directory
    add r8, rdx
    mov r9, [r8 + 20h]              ; Name Table
    add r9, rdx
    xor rax, rax
    
@@Loop:
    mov r10d, [r9 + rax*4]
    add r10, rdx                    ; r10 = Function Name
    
    push rax
    xor r11, r11
@@HashChar:
    ror r11d, 13
    movzx r12b, byte ptr [r10]
    add r11d, r12d
    inc r10
    cmp byte ptr [r10], 0
    jne @@HashChar
    
    cmp r11d, ecx                   ; Match?
    je @@Found
    pop rax
    inc rax
    jmp @@Loop

@@Found:
    pop rax
    mov r10, [r8 + 24h]             ; Ordinals
    add r10, rdx
    movzx rax, word ptr [r10 + rax*2]
    mov r10, [r8 + 1Ch]             ; Functions
    add r10, rdx
    mov eax, [r10 + rax*4]
    add rax, rdx
    ret
Sovereign_Hash_Resolve ENDP

END
