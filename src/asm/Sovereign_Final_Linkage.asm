; Sovereign_Final_Linkage.asm - Corrected Entry Point
; Zero-CRT, Win64, kernel32.lib only
; No includes, no MASM32 dependencies

.CODE

PUBLIC XR_Production_Entry
XR_Production_Entry PROC
    sub rsp, 40

    ; --- Phase 0: Check Command Line ---
    ; GetCommandLineW()
    ; EXTERN GetCommandLineW : PROC is declared below
    call GetCommandLineW
    mov rdx, rax
    ; Simple check for "--gate-verify" (L'-', L'-', L'g', L'a', L't', L'e')
    ; We'll skip complex parsing and just look for the magic verification code if it succeeds
    
    ; --- Phase 0.1: Dispatch Ingestion Pipeline ---
    call Sovereign_PEB_Bootstrap
    call Sovereign_IPC_Bootstrap
    call Sovereign_LoadModel_Disk
    test rax, rax
    jz ingest_failure

    call XR_Acquire_LargePage_Privilege
    call XR_Dispatch_Ingest
    cmp rax, 2
    je ingest_createfile_failure
    cmp rax, 3
    je ingest_mapping_failure
    cmp rax, 4
    je ingest_view_failure

    ; --- Phase 0.2: Initialize Gameplay Subsystems ---
    EXTERN Sovereign_Initialize_All_Systems : PROC
    call Sovereign_Initialize_All_Systems

    ; Verify mapped base is valid
    mov rcx, [g_MappedBase]
    test rcx, rcx
    jz privilege_failure

    ; --- Phase 1 & 2: GGUF Metadata & Registry ---
    mov rcx, [g_MappedBase]
    mov rdx, [g_MappedSize]
    call XR_Parse_GGUF_Tensors
    test rax, rax
    jnz parse_failure

    ; If we got here, parser succeeded. 
    ; For "--gate-verify", we exit with the SUCCESS code
    ; Disabled early exit to allow flow into TITAN_LOOP
    ; mov ecx, 0CAFEBABEh
    ; call ExitProcess

    ; --- Phase 3: Transition to Sovereign Space ---
    ; 1. Install Windows VEH Exception Hooks
    call XR_Install_Fault_Hooks

    ; 2. Instruction Cache Flush
    ; FlushInstructionCache(GetCurrentProcess(), NULL, 0)
    call GetCurrentProcess
    mov rcx, rax
    xor rdx, rdx
    xor r8, r8
    call FlushInstructionCache

    ; (Full JIT loop would go here in normal mode)
    call TITAN_LOOP
    call ExitProcess

ingest_createfile_failure:
    mov ecx, 0BADF004h      ; CreateFileW failed
    call ExitProcess

ingest_mapping_failure:
    mov ecx, 0BADF003h      ; CreateFileMappingW failed
    call ExitProcess

ingest_view_failure:
    mov ecx, 0BADF002h      ; MapViewOfFileEx failed
    call ExitProcess

privilege_failure:
    mov ecx, 0BADF001h
    call ExitProcess

ingest_failure:
    mov ecx, eax    ; Forward specific parser error code into exit code
    call ExitProcess

parse_failure:
    mov ecx, eax    ; Forward specific parser error code into exit code
    call ExitProcess

titan_fault:
    mov ecx, 0DEAD0001h
    call ExitProcess
XR_Production_Entry ENDP

PUBLIC XR_FaultHandler_Resolve
XR_FaultHandler_Resolve PROC
    ret
XR_FaultHandler_Resolve ENDP

EXTERN g_MappedBase : QWORD
EXTERN g_MappedSize : QWORD
EXTERN XR_Acquire_LargePage_Privilege : PROC
EXTERN XR_Dispatch_Ingest : PROC
EXTERN XR_Parse_GGUF_Tensors : PROC
EXTERN TITAN_LOOP : PROC
EXTERN ExitProcess : PROC
EXTERN GetCommandLineW : PROC
EXTERN GetCurrentProcess : PROC
EXTERN FlushInstructionCache : PROC
EXTERN XR_Install_Fault_Hooks : PROC
EXTERN Sovereign_PEB_Bootstrap : PROC
EXTERN Sovereign_IPC_Bootstrap : PROC
EXTERN Sovereign_LoadModel_Disk : PROC

.DATA
align 8
output_sequence     dd 128 dup(0)
END
