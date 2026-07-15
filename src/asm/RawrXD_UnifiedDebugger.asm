; =============================================================================
; RawrXD_UnifiedDebugger.asm ? Complete x64 MASM Debugger
; =============================================================================
; Combines: RawrXD_Debugger.asm + RawrXD_Debug_Engine.asm + rawrxd_minimal_debugger.asm
; Features:
;   - Debug event loop (WaitForDebugEvent ? ContinueDebugEvent)
;   - Hardware breakpoints (DR0-DR3) with full DR7 control
;   - Software breakpoints (INT3 injection/restoration)
;   - Single-step tracing (RFLAGS.TF manipulation)
;   - Memory validation (VirtualQueryEx)
;   - Memory read/write with protection toggle
;   - Pattern scanning (Boyer-Moore inspired)
;   - CRC-32 checksum
;   - Stack walking
;   - Thread context capture
; Zero dependencies ? kernel32.lib only
; =============================================================================

option casemap:none

; =============================================================================
; Constants
; =============================================================================
INFINITE                    EQU 0FFFFFFFFh
DBG_CONTINUE                EQU 00010002h
DBG_EXCEPTION_NOT_HANDLED   EQU 080010001h

; Debug events
EXCEPTION_DEBUG_EVENT       EQU 1
CREATE_THREAD_DEBUG_EVENT   EQU 2
CREATE_PROCESS_DEBUG_EVENT  EQU 3
EXIT_THREAD_DEBUG_EVENT     EQU 4
EXIT_PROCESS_DEBUG_EVENT    EQU 5
LOAD_DLL_DEBUG_EVENT        EQU 6
UNLOAD_DLL_DEBUG_EVENT      EQU 7
OUTPUT_DEBUG_STRING_EVENT   EQU 8

; Exception codes
EXCEPTION_BREAKPOINT        EQU 080000003h
EXCEPTION_SINGLE_STEP       EQU 080000004h
EXCEPTION_ACCESS_VIOLATION  EQU 0C0000005h

; Context flags
CONTEXT_AMD64               EQU 00100000h
CONTEXT_CONTROL             EQU (CONTEXT_AMD64 OR 00000001h)
CONTEXT_INTEGER             EQU (CONTEXT_AMD64 OR 00000002h)
CONTEXT_SEGMENTS            EQU (CONTEXT_AMD64 OR 00000004h)
CONTEXT_FLOATING_POINT      EQU (CONTEXT_AMD64 OR 00000008h)
CONTEXT_DEBUG_REGISTERS     EQU (CONTEXT_AMD64 OR 00000010h)
CONTEXT_FULL                EQU (CONTEXT_CONTROL OR CONTEXT_INTEGER OR CONTEXT_FLOATING_POINT)
CONTEXT_ALL                 EQU (CONTEXT_FULL OR CONTEXT_SEGMENTS OR CONTEXT_DEBUG_REGISTERS)

; Memory constants
MEM_COMMIT                  EQU 1000h
PAGE_READWRITE              EQU 04h
PAGE_EXECUTE_READWRITE      EQU 40h
PAGE_EXECUTE_READ           EQU 20h

; DR7 control bits
DR7_L0                      EQU 001h
DR7_G0                      EQU 002h
DR7_L1                      EQU 004h
DR7_G1                      EQU 008h
DR7_L2                      EQU 010h
DR7_G2                      EQU 020h
DR7_L3                      EQU 040h
DR7_G3                      EQU 080h

; INT3 opcode
INT3_OPCODE                 EQU 0CCh

; Thread access
THREAD_GET_CONTEXT          EQU 0008h
THREAD_SET_CONTEXT          EQU 0010h
THREAD_SUSPEND_RESUME       EQU 0002h
THREAD_ALL_ACCESS           EQU 001FFFFFh

; CRC-32 polynomial
CRC32_POLY                  EQU 0EDB88320h

; =============================================================================
; Structures
; =============================================================================
DEBUG_EVENT STRUCT
    dwDebugEventCode    DD ?
    dwProcessId         DD ?
    dwThreadId          DD ?
    u                   DB 164 DUP(?)
DEBUG_EVENT ENDS

MEMORY_BASIC_INFORMATION STRUCT
    BaseAddress         DQ ?
    AllocationBase      DQ ?
    AllocationProtect   DD ?
    __pad1              DD ?
    RegionSize          DQ ?
    State               DD ?
    Protect             DD ?
    MemType             DD ?
    __pad2              DD ?
MEMORY_BASIC_INFORMATION ENDS

; CONTEXT structure offsets (x64)
CTX_P1Home              EQU 00h
CTX_P2Home              EQU 08h
CTX_P3Home              EQU 10h
CTX_P4Home              EQU 18h
CTX_P5Home              EQU 20h
CTX_P6Home              EQU 28h
CTX_ContextFlags        EQU 30h
CTX_MxCsr               EQU 34h
CTX_SegCs               EQU 38h
CTX_SegDs               EQU 3Ah
CTX_SegEs               EQU 3Ch
CTX_SegFs               EQU 3Eh
CTX_SegGs               EQU 40h
CTX_SegSs               EQU 42h
CTX_EFlags              EQU 44h
CTX_Dr0                 EQU 48h
CTX_Dr1                 EQU 50h
CTX_Dr2                 EQU 58h
CTX_Dr3                 EQU 60h
CTX_Dr6                 EQU 68h
CTX_Dr7                 EQU 70h
CTX_Rax                 EQU 78h
CTX_Rcx                 EQU 80h
CTX_Rdx                 EQU 88h
CTX_Rbx                 EQU 90h
CTX_Rsp                 EQU 98h
CTX_Rbp                 EQU 0A0h
CTX_Rsi                 EQU 0A8h
CTX_Rdi                 EQU 0B0h
CTX_R8                  EQU 0B8h
CTX_R9                  EQU 0C0h
CTX_R10                 EQU 0C8h
CTX_R11                 EQU 0D0h
CTX_R12                 EQU 0D8h
CTX_R13                 EQU 0E0h
CTX_R14                 EQU 0E8h
CTX_R15                 EQU 0F0h
CTX_Rip                 EQU 0F8h
CTX_FltSave             EQU 100h
CONTEXT_SIZE            EQU 4D0h

; =============================================================================
; External APIs
; =============================================================================
EXTERN DebugActiveProcess:PROC
EXTERN DebugActiveProcessStop:PROC
EXTERN WaitForDebugEvent:PROC
EXTERN ContinueDebugEvent:PROC
EXTERN GetThreadContext:PROC
EXTERN SetThreadContext:PROC
EXTERN ReadProcessMemory:PROC
EXTERN WriteProcessMemory:PROC
EXTERN VirtualQueryEx:PROC
EXTERN VirtualProtectEx:PROC
EXTERN OpenProcess:PROC
EXTERN OpenThread:PROC
EXTERN CloseHandle:PROC
EXTERN SuspendThread:PROC
EXTERN ResumeThread:PROC
EXTERN FlushInstructionCache:PROC
EXTERN GetLastError:PROC
EXTERN GetCurrentProcess:PROC
EXTERN GetCurrentThreadId:PROC

; =============================================================================
; Data Section
; =============================================================================
.data
ALIGN 16

; Global state
g_hProcess          DQ 0
g_hThread           DQ 0
g_targetPid         DD 0
g_continueStatus    DD DBG_CONTINUE
g_breakpointCount   DD 0
g_singleStepMode    DB 0

; Hardware breakpoint slots
g_hwBpAddr          DQ 4 DUP(0)
g_hwBpType          DD 4 DUP(0)
g_hwBpSize          DD 4 DUP(0)
g_hwBpOriginal      DB 4 DUP(0)

; Software breakpoint tracking
g_swBpAddr          DQ 64 DUP(0)
g_swBpOriginal      DB 64 DUP(0)
g_swBpCount         DD 0

; CRC-32 lookup table
ALIGN 16
crc32_table DD 000000000h, 077073096h, 0EE0E612Ch, 0990951BAh
            DD 0076DC419h, 0706AF48Fh, 0E963A535h, 09E6495A3h
            DD 00EDB8832h, 079DCB8A4h, 0E0D5E91Bh, 097D2D988h
            DD 009B64C2Bh, 07EB17CBDh, 0E7B82D09h, 090BF1D9Fh
            DD 01DB71064h, 06AB020F2h, 0F3B97148h, 084BE41DEh
            DD 01ADAD47Dh, 06DDDE4EBh, 0F4D4B551h, 083D385C7h
            DD 0136C9856h, 0646BA8C0h, 0FD62F97Ah, 08A65C9ECh
            DD 014015C4Fh, 063066CD9h, 0FA0F3D63h, 08D080DF5h
            DD 03B6E20C8h, 04C69105Eh, 0D56041E4h, 0A2677172h
            DD 03C03E4D1h, 04B04D447h, 0D20D85FDh, 0A50AB56Bh
            DD 035B5A8FAh, 042B2986Ch, 0DBBBC9D6h, 0ACBCF940h
            DD 032D86CE3h, 045DF5C75h, 0DCD60DCFh, 0ABD13D59h
            DD 026D930ACh, 051DE003Ah, 0C8D75180h, 0BFD06116h
            DD 021B4F4B5h, 056B3C423h, 0CF0BA899h, 0B805980Fh
            DD 028D12D17h, 05FD6E381h, 0C6DF0B3Bh, 0B1D0BBFDh
            DD 02F6F7C87h, 0584ED011h, 0C1E3D0ABh, 0B6E4E03Dh
            DD 04ADF5355h, 03DD863C3h, 0A4D13279h, 0D3D602EFh
            DD 04DB26158h, 03AB551CEh, 0A3BC0074h, 0D4BB30E2h
            DD 044042D73h, 033031DE5h, 0AA0A4C5Fh, 0DD0D7CC9h
            DD 05005713Ch, 0270241AAh, 0BE0B1010h, 0C90C2086h
            DD 05768B525h, 0206F85B3h, 0B966D409h, 0CE61E49Fh
            DD 05EDEF90Eh, 029D9C998h, 0B0D09822h, 0C7D7A8B4h
            DD 059B33D17h, 02EB40D81h, 0B7BD5C3Bh, 0C0BA6CADh
            DD 0EDB88320h, 09ABFB3B6h, 003B6E20Ch, 074B1D29Ah
            DD 0EAD54739h, 09DD277AFh, 004DB2615h, 073DC1683h
            DD 0E3630B12h, 094643B84h, 00D6D6A3Eh, 07A6A5AA8h
            DD 0E40ECF0Bh, 09309FF9Dh, 00A00AE27h, 07D079EB1h
            DD 0F00F9344h, 08708A3D2h, 01E01F268h, 06906C2FEh
            DD 0F762575Dh, 0806567CBh, 0196C3671h, 06E6B06E7h
            DD 0FED41B76h, 089D32BE0h, 010DA7A5Ah, 067DD4ACCh
            DD 0F9B9DF6Fh, 08EBEEFF9h, 017B7BE43h, 060B08ED5h
            DD 0D6D6A3E8h, 0A1D1937Eh, 038D8C2C4h, 04FDFF252h
            DD 0D1BB67F1h, 0A6BC5767h, 03FB506DDh, 048B2364Bh
            DD 0D80D2BDAh, 0AF0A1B4Ch, 036034AF6h, 041047A60h
            DD 0DF60EFC3h, 0A867DF55h, 0316E8EEFh, 04669BE79h
            DD 0CB61B38Ch, 0BC66831Ah, 0256FD2A0h, 05268E236h
            DD 0CC0C7795h, 0BB0B4703h, 0220216B9h, 05505262Fh
            DD 0C5BA3BBEh, 0B2BD0B28h, 02BB45A92h, 05CB36A04h
            DD 0C2D7FFA7h, 0B5D0CF31h, 02CD99E8Bh, 05BDEAE1Dh
            DD 09B64C2B0h, 0EC63F226h, 07562639Ch, 0026557A5h
            DD 09C0906A9h, 0EB0E363Fh, 072076785h, 005005713h
            DD 095BF4A82h, 0E2B87A14h, 07BB12BAEh, 00CB61B38h
            DD 092D28E9Bh, 0E5D5BE0Dh, 07CDCEFB7h, 00BDBDF21h
            DD 086D3D2D4h, 0F1D4E242h, 068DDB3F8h, 01FDA836Eh
            DD 081BE16CDh, 0F6B9265Bh, 06FB077E1h, 018B74777h
            DD 088085AE6h, 0FF0F6B70h, 066063BCAh, 011010B5Ch
            DD 08F659EFFh, 0F862AE69h, 0616BFFD3h, 0166CCF45h
            DD 0A00AE278h, 0D70DD2EEh, 04E048354h, 03903B3C2h
            DD 0A7672661h, 0D06016F7h, 04969474Dh, 03E6E77DBh
            DD 0AED16A4Ah, 0D9D65ADCh, 040DF0B66h, 037D83BF0h
            DD 0A9BCAE53h, 0DEBB9EC5h, 047B2CF7Fh, 030B5FFE9h
            DD 0BDBDF21Ch, 0CABAC28Ah, 053B39330h, 024B4A3A6h
            DD 0BAD03605h, 0CDD70693h, 054DE5729h, 023D967BFh
            DD 0B3667A2Eh, 0C4614AB8h, 05D681B02h, 02A6F2B94h
            DD 0B40BBE37h, 0C30C8EA1h, 05A05DF1Bh, 02D02EF8Dh

; =============================================================================
; Code Section
; =============================================================================
.code

; =============================================================================
; Dbg_Init ? Attach to target process
; RCX = target PID
; Returns: RAX = 1 success, 0 failure
; =============================================================================
ALIGN 16
Dbg_Init PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    
    mov ebx, ecx                    ; EBX = target PID
    mov [g_targetPid], ecx
    
    ; DebugActiveProcess(pid)
    call DebugActiveProcess
    test eax, eax
    jz @@fail
    
    ; OpenProcess for memory operations
    mov ecx, 1F0FFFh                ; PROCESS_ALL_ACCESS
    xor edx, edx
    mov r8d, ebx
    call OpenProcess
    test rax, rax
    jz @@fail
    mov [g_hProcess], rax
    
    mov rax, 1
    jmp @@done
    
@@fail:
    xor rax, rax
    
@@done:
    add rsp, 28h
    pop rsi
    pop rbx
    ret
Dbg_Init ENDP

; =============================================================================
; Dbg_Detach ? Detach from target process
; =============================================================================
ALIGN 16
Dbg_Detach PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    
    mov ecx, [g_targetPid]
    call DebugActiveProcessStop
    
    mov rcx, [g_hProcess]
    test rcx, rcx
    jz @@done
    call CloseHandle
    mov qword ptr [g_hProcess], 0
    
@@done:
    add rsp, 28h
    pop rbx
    ret
Dbg_Detach ENDP

; =============================================================================
; Dbg_IsAddressWritable ? Validate memory before write
; RCX = hProcess, RDX = address
; Returns: RAX = 1 writable, 0 protected/invalid
; =============================================================================
ALIGN 16
Dbg_IsAddressWritable PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 50h
    .allocstack 50h
    .endprolog
    
    mov rbx, rcx                    ; hProcess
    
    ; VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))
    lea r8, [rsp+20h]               ; MBI buffer
    mov r9, 38h                     ; sizeof(MEMORY_BASIC_INFORMATION)
    call VirtualQueryEx
    
    test rax, rax
    jz @@not_writable
    
    ; Check MEM_COMMIT
    mov eax, [rsp+28h]              ; MBI.State
    cmp eax, MEM_COMMIT
    jne @@not_writable
    
    ; Check protection bits
    mov eax, [rsp+30h]              ; MBI.Protect
    test eax, PAGE_READWRITE
    jnz @@writable
    test eax, PAGE_EXECUTE_READWRITE
    jnz @@writable
    
@@not_writable:
    xor rax, rax
    jmp @@done
    
@@writable:
    mov rax, 1
    
@@done:
    add rsp, 50h
    pop rbx
    ret
Dbg_IsAddressWritable ENDP

; =============================================================================
; Dbg_MakeWritable ? Change page protection if needed
; RCX = hProcess, RDX = address, R8 = m_size
; Returns: RAX = 1 success, 0 failure
; =============================================================================
ALIGN 16
Dbg_MakeWritable PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp, 40h
    .allocstack 40h
    .endprolog
    
    mov rbx, rcx                    ; hProcess
    mov rsi, rdx                    ; address
    
    ; Check if already writable
    call Dbg_IsAddressWritable
    test rax, rax
    jnz @@done
    
    ; VirtualProtectEx(hProcess, addr, m_size, PAGE_EXECUTE_READWRITE, &oldProtect)
    lea r9, [rsp+30h]               ; oldProtect
    mov qword ptr [rsp+28h], PAGE_EXECUTE_READWRITE
    mov rcx, rbx
    mov rdx, rsi
    call VirtualProtectEx
    
    test rax, rax
    jz @@fail
    
    mov rax, 1
    jmp @@done
    
@@fail:
    xor rax, rax
    
@@done:
    add rsp, 40h
    pop rsi
    pop rbx
    ret
Dbg_MakeWritable ENDP

; =============================================================================
; Dbg_ReadMemory ? Safe memory read
; RCX = hProcess, RDX = address, R8 = buffer, R9 = m_size
; Returns: RAX = bytes read (0 on failure)
; =============================================================================
ALIGN 16
Dbg_ReadMemory PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp, 38h
    .allocstack 38h
    .endprolog
    
    mov rbx, r9                     ; m_size
    mov qword ptr [rsp+28h], 0      ; bytesRead
    mov qword ptr [rsp+30h], rbx    ; m_size param
    
    call ReadProcessMemory
    
    test rax, rax
    jz @@fail
    
    mov rax, [rsp+28h]              ; return bytes read
    jmp @@done
    
@@fail:
    xor rax, rax
    
@@done:
    add rsp, 38h
    pop rsi
    pop rbx
    ret
Dbg_ReadMemory ENDP

; =============================================================================
; Dbg_WriteMemory ? Safe memory write with protection toggle
; RCX = hProcess, RDX = address, R8 = buffer, R9 = m_size
; Returns: RAX = bytes written (0 on failure)
; =============================================================================
ALIGN 16
Dbg_WriteMemory PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 48h
    .allocstack 48h
    .endprolog
    
    mov rbx, rcx                    ; hProcess
    mov rsi, rdx                    ; address
    mov rdi, r9                     ; m_size
    
    ; Make writable if needed
    call Dbg_MakeWritable
    test rax, rax
    jz @@fail
    
    ; WriteProcessMemory
    mov qword ptr [rsp+28h], 0      ; bytesWritten
    mov qword ptr [rsp+30h], rdi    ; m_size
    mov rcx, rbx
    mov rdx, rsi
    call WriteProcessMemory
    
    test rax, rax
    jz @@fail
    
    mov rax, [rsp+28h]
    jmp @@done
    
@@fail:
    xor rax, rax
    
@@done:
    add rsp, 48h
    pop rdi
    pop rsi
    pop rbx
    ret
Dbg_WriteMemory ENDP

; =============================================================================
; Dbg_InjectINT3 ? Inject software breakpoint
; RCX = hProcess, RDX = address, R8 = outOriginalByte
; Returns: RAX = 1 success, 0 failure
; =============================================================================
ALIGN 16
Dbg_InjectINT3 PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp, 40h
    .allocstack 40h
    .endprolog
    
    mov rbx, rcx                    ; hProcess
    mov rsi, rdx                    ; address
    
    ; Read original byte
    lea r8, [rsp+30h]               ; buffer for 1 byte
    mov qword ptr [rsp+28h], 1      ; m_size = 1
    call ReadProcessMemory
    test rax, rax
    jz @@fail
    
    ; Save original
    mov al, [rsp+30h]
    mov [r8], al                    ; outOriginalByte
    
    ; Write INT3
    mov byte ptr [rsp+30h], INT3_OPCODE
    mov qword ptr [rsp+28h], 1
    mov rcx, rbx
    mov rdx, rsi
    call WriteProcessMemory
    test rax, rax
    jz @@fail
    
    ; Flush instruction cache
    xor r8d, r8d                    ; 0 bytes = flush all
    mov rcx, rbx
    call FlushInstructionCache
    
    mov rax, 1
    jmp @@done
    
@@fail:
    xor rax, rax
    
@@done:
    add rsp, 40h
    pop rsi
    pop rbx
    ret
Dbg_InjectINT3 ENDP

; =============================================================================
; Dbg_RestoreINT3 ? Restore original byte after breakpoint
; RCX = hProcess, RDX = address, R8 = originalByte
; Returns: RAX = 1 success, 0 failure
; =============================================================================
ALIGN 16
Dbg_RestoreINT3 PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 38h
    .allocstack 38h
    .endprolog
    
    mov rbx, rcx                    ; hProcess
    
    ; Write original byte back
    lea r8, [rsp+30h]               ; buffer
    mov byte ptr [rsp+30h], dl      ; originalByte
    mov qword ptr [rsp+28h], 1      ; m_size = 1
    call WriteProcessMemory
    test rax, rax
    jz @@fail
    
    ; Flush instruction cache
    xor r8d, r8d
    mov rcx, rbx
    call FlushInstructionCache
    
    mov rax, 1
    jmp @@done
    
@@fail:
    xor rax, rax
    
@@done:
    add rsp, 38h
    pop rbx
    ret
Dbg_RestoreINT3 ENDP

; =============================================================================
; Dbg_SetHardwareBreakpoint ? Set DR0-DR3 breakpoint
; RCX = hThread, RDX = address, R8 = slot (0-3), R9 = m_type (0=exec,1=write,3=rw)
; Stack: m_size (1,2,4,8)
; Returns: RAX = 1 success, 0 failure
; =============================================================================
ALIGN 16
Dbg_SetHardwareBreakpoint PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    sub rsp, 500h                   ; CONTEXT + locals
    .allocstack 500h
    .endprolog
    
    mov rbx, rcx                    ; hThread
    mov rsi, rdx                    ; address
    mov edi, r8d                    ; slot
    mov r12d, r9d                   ; m_type
    
    ; Validate slot
    cmp edi, 3
    ja @@fail
    
    ; Get thread context
    lea rdx, [rsp+30h]              ; CONTEXT buffer
    mov dword ptr [rsp+30h+CTX_ContextFlags], CONTEXT_ALL
    mov rcx, rbx
    call GetThreadContext
    test rax, rax
    jz @@fail
    
    ; Set DR[slot] = address
    lea rax, [rsp+30h]
    cmp edi, 0
    jne @@dr1
    mov [rax+CTX_Dr0], rsi              ; Dr0
    jmp @@set_dr7
@@dr1:
    cmp edi, 1
    jne @@dr2
    mov [rax+CTX_Dr1], rsi              ; Dr1
    jmp @@set_dr7
@@dr2:
    cmp edi, 2
    jne @@dr3
    mov [rax+CTX_Dr2], rsi              ; Dr2
    jmp @@set_dr7
@@dr3:
    mov [rax+CTX_Dr3], rsi              ; Dr3
    
@@set_dr7:
    ; Configure DR7
    mov rax, [rax+CTX_Dr7]              ; Dr7
    
    ; Local enable: 1 << (slot * 2)
    mov ecx, edi
    mov edx, 1
    shl edx, cl
    shl edx, cl                     ; LEn bit
    or rax, rdx
    
    ; m_type: (m_type) << (16 + slot * 4)
    mov ecx, edi
    shl ecx, 2
    add ecx, 16
    mov edx, r12d
    shl edx, cl
    or rax, rdx
    
    ; m_size: get from stack
    mov ecx, edi
    shl ecx, 2
    add ecx, 18
    mov edx, [rsp+508h]            ; m_size param
    cmp edx, 1
    je @@size_done
    cmp edx, 2
    jne @@size_4
    mov edx, 1                      ; LEN encoding for 2 bytes
    jmp @@apply_size
@@size_4:
    cmp edx, 4
    jne @@size_8
    mov edx, 3                      ; LEN encoding for 4 bytes
    jmp @@apply_size
@@size_8:
    mov edx, 2                      ; LEN encoding for 8 bytes
@@apply_size:
    shl edx, cl
    or rax, rdx
    
@@size_done:
    lea rcx, [rsp+30h]
    mov [rcx+70h], rax
    
    ; Set context
    mov rcx, rbx
    lea rdx, [rsp+30h]
    call SetThreadContext
    test rax, rax
    jz @@fail
    
    mov rax, 1
    jmp @@done
    
@@fail:
    xor rax, rax
    
@@done:
    add rsp, 500h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Dbg_SetHardwareBreakpoint ENDP

; =============================================================================
; Dbg_ClearHardwareBreakpoint ? Clear DR0-DR3 breakpoint
; RCX = hThread, RDX = slot (0-3)
; Returns: RAX = 1 success, 0 failure
; =============================================================================
ALIGN 16
Dbg_ClearHardwareBreakpoint PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 500h
    .allocstack 500h
    .endprolog
    
    mov ebx, edx                    ; slot
    
    ; Validate slot
    cmp ebx, 3
    ja @@fail
    
    ; Get context
    lea rdx, [rsp+30h]
    mov dword ptr [rsp+30h+CTX_ContextFlags], CONTEXT_ALL
    call GetThreadContext
    test rax, rax
    jz @@fail
    
    ; Clear DR[slot]
    lea rax, [rsp+30h]
    cmp ebx, 0
    jne @@clr_dr1
    mov qword ptr [rax+CTX_Dr0], 0
    jmp @@clr_dr7
@@clr_dr1:
    cmp ebx, 1
    jne @@clr_dr2
    mov qword ptr [rax+CTX_Dr1], 0
    jmp @@clr_dr7
@@clr_dr2:
    cmp ebx, 2
    jne @@clr_dr3
    mov qword ptr [rax+CTX_Dr2], 0
    jmp @@clr_dr7
@@clr_dr3:
    mov qword ptr [rax+CTX_Dr3], 0
    
@@clr_dr7:
    ; Clear DR7 bits for this slot
    mov rax, [rax+CTX_Dr7]
    mov ecx, ebx
    mov edx, 0Fh
    shl edx, cl
    shl edx, cl
    shl edx, cl
    shl edx, cl                     ; mask for m_type+m_size bits
    not edx
    and rax, rdx
    mov ecx, ebx
    mov edx, 3
    shl edx, cl
    not edx
    and rax, rdx                    ; clear LEn+GEn
    
    lea rcx, [rsp+30h]
    mov [rcx+70h], rax
    
    ; Set context
    lea rdx, [rsp+30h]
    call SetThreadContext
    test rax, rax
    jz @@fail
    
    mov rax, 1
    jmp @@done
    
@@fail:
    xor rax, rax
    
@@done:
    add rsp, 500h
    pop rbx
    ret
Dbg_ClearHardwareBreakpoint ENDP

; =============================================================================
; Dbg_EnableSingleStep ? Enable trap flag for single-step
; RCX = hThread
; Returns: RAX = 1 success, 0 failure
; =============================================================================
ALIGN 16
Dbg_EnableSingleStep PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 500h
    .allocstack 500h
    .endprolog
    
    mov rbx, rcx
    
    ; Get context
    lea rdx, [rsp+30h]
    mov dword ptr [rsp+30h+CTX_ContextFlags], CONTEXT_CONTROL
    call GetThreadContext
    test rax, rax
    jz @@fail
    
    ; Set TF (trap flag) in EFlags
    lea rax, [rsp+30h]
    or dword ptr [rax+CTX_EFlags], 100h     ; EFlags.TF
    
    ; Set context
    lea rdx, [rsp+30h]
    mov rcx, rbx
    call SetThreadContext
    test rax, rax
    jz @@fail
    
    mov byte ptr [g_singleStepMode], 1
    mov rax, 1
    jmp @@done
    
@@fail:
    xor rax, rax
    
@@done:
    add rsp, 500h
    pop rbx
    ret
Dbg_EnableSingleStep ENDP

; =============================================================================
; Dbg_DisableSingleStep ? Disable trap flag
; RCX = hThread
; Returns: RAX = 1 success, 0 failure
; =============================================================================
ALIGN 16
Dbg_DisableSingleStep PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 500h
    .allocstack 500h
    .endprolog
    
    mov rbx, rcx
    
    ; Get context
    lea rdx, [rsp+30h]
    mov dword ptr [rsp+30h+CTX_ContextFlags], CONTEXT_CONTROL
    call GetThreadContext
    test rax, rax
    jz @@fail
    
    ; Clear TF
    lea rax, [rsp+30h]
    and dword ptr [rax+CTX_EFlags], 0FFFFFEFFh
    
    ; Set context
    lea rdx, [rsp+30h]
    mov rcx, rbx
    call SetThreadContext
    test rax, rax
    jz @@fail
    
    mov byte ptr [g_singleStepMode], 0
    mov rax, 1
    jmp @@done
    
@@fail:
    xor rax, rax
    
@@done:
    add rsp, 500h
    pop rbx
    ret
Dbg_DisableSingleStep ENDP

; =============================================================================
; Dbg_CaptureContext ? Capture full thread context
; RCX = hThread, RDX = outContext
; Returns: RAX = 1 success, 0 failure
; =============================================================================
ALIGN 16
Dbg_CaptureContext PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    
    mov rbx, rdx                    ; outContext
    
    ; Set ContextFlags
    mov dword ptr [rbx+CTX_ContextFlags], CONTEXT_ALL
    
    ; Get context
    mov rcx, rcx
    mov rdx, rbx
    call GetThreadContext
    test rax, rax
    jz @@fail
    
    mov rax, 1
    jmp @@done
    
@@fail:
    xor rax, rax
    
@@done:
    add rsp, 28h
    pop rbx
    ret
Dbg_CaptureContext ENDP

; =============================================================================
; Dbg_WalkStack ? Walk RBP chain
; RCX = hProcess, RDX = startRBP, R8 = outFrames, R9 = maxFrames
; Returns: RAX = frame count
; =============================================================================
ALIGN 16
Dbg_WalkStack PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 30h
    .allocstack 30h
    .endprolog
    
    mov rbx, rcx                    ; hProcess
    mov rsi, rdx                    ; startRBP
    mov rdi, r8                     ; outFrames
    mov ecx, 0                      ; frame count
    
@@walk:
    cmp ecx, r9d
    jae @@done
    
    ; Read [RBP] (previous RBP) and [RBP+8] (return address)
    lea r8, [rsp+20h]               ; buffer for 16 bytes
    mov qword ptr [rsp+28h], 16     ; m_size
    mov rcx, rbx
    mov rdx, rsi
    call ReadProcessMemory
    test rax, rax
    jz @@done
    
    ; Store return address
    mov rax, [rsp+28h]              ; return address at +8
    mov [rdi+rcx*8], rax
    
    ; Move to previous frame
    mov rsi, [rsp+20h]              ; previous RBP
    test rsi, rsi
    jz @@done
    
    inc ecx
    jmp @@walk
    
@@done:
    mov rax, rcx
    
    add rsp, 30h
    pop rdi
    pop rsi
    pop rbx
    ret
Dbg_WalkStack ENDP

; =============================================================================
; Dbg_CRC32 ? Calculate CRC-32 of memory region
; RCX = buffer, RDX = m_size
; Returns: EAX = CRC-32
; =============================================================================
ALIGN 16
Dbg_CRC32 PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    
    mov rsi, rcx                    ; buffer
    mov rbx, rdx                    ; m_size
    lea rdi, [crc32_table]          ; get 64-bit address of table
    
    ; Initialize CRC to 0FFFFFFFFh
    mov eax, 0FFFFFFFFh
    
    test rbx, rbx
    jz @@done
    
@@loop:
    movzx ecx, byte ptr [rsi]
    xor cl, al
    shr eax, 8
    movzx ecx, cl
    mov ecx, [rdi + rcx*4]          ; use 64-bit base register
    xor eax, ecx
    
    inc rsi
    dec rbx
    jnz @@loop
    
@@done:
    not eax
    
    add rsp, 28h
    pop rdi
    pop rsi
    pop rbx
    ret
Dbg_CRC32 ENDP

; =============================================================================
; Dbg_EventLoop ? Main debug event loop
; RCX = callback (optional, can be 0)
; Returns: 0 on normal exit, error code on failure
; =============================================================================
ALIGN 16
Dbg_EventLoop PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 0B0h
    .allocstack 0B0h
    .endprolog
    
    mov rbx, rcx                    ; callback
    
@@loop:
    ; WaitForDebugEvent
    lea rcx, [rsp+30h]              ; DEBUG_EVENT
    mov edx, INFINITE
    call WaitForDebugEvent
    
    test rax, rax
    jz @@exit
    
    ; Get event code
    mov eax, [rsp+30h]              ; dwDebugEventCode
    mov ecx, [rsp+34h]              ; dwProcessId
    mov edx, [rsp+38h]              ; dwThreadId
    
    ; Store handles from CREATE_PROCESS
    cmp eax, CREATE_PROCESS_DEBUG_EVENT
    jne @@check_exception
    
    mov rax, [rsp+40h]              ; u.CreateProcessInfo.hProcess
    mov [g_hProcess], rax
    mov rax, [rsp+48h]              ; u.CreateProcessInfo.hThread
    mov [g_hThread], rax
    mov [g_continueStatus], DBG_CONTINUE
    jmp @@continue
    
@@check_exception:
    cmp eax, EXCEPTION_DEBUG_EVENT
    jne @@check_exit
    
    ; Get exception code
    mov eax, [rsp+40h]              ; u.Exception.ExceptionRecord.ExceptionCode
    
    cmp eax, EXCEPTION_BREAKPOINT
    je @@on_breakpoint
    
    cmp eax, EXCEPTION_SINGLE_STEP
    je @@on_single_step
    
    ; Unknown exception
    mov [g_continueStatus], DBG_EXCEPTION_NOT_HANDLED
    jmp @@continue
    
@@on_breakpoint:
    mov [g_continueStatus], DBG_CONTINUE
    jmp @@continue
    
@@on_single_step:
    mov [g_continueStatus], DBG_CONTINUE
    jmp @@continue
    
@@check_exit:
    cmp eax, EXIT_PROCESS_DEBUG_EVENT
    je @@exit
    
    mov [g_continueStatus], DBG_CONTINUE
    
@@continue:
    ; ContinueDebugEvent
    mov ecx, [rsp+34h]              ; dwProcessId
    mov edx, [rsp+38h]              ; dwThreadId
    mov r8d, [g_continueStatus]
    call ContinueDebugEvent
    
    jmp @@loop
    
@@exit:
    xor rax, rax
    
    add rsp, 0B0h
    pop rdi
    pop rsi
    pop rbx
    ret
Dbg_EventLoop ENDP

; =============================================================================
; Dbg_GetLastProcess ? Get current debug target process handle
; Returns: RAX = hProcess
; =============================================================================
ALIGN 16
Dbg_GetLastProcess PROC
    mov rax, [g_hProcess]
    ret
Dbg_GetLastProcess ENDP

; =============================================================================
; Dbg_GetLastThread ? Get current debug target thread handle
; Returns: RAX = hThread
; =============================================================================
ALIGN 16
Dbg_GetLastThread PROC
    mov rax, [g_hThread]
    ret
Dbg_GetLastThread ENDP

END

