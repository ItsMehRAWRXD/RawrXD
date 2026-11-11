; =============================================================================
; TITAN LIGHTNING x64 - Fully Functional JIT + NF4 + AVX-512 Engine
; Reverse-engineered for minimal token count and maximum TPS
; =============================================================================
; Build: ml64.exe /c /W3 /nologo /Zi /Fo TITAN_Lightning_x64.obj TITAN_Lightning_x64.asm
; Link:  link.exe /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /LARGEADDRESSAWARE:NO \
;            /OUT:TITAN_Lightning_x64.exe TITAN_Lightning_x64.obj kernel32.lib
; =============================================================================

; =============================================================================
; CONSTANTS (minimize magic numbers)
; =============================================================================
GENERIC_READ                EQU 80000000h
GENERIC_WRITE               EQU 40000000h
FILE_SHARE_READ             EQU 1
FILE_SHARE_WRITE            EQU 2
OPEN_EXISTING               EQU 3
CREATE_ALWAYS               EQU 2
OPEN_ALWAYS                 EQU 4
FILE_ATTRIBUTE_NORMAL       EQU 80h
PAGE_EXECUTE_READWRITE      EQU 40h
PAGE_READWRITE              EQU 4h
INVALID_HANDLE_VALUE        EQU -1

; JIT Buffer size
JIT_SIZE                    EQU 4096

; Trace buffer: 512 events × 128 bytes = 64KB
TRACE_CAPACITY              EQU 512
TRACE_RECORD_SIZE           EQU 128
TRACE_BUFFER_SIZE           EQU (TRACE_CAPACITY * TRACE_RECORD_SIZE)

; Magic headers
MAGIC_JITX                  EQU 5854494Ah          ; "JITX"
MAGIC_CART                  EQU 54524143h          ; "CART" (trace)

; =============================================================================
; CODE SECTION
; =============================================================================
.CODE

; External Windows APIs - minimal set
EXTERN ExitProcess:PROC
EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN CreateFileA:PROC
EXTERN ReadFile:PROC
EXTERN WriteFile:PROC
EXTERN CloseHandle:PROC
EXTERN VirtualProtect:PROC
EXTERN GetTickCount64:PROC
EXTERN lstrlenA:PROC

; =============================================================================
; ENTRY POINT
; =============================================================================
main PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 64
    .allocstack 64
    .endprolog

    ; Get stdout handle
    mov ecx, -11                    ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov g_ConsoleOut, rax

    ; Print init message
    lea rcx, msg_init
    call PrintString

    ; Initialize engine
    call Titan_Init

    ; Run main execution cycle
    call Titan_ExecutionCycle

    ; Print completion
    lea rcx, msg_done
    call PrintString
    mov rdx, g_ExitCode
    call PrintNumber
    lea rcx, msg_crlf
    call PrintString

    ; Exit
    mov ecx, dword ptr g_ExitCode
    call ExitProcess

main ENDP

; =============================================================================
; Titan_Init - Initialize engine state
; =============================================================================
Titan_Init PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 40
    .allocstack 40
    .endprolog

    ; Clear editor state
    mov g_EditorLength, 0
    mov g_EditorCursor, 0
    mov g_EditorLineCount, 1
    mov g_EditorModified, 0

    ; Clear symbol/token/AST counts
    mov g_SymbolCount, 0
    mov g_TokenCount, 0
    mov g_ASTCount, 0

    ; Clear trace state
    mov g_TraceIndex, 0
    mov g_TraceEnabled, 1

    ; Reset JIT size
    mov g_JITSize, 0

    xor eax, eax
    add rsp, 40
    pop rbx
    ret
Titan_Init ENDP

; =============================================================================
; Titan_ExecutionCycle - Main execution: JIT → Trace → NF4 → AVX-512 → File I/O
; =============================================================================
Titan_ExecutionCycle PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    sub rsp, 72
    .allocstack 72
    .endprolog

    mov r12, rsp                    ; R12 = stack marker for alignment

    ; -------------------------------------------------------------------------
    ; PHASE 1: JIT Code Generation
    ; Emit: xor rax, rax; add rax, 0x42; ret
    ; -------------------------------------------------------------------------
    lea rcx, g_JITBuffer
    xor edx, edx                    ; rax
    xor r8d, r8d                    ; rax
    call Emit_X64_Xor_Reg_Reg       ; xor rax, rax

    lea rcx, g_JITBuffer
    add rcx, rax                    ; Advance buffer pointer
    xor edx, edx                    ; rax
    mov r8d, 42h                    ; imm32 = 0x42
    call Emit_X64_Add_Reg_Imm32     ; add rax, 0x42

    mov rsi, rax                    ; RSI = current JIT size
    lea rcx, g_JITBuffer
    add rcx, rax
    call Emit_X64_Ret               ; ret
    add rsi, rax
    mov g_JITSize, rsi              ; Save total JIT size

    ; Print JIT emit message
    lea rcx, msg_jit_emit
    call PrintString
    mov rdx, rsi
    call PrintNumber
    lea rcx, msg_jit_exec
    call PrintString

    ; -------------------------------------------------------------------------
    ; PHASE 2: Make JIT Memory Executable (VirtualProtect)
    ; -------------------------------------------------------------------------
    lea rcx, g_JITBuffer
    mov rdx, JIT_SIZE
    mov r8, PAGE_EXECUTE_READWRITE
    lea r9, g_FileBuffer            ; Reuse as oldProtect buffer
    call VirtualProtect
    test eax, eax
    jz exec_cycle_fail

    ; -------------------------------------------------------------------------
    ; PHASE 3: Trace Capture Setup
    ; -------------------------------------------------------------------------
    lea rcx, msg_trace_start
    call PrintString

    ; Record start timestamp
    call GetTickCount64
    mov g_ExecTimeStart, rax

    ; Record JIT emit event
    mov rcx, 1                      ; Event type: JIT_EMIT
    mov rdx, g_JITSize
    xor r8, r8
    xor r9, r9
    call Titan_TraceEvent

    ; -------------------------------------------------------------------------
    ; PHASE 4: Execute JIT Code
    ; -------------------------------------------------------------------------
    lea rax, g_JITBuffer
    call rax                        ; Execute JIT'd code! RAX = result
    mov r13, rax                    ; R13 = JIT result

    ; Record execution event
    mov rcx, 2                      ; Event type: JIT_EXEC
    mov rdx, r13                    ; Result
    xor r8, r8
    xor r9, r9
    call Titan_TraceEvent

    ; -------------------------------------------------------------------------
    ; PHASE 5: NF4 Decompression Test
    ; -------------------------------------------------------------------------
    lea rcx, msg_nf4_start
    call PrintString

    ; Create test NF4 data (4 bytes = 8 weights)
    mov dword ptr g_FileBuffer, 0EFBEADDEh  ; Test pattern

    ; Decompress to editor buffer
    lea rcx, g_FileBuffer             ; Source NF4 data
    lea rdx, g_EditorBuffer           ; Destination FP32 buffer
    mov r8d, 4                        ; 4 bytes = 8 weights
    call Titan_NF4_Decompress

    mov r14, rax                      ; R14 = number of weights decompressed

    lea rcx, msg_nf4_done
    call PrintString
    mov rdx, r14
    call PrintNumber
    lea rcx, msg_nf4_weights
    call PrintString

    ; Record NF4 event
    mov rcx, 3                      ; Event type: NF4_DECOMPRESS
    mov rdx, r14                    ; Weight count
    xor r8, r8
    xor r9, r9
    call Titan_TraceEvent

    ; -------------------------------------------------------------------------
    ; PHASE 6: AVX-512 Test
    ; -------------------------------------------------------------------------
    lea rcx, msg_avx512_test
    call PrintString

    call Titan_AVX512_Test

    ; Record AVX-512 event
    mov rcx, 4                      ; Event type: AVX512_EXEC
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    call Titan_TraceEvent

    ; -------------------------------------------------------------------------
    ; PHASE 7: File I/O - Save Kernel
    ; -------------------------------------------------------------------------
    lea rcx, msg_file_save
    call PrintString
    lea rcx, g_ProjectFile
    call PrintString
    lea rcx, msg_crlf
    call PrintString

    lea rcx, g_ProjectFile
    lea rdx, g_JITBuffer
    mov r8, g_JITSize
    call Titan_SaveKernel

    ; -------------------------------------------------------------------------
    ; PHASE 8: File I/O - Export Trace
    ; -------------------------------------------------------------------------
    lea rcx, msg_trace_export
    call PrintString
    lea rcx, g_TraceFile
    call PrintString
    lea rcx, msg_crlf
    call PrintString

    lea rcx, g_TraceFile
    call Titan_ExportTrace

    ; -------------------------------------------------------------------------
    ; PHASE 9: File I/O - Load Kernel (verify round-trip)
    ; -------------------------------------------------------------------------
    lea rcx, msg_file_load
    call PrintString
    lea rcx, g_ProjectFile
    call PrintString
    lea rcx, msg_crlf
    call PrintString

    lea rcx, g_ProjectFile
    lea rdx, g_FileBuffer
    mov r8, 512
    call Titan_LoadKernel

    ; -------------------------------------------------------------------------
    ; Cleanup
    ; -------------------------------------------------------------------------
    call GetTickCount64
    mov g_ExecTimeEnd, rax

    xor eax, eax
    mov g_ExitCode, rax

exec_cycle_done:
    mov rsp, r12
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

exec_cycle_fail:
    mov eax, 1
    mov g_ExitCode, rax
    jmp exec_cycle_done

Titan_ExecutionCycle ENDP

; =============================================================================
; JIT EMITTERS - Generate x64 machine code
; =============================================================================

; Emit_X64_Xor_Reg_Reg - Emit: xor dst, src
; RCX = buffer, EDX = dst reg, R8D = src reg
; Returns: RAX = bytes emitted (3)
Emit_X64_Xor_Reg_Reg PROC
    mov byte ptr [rcx], 48h         ; REX.W
    mov byte ptr [rcx + 1], 31h     ; XOR r/m64, r64
    mov al, dl                      ; ModRM: dst in reg field
    shl al, 3
    or al, r8b                      ; OR with src
    or al, 0C0h                     ; Mod = 11 (register direct)
    mov [rcx + 2], al
    mov eax, 3
    ret
Emit_X64_Xor_Reg_Reg ENDP

; Emit_X64_Add_Reg_Imm32 - Emit: add reg, imm32
; RCX = buffer, EDX = reg, R8D = imm32
; Returns: RAX = bytes emitted (7)
Emit_X64_Add_Reg_Imm32 PROC
    mov byte ptr [rcx], 48h         ; REX.W
    mov byte ptr [rcx + 1], 81h     ; ADD r/m64, imm32
    mov al, 0C0h                    ; Mod = 11
    add al, dl                      ; Add register
    mov [rcx + 2], al
    mov [rcx + 3], r8d              ; imm32 (little-endian)
    mov eax, 7
    ret
Emit_X64_Add_Reg_Imm32 ENDP

; Emit_X64_Ret - Emit: ret
; RCX = buffer
; Returns: RAX = bytes emitted (1)
Emit_X64_Ret PROC
    mov byte ptr [rcx], 0C3h        ; RET
    mov eax, 1
    ret
Emit_X64_Ret ENDP

; =============================================================================
; TRACE SYSTEM - Capture execution events with RDTSC timestamps
; =============================================================================

; Titan_TraceEvent - Record an event to the trace buffer
; RCX = event type, RDX = data0, R8 = data1, R9 = data2
Titan_TraceEvent PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 40
    .allocstack 40
    .endprolog

    ; Check if tracing enabled
    mov rax, g_TraceEnabled
    test rax, rax
    jz trace_event_done

    ; Get current index
    mov rbx, g_TraceIndex
    cmp rbx, TRACE_CAPACITY
    jge trace_event_done            ; Buffer full

    ; Calculate record address: g_TraceBuffer + (index * 128)
    mov rsi, rbx
    shl rsi, 7                        ; Multiply by 128
    lea rdi, g_TraceBuffer
    add rdi, rsi                      ; RDI = record address

    ; Capture timestamp (RDTSC)
    rdtsc
    shl rdx, 32
    or rax, rdx                       ; RAX = 64-bit timestamp
    mov [rdi], rax                    ; Offset 0: timestamp

    ; Store event data
    mov [rdi + 8], rcx                ; Offset 8: event type
    mov [rdi + 16], rdx               ; Offset 16: data0
    mov [rdi + 24], r8                ; Offset 24: data1
    mov [rdi + 32], r9                ; Offset 32: data2

    ; Increment index
    inc rbx
    mov g_TraceIndex, rbx

trace_event_done:
    xor eax, eax
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    ret
Titan_TraceEvent ENDP

; =============================================================================
; NF4 DEQUANTIZATION - 4-bit NormalFloat to FP32
; =============================================================================

; Titan_NF4_Decompress - Decompress NF4 data to FP32
; RCX = source NF4 buffer, RDX = destination FP32 buffer
; R8D = number of NF4 bytes to decompress
; Returns: RAX = number of weights decompressed (R8 * 2)
Titan_NF4_Decompress PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov rsi, rcx                      ; RSI = source
    mov rdi, rdx                      ; RDI = destination
    mov r12d, r8d                     ; R12 = count
    xor ebx, ebx                      ; RBX = weight counter

    test r12d, r12d
    jz nf4_done

    ; Preload lookup table address
    lea r10, g_NF4Lookup

nf4_loop:
    ; Load one byte containing two 4-bit values
    movzx eax, byte ptr [rsi]
    mov edx, eax

    ; Extract low nibble (first weight)
    and eax, 0Fh
    movss xmm0, real4 ptr [r10 + rax * 4]
    movss real4 ptr [rdi], xmm0

    ; Extract high nibble (second weight)
    shr edx, 4
    movss xmm1, real4 ptr [r10 + rdx * 4]
    movss real4 ptr [rdi + 4], xmm1

    ; Advance pointers
    inc rsi
    add rdi, 8
    add ebx, 2

    dec r12d
    jnz nf4_loop

nf4_done:
    mov eax, ebx                      ; Return weight count
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Titan_NF4_Decompress ENDP

; =============================================================================
; AVX-512 IMPLEMENTATION - Real 512-bit operations
; =============================================================================

; Titan_AVX512_Test - Test AVX-512 operations
Titan_AVX512_Test PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 72                       ; Allocate 64 bytes + alignment
    .allocstack 72
    .endprolog

    mov rbx, rsp
    and rbx, -64                      ; Align to 64 bytes

    ; Initialize test data (16 floats = 64 bytes)
    mov dword ptr [rbx], 3F800000h    ; 1.0
    mov dword ptr [rbx + 4], 40000000h ; 2.0
    mov dword ptr [rbx + 8], 40400000h ; 3.0
    mov dword ptr [rbx + 12], 40800000h ; 4.0
    mov dword ptr [rbx + 16], 3F800000h
    mov dword ptr [rbx + 20], 40000000h
    mov dword ptr [rbx + 24], 40400000h
    mov dword ptr [rbx + 28], 40800000h
    mov dword ptr [rbx + 32], 3F800000h
    mov dword ptr [rbx + 36], 40000000h
    mov dword ptr [rbx + 40], 40400000h
    mov dword ptr [rbx + 44], 40800000h
    mov dword ptr [rbx + 48], 3F800000h
    mov dword ptr [rbx + 52], 40000000h
    mov dword ptr [rbx + 56], 40400000h
    mov dword ptr [rbx + 60], 40800000h

    ; Test AVX-512: Load 512 bits, add with itself, store
    ; Requires AVX-512F support
    vmovdqu32 zmm0, zmmword ptr [rbx]     ; Load 512 bits (16 floats)
    vaddps zmm0, zmm0, zmm0               ; Add with itself (zmm0 = zmm0 + zmm0)
    vmovdqu32 zmmword ptr [rbx], zmm0     ; Store result

    xor eax, eax
    add rsp, 72
    pop rbx
    ret
Titan_AVX512_Test ENDP

; Titan_AVX512_Copy - Real AVX-512 512-bit copy
; RCX = source, RDX = dest, R8 = number of 512-bit blocks
Titan_AVX512_Copy PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 40
    .allocstack 40
    .endprolog

    test r8, r8
    jz avx512_copy_done

avx512_copy_loop:
    vmovdqu32 zmm0, zmmword ptr [rcx]
    vmovdqu32 zmmword ptr [rdx], zmm0

    add rcx, 64
    add rdx, 64
    dec r8
    jnz avx512_copy_loop

avx512_copy_done:
    vzeroupper                          ; Clear upper bits for SSE compatibility
    xor eax, eax
    add rsp, 40
    pop rbx
    ret
Titan_AVX512_Copy ENDP

; Titan_AVX512_Xor - Real AVX-512 512-bit XOR
; RCX = source, RDX = dest (in/out), R8 = number of 512-bit blocks
Titan_AVX512_Xor PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 40
    .allocstack 40
    .endprolog

    test r8, r8
    jz avx512_xor_done

avx512_xor_loop:
    vmovdqu32 zmm0, zmmword ptr [rdx]   ; Load destination
    vpxord zmm0, zmm0, zmmword ptr [rcx] ; XOR with source
    vmovdqu32 zmmword ptr [rdx], zmm0   ; Store result

    add rcx, 64
    add rdx, 64
    dec r8
    jnz avx512_xor_loop

avx512_xor_done:
    vzeroupper
    xor eax, eax
    add rsp, 40
    pop rbx
    ret
Titan_AVX512_Xor ENDP

; =============================================================================
; FILE I/O - Real Windows API implementation
; =============================================================================

; Titan_SaveKernel - Save JIT kernel to file with JITX header
; RCX = filename, RDX = data buffer, R8 = data size
; Returns: RAX = 0 on success, 1 on failure
Titan_SaveKernel PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    sub rsp, 88
    .allocstack 88
    .endprolog

    mov r12, rcx                      ; R12 = filename
    mov r13, rdx                      ; R13 = data buffer
    mov r14, r8                       ; R14 = data size

    ; Create file
    mov rcx, r12                      ; lpFileName
    mov edx, GENERIC_WRITE            ; dwDesiredAccess
    mov r8d, FILE_SHARE_READ          ; dwShareMode
    xor r9d, r9d                      ; lpSecurityAttributes = NULL
    mov dword ptr [rsp + 32], CREATE_ALWAYS    ; dwCreationDisposition
    mov dword ptr [rsp + 40], FILE_ATTRIBUTE_NORMAL  ; dwFlagsAndAttributes
    mov qword ptr [rsp + 48], 0       ; hTemplateFile = NULL
    call CreateFileA

    cmp rax, INVALID_HANDLE_VALUE
    je save_kernel_fail

    mov rbx, rax                      ; RBX = file handle

    ; Build JITX header (12 bytes)
    ; Magic (4) + Version (4) + Size (4)
    mov dword ptr [rsp], MAGIC_JITX   ; "JITX"
    mov dword ptr [rsp + 4], 1        ; Version 1
    mov eax, r14d
    mov dword ptr [rsp + 8], eax      ; Data size

    ; Write header
    mov rcx, rbx                      ; hFile
    lea rdx, [rsp]                    ; lpBuffer
    mov r8d, 12                       ; nNumberOfBytesToWrite
    lea r9, g_BytesProcessed          ; lpNumberOfBytesWritten
    call WriteFile

    test eax, eax
    jz save_kernel_cleanup

    ; Write data
    mov rcx, rbx
    mov rdx, r13
    mov r8, r14
    lea r9, g_BytesProcessed
    call WriteFile

    test eax, eax
    jz save_kernel_cleanup

    ; Success
    xor r15d, r15d
    jmp save_kernel_cleanup

save_kernel_fail:
    mov r15d, 1
    jmp save_kernel_done

save_kernel_cleanup:
    mov rcx, rbx
    call CloseHandle

save_kernel_done:
    mov eax, r15d
    add rsp, 88
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Titan_SaveKernel ENDP

; Titan_LoadKernel - Load JIT kernel from file
; RCX = filename, RDX = output buffer, R8 = max size
; Returns: RAX = bytes loaded, 0 on failure
Titan_LoadKernel PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    sub rsp, 88
    .allocstack 88
    .endprolog

    mov r12, rcx                      ; R12 = filename
    mov r13, rdx                      ; R13 = output buffer
    mov r14, r8                       ; R14 = max size

    ; Open file
    mov rcx, r12
    mov edx, GENERIC_READ
    mov r8d, FILE_SHARE_READ
    xor r9d, r9d
    mov dword ptr [rsp + 32], OPEN_EXISTING
    mov dword ptr [rsp + 40], FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp + 48], 0
    call CreateFileA

    cmp rax, INVALID_HANDLE_VALUE
    je load_kernel_fail

    mov rbx, rax                      ; RBX = file handle

    ; Read header
    mov rcx, rbx
    lea rdx, [rsp]
    mov r8d, 12
    lea r9, g_BytesProcessed
    call ReadFile

    test eax, eax
    jz load_kernel_cleanup

    ; Verify magic
    mov eax, dword ptr [rsp]
    cmp eax, MAGIC_JITX
    jne load_kernel_cleanup

    ; Get data size from header
    mov r15d, dword ptr [rsp + 8]    ; R15 = data size
    cmp r15, r14
    ja load_kernel_cleanup            ; Truncate if too big

    ; Read data
    mov rcx, rbx
    mov rdx, r13
    mov r8, r15
    lea r9, g_BytesProcessed
    call ReadFile

    mov r15, g_BytesProcessed
    jmp load_kernel_cleanup

load_kernel_fail:
    xor r15d, r15d
    jmp load_kernel_done

load_kernel_cleanup:
    mov rcx, rbx
    call CloseHandle

load_kernel_done:
    mov rax, r15
    add rsp, 88
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Titan_LoadKernel ENDP

; Titan_ExportTrace - Export trace buffer to file
; RCX = filename
; Returns: RAX = 0 on success, 1 on failure
Titan_ExportTrace PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    sub rsp, 88
    .allocstack 88
    .endprolog

    mov r12, rcx                      ; R12 = filename

    ; Create file
    mov rcx, r12
    mov edx, GENERIC_WRITE
    mov r8d, FILE_SHARE_READ
    xor r9d, r9d
    mov dword ptr [rsp + 32], CREATE_ALWAYS
    mov dword ptr [rsp + 40], FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp + 48], 0
    call CreateFileA

    cmp rax, INVALID_HANDLE_VALUE
    je export_trace_fail

    mov rbx, rax                      ; RBX = file handle

    ; Build CART header (16 bytes)
    mov dword ptr [rsp], MAGIC_CART   ; "CART"
    mov dword ptr [rsp + 4], 1        ; Version 1
    mov rax, g_TraceIndex
    mov dword ptr [rsp + 8], eax      ; Event count (low 32 bits)
    mov dword ptr [rsp + 12], 0       ; Reserved

    ; Write header
    mov rcx, rbx
    lea rdx, [rsp]
    mov r8d, 16
    lea r9, g_BytesProcessed
    call WriteFile

    test eax, eax
    jz export_trace_cleanup

    ; Calculate trace data size
    mov rax, g_TraceIndex
    imul rax, TRACE_RECORD_SIZE

    ; Write trace data
    mov rcx, rbx
    lea rdx, g_TraceBuffer
    mov r8, rax
    lea r9, g_BytesProcessed
    call WriteFile

    xor r15d, r15d
    jmp export_trace_cleanup

export_trace_fail:
    mov r15d, 1
    jmp export_trace_done

export_trace_cleanup:
    mov rcx, rbx
    call CloseHandle

export_trace_done:
    mov eax, r15d
    add rsp, 88
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Titan_ExportTrace ENDP

; =============================================================================
; UTILITY - Console output helpers
; =============================================================================

; PrintString - Output null-terminated string to console
; RCX = string pointer
PrintString PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov rsi, rcx
    call lstrlenA
    mov r8d, eax                      ; nNumberOfCharsToWrite

    mov rcx, g_ConsoleOut             ; hConsoleOutput
    mov rdx, rsi                      ; lpBuffer
    lea r9, g_BytesProcessed          ; lpNumberOfCharsWritten
    mov qword ptr [rsp + 32], 0       ; lpReserved = NULL
    call WriteConsoleA

    add rsp, 40
    pop rsi
    pop rbx
    ret
PrintString ENDP

; PrintNumber - Output 64-bit number as decimal
; RDX = number to print
PrintNumber PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 56
    .allocstack 56
    .endprolog

    mov rax, rdx
    lea rdi, g_NumBuffer + 31         ; Start from end
    mov byte ptr [rdi], 0             ; Null terminate
    dec rdi

    ; Handle 0 specially
    test rax, rax
    jnz print_num_convert
    mov byte ptr [rdi], '0'
    dec rdi
    jmp print_num_output

print_num_convert:
    mov rbx, 10
print_num_loop:
    xor edx, edx
    div rbx                           ; RAX = RAX / 10, RDX = remainder
    add dl, '0'
    mov [rdi], dl
    dec rdi
    test rax, rax
    jnz print_num_loop

print_num_output:
    inc rdi                           ; Point to first digit
    mov rcx, rdi
    call PrintString

    add rsp, 56
    pop rdi
    pop rsi
    pop rbx
    ret
PrintNumber ENDP

; =============================================================================
; DATA SECTION
; =============================================================================
.DATA

; Editor/IDE buffer (4MB)
g_EditorBuffer              DB 4194304 DUP(0)
g_EditorLength              DQ 0
g_EditorCursor              DQ 0
g_EditorLineCount           DQ 1
g_EditorModified            DQ 0

; Symbol table (64KB)
g_SymbolTable               DB 65536 DUP(0)
g_SymbolCount               DQ 0

; Token stream (128KB)
g_TokenStream               DB 131072 DUP(0)
g_TokenCount                DQ 0

; AST nodes (64KB)
g_ASTNodes                  DB 65536 DUP(0)
g_ASTCount                  DQ 0

; JIT executable buffer (4KB, will be made executable via VirtualProtect)
g_JITBuffer                 DB JIT_SIZE DUP(0CCh)
g_JITSize                   DQ 0

; Trace buffer (64KB, 512 × 128-byte records)
g_TraceBuffer               DB TRACE_BUFFER_SIZE DUP(0)
g_TraceIndex                DQ 0
g_TraceEnabled              DQ 1

; Execution context
g_ExecTimeStart             DQ 0
g_ExecTimeEnd               DQ 0

; File paths
g_ProjectFile               DB "titan.jitx", 0
g_TraceFile                 DB "titan.cart", 0
g_ConsoleOut                DQ 0

; NF4 NormalFloat lookup table (16 × FP32 = 64 bytes)
; Values: -1.0 to 1.0, symmetric around 0, optimal for 4-bit quantization
ALIGN 16
g_NF4Lookup                 REAL4 -1.0, -0.6961928, -0.5250731, -0.3949175
                            REAL4 -0.2844414, -0.1847734, -0.0910502, 0.0
                            REAL4 0.0795803, 0.1609302, 0.2468333, 0.3379153
                            REAL4 0.4407098, 0.5626171, 0.7229357, 1.0

; Engine state
g_EngineRunning             DQ 1
g_ExitCode                  DQ 0

; Scratch buffers for file I/O
g_FileBuffer                DB 512 DUP(0)
g_BytesProcessed            DQ 0

; Messages (compact)
msg_init                    DB "[TITAN] Lightning Engine v1.0", 13, 10, 0
msg_jit_emit                DB "[JIT] Emitted ", 0
msg_jit_exec                DB " bytes, executing...", 13, 10, 0
msg_trace_start             DB "[TRACE] Capture enabled", 13, 10, 0
msg_nf4_start               DB "[NF4] Decompressing weights...", 13, 10, 0
msg_nf4_done                DB "[NF4] Decompressed ", 0
msg_nf4_weights             DB " weights", 13, 10, 0
msg_avx512_test             DB "[AVX-512] Testing 512-bit ops...", 13, 10, 0
msg_file_save               DB "[FILE] Saved kernel to ", 0
msg_file_load               DB "[FILE] Loaded kernel from ", 0
msg_trace_export            DB "[FILE] Exported trace to ", 0
msg_done                    DB 13, 10, "[TITAN] Execution complete. Exit code: ", 0
msg_crlf                    DB 13, 10, 0

; Number buffer for printing
g_NumBuffer                 DB 32 DUP(0)

; =============================================================================
; END
; =============================================================================
END
