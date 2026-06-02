; ============================================
; linker_ir_harness_crash.asm
; Diagnostic harness with pre-crash markers and UD2 traps
; ============================================

option casemap:none

include linker_ir.inc
include arena_alloc.inc

EXTERN ArenaReserve : PROC
EXTERN ArenaAllocate : PROC
EXTERN ArenaRelease : PROC
EXTERN SealLinkerIR : PROC
EXTERN CoffLinkerRunWithArena : PROC
EXTERN PEFinalizerConsumeIR : PROC
EXTERN FlushPEToDisk : PROC

EXTERN __imp_GetStdHandle : QWORD
EXTERN __imp_WriteFile : QWORD
EXTERN __imp_CreateFileA : QWORD
EXTERN __imp_CloseHandle : QWORD
EXTERN __imp_ExitProcess : QWORD

PUBLIC g_TraceBreadcrumb

.data

g_TraceBreadcrumb dd 0
g_UseIRMode       db 0

sz_mode_legacy    db "--mode legacy", 0
sz_mode_ir        db "--mode ir", 0
sz_marker_trap1   db "d:/trap1_callsite_reached.marker", 0
sz_marker_trap2   db "d:/trap2_callee_entered.marker", 0
sz_marker_success db "d:/harness_success.marker", 0
sz_crash_marker   db "d:/harness_crash.marker", 0
sz_out_legacy     db "d:/out_legacy.exe", 0
sz_out_ir         db "d:/out_ir.exe", 0
sz_preflight      db "d:/write_test.bin", 0
PreflightData     db "PREFLIGHT_OK", 0
PreflightLen      equ ($ - PreflightData)
sz_dummy_path     db "d:/linker_ir_dummy.obj", 0
sz_ok             db "Harness completed.", 13, 10
sz_ok_len         equ ($ - sz_ok)

MarkerByte        db "X"
TempWritten       dd 0
SectionTableBuf   db 1024 dup(0)
RawOutputBuf      db 1048576 dup(0)

.code

WriteMarkerFile PROC
    ; RCX = filename ASCIIZ
    push rbx
    sub rsp, 40h

    mov rbx, rcx
    mov rcx, rbx
    mov rdx, 40000000h          ; GENERIC_WRITE
    xor r8, r8                  ; share = 0
    xor r9, r9                  ; security = NULL
    mov qword ptr [rsp+20h], 2  ; CREATE_ALWAYS
    mov qword ptr [rsp+28h], 80h ; FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+30h], 0  ; template = NULL
    call qword ptr [__imp_CreateFileA]

    cmp rax, -1
    je short WMF_DONE

    mov rbx, rax
    mov rcx, rbx
    lea rdx, MarkerByte
    mov r8, 1
    lea r9, TempWritten
    mov qword ptr [rsp+20h], 0
    call qword ptr [__imp_WriteFile]

    mov rcx, rbx
    call qword ptr [__imp_CloseHandle]

WMF_DONE:
    add rsp, 40h
    pop rbx
    ret
WriteMarkerFile ENDP

CrashWithCode PROC
    ; RCX = crash code
    mov [g_TraceBreadcrumb], ecx
    lea rcx, sz_crash_marker
    call WriteMarkerFile
    ud2
    mov ecx, [g_TraceBreadcrumb]
    call qword ptr [__imp_ExitProcess]
CrashWithCode ENDP

WritePreflightTest PROC
    push rbx
    sub rsp, 40h

    lea rcx, sz_preflight
    mov rdx, 40000000h
    xor r8, r8
    xor r9, r9
    mov qword ptr [rsp+20h], 2
    mov qword ptr [rsp+28h], 80h
    mov qword ptr [rsp+30h], 0
    call qword ptr [__imp_CreateFileA]

    cmp rax, -1
    je short WPT_FAIL

    mov rbx, rax
    mov rcx, rbx
    lea rdx, PreflightData
    mov r8, PreflightLen
    lea r9, TempWritten
    mov qword ptr [rsp+20h], 0
    call qword ptr [__imp_WriteFile]

    mov rcx, rbx
    call qword ptr [__imp_CloseHandle]
    mov eax, 1
    jmp short WPT_DONE

WPT_FAIL:
    xor eax, eax

WPT_DONE:
    add rsp, 40h
    pop rbx
    ret
WritePreflightTest ENDP

ConsoleWrite PROC
    ; RCX = buffer, RDX = length
    push rbx
    sub rsp, 40h

    mov rbx, rcx
    mov rcx, -11                 ; STD_OUTPUT_HANDLE
    call qword ptr [__imp_GetStdHandle]

    mov rcx, rax
    mov rdx, rbx
    mov r8, rdx
    lea r9, TempWritten
    mov qword ptr [rsp+20h], 0
    call qword ptr [__imp_WriteFile]

    add rsp, 40h
    pop rbx
    ret
ConsoleWrite ENDP

mainCRTStartup PROC
    sub rsp, 40h

    mov dword ptr [g_TraceBreadcrumb], 10h

    ; Minimal argument parsing: detect "--mode ir" if present.
    mov byte ptr [g_UseIRMode], 0

    mov rax, qword ptr gs:[60h]
    mov rax, [rax+20h]
    mov rsi, [rax+70h]           ; CommandLine.Buffer

.skip_exe:
    lodsb
    test al, al
    jz short MODE_DONE
    cmp al, ' '
    jne short SKIP_EXE

SKIP_EXE:
    lodsb
    test al, al
    jz short MODE_DONE
    cmp al, ' '
    jne short SKIP_EXE

SKIP_SPACES:
    lodsb
    cmp al, ' '
    je short SKIP_SPACES
    dec rsi

    cmp word ptr [rsi], 2D2Dh    ; "--"
    jne short MODE_DONE
    add rsi, 2
    cmp dword ptr [rsi], 65646F6Dh ; "mode"
    jne short MODE_DONE
    add rsi, 4

SKIP_MODE_SPACES:
    lodsb
    cmp al, ' '
    je short SKIP_MODE_SPACES
    dec rsi

    cmp byte ptr [rsi], 'i'
    jne short MODE_DONE
    mov byte ptr [g_UseIRMode], 1

MODE_DONE:
    mov dword ptr [g_TraceBreadcrumb], 20h

    call WritePreflightTest
    test eax, eax
    jnz short PREFLIGHT_OK
    mov ecx, 41h
    call CrashWithCode

PREFLIGHT_OK:
    mov dword ptr [g_TraceBreadcrumb], 30h

    lea rcx, sz_dummy_path
    call CoffLinkerRunWithArena

    mov dword ptr [g_TraceBreadcrumb], 40h
    test rax, rax
    jnz short LINKER_OK
    mov ecx, 52h
    call CrashWithCode

LINKER_OK:
    mov rbx, rax
    mov dword ptr [g_TraceBreadcrumb], 50h

    lea r12, SectionTableBuf
    lea r13, RawOutputBuf
    mov rcx, rbx
    mov rdx, r12
    mov r8, r13
    call PEFinalizerConsumeIR

    mov dword ptr [g_TraceBreadcrumb], 60h
    test eax, eax
    jnz short CONSUME_OK
    mov ecx, 62h
    call CrashWithCode

CONSUME_OK:
    mov dword ptr [g_TraceBreadcrumb], 70h

    cmp byte ptr [g_UseIRMode], 0
    je short LEGACY_OUT
    lea r15, sz_out_ir
    jmp short OUT_SELECTED

LEGACY_OUT:
    lea r15, sz_out_legacy

OUT_SELECTED:
    mov dword ptr [g_TraceBreadcrumb], 80h

    ; Trap 1: prove call site reached before flush.
    lea rcx, sz_marker_trap1
    call WriteMarkerFile
    mov dword ptr [g_TraceBreadcrumb], 81h
    ud2

    ; If execution continues (it should not), attempt flush.
    call FlushPEToDisk
    mov dword ptr [g_TraceBreadcrumb], 90h
    test eax, eax
    jnz short FLUSH_OK
    mov ecx, 92h
    call CrashWithCode

FLUSH_OK:
    mov dword ptr [g_TraceBreadcrumb], 0A0h
    lea rcx, sz_marker_success
    call WriteMarkerFile
    lea rcx, sz_ok
    mov rdx, sz_ok_len
    call ConsoleWrite
    mov ecx, [g_TraceBreadcrumb]
    call qword ptr [__imp_ExitProcess]

    xor eax, eax
    add rsp, 40h
    ret
mainCRTStartup ENDP

END
