; ============================================
; linker_ir_harness_crash.asm — CRASH DIAGNOSTIC VERSION
; ============================================
; Replaces int3 with ud2 + pre-crash file markers.
; Each trap writes a marker file before crashing.
; ============================================

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
sz_preflight      db "d:/write_test.bin", 0
sz_dummy_path     db "d:/linker_ir_dummy.obj", 0
sz_out_legacy     db "d:/out_legacy.exe", 0
sz_out_ir         db "d:/out_ir.exe", 0

sz_banner         db "LinkerIR Harness", 13, 10
sz_banner_len     equ ($ - sz_banner)
sz_err_args       db "Usage: harness [--mode legacy|--mode ir]", 13, 10
sz_err_args_len   equ ($ - sz_err_args)
sz_ok             db "Harness completed.", 13, 10
sz_ok_len         equ ($ - sz_ok)

SectionTableBuf   db 1024 dup(0)
RawOutputBuf      db (1024 * 1024) dup(0)
PreflightData     db "PREFLIGHT_OK", 0
PreflightLen      equ ($ - PreflightData)
MarkerByte        db "X"
TempWritten       dd 0

.code

WriteMarkerFile PROC
    sub rsp, 40
    mov r10, rcx

    mov rcx, r10
    mov rdx, 40000000h
    xor r8, r8
    xor r9, r9
    mov qword ptr [rsp+32], 2
    mov qword ptr [rsp+40], 80h
    mov qword ptr [rsp+48], 0
    call qword ptr [__imp_CreateFileA]

    cmp rax, -1
    je short wm_done

    mov rbx, rax
    mov rcx, rbx
    lea rdx, MarkerByte
    mov r8, 1
    lea r9, TempWritten
    mov qword ptr [rsp+32], 0
    call qword ptr [__imp_WriteFile]

    mov rcx, rbx
    call qword ptr [__imp_CloseHandle]

wm_done:
    add rsp, 40
    ret
WriteMarkerFile ENDP

CrashWithCode PROC
    sub rsp, 40
    mov [g_TraceBreadcrumb], ecx
    lea rcx, sz_crash_marker
    call WriteMarkerFile
    ud2
    mov ecx, [g_TraceBreadcrumb]
    call qword ptr [__imp_ExitProcess]
    add rsp, 40
    ret
CrashWithCode ENDP

WritePreflightTest PROC
    sub rsp, 40

    lea rcx, sz_preflight
    mov rdx, 40000000h
    xor r8, r8
    xor r9, r9
    mov qword ptr [rsp+32], 2
    mov qword ptr [rsp+40], 80h
    mov qword ptr [rsp+48], 0
    call qword ptr [__imp_CreateFileA]

    cmp rax, -1
    je short wpt_fail

    mov rbx, rax
    mov rcx, rbx
    lea rdx, PreflightData
    mov r8, PreflightLen
    lea r9, TempWritten
    mov qword ptr [rsp+32], 0
    call qword ptr [__imp_WriteFile]

    mov rcx, rbx
    call qword ptr [__imp_CloseHandle]
    mov eax, 1
    jmp short wpt_done

wpt_fail:
    xor eax, eax

wpt_done:
    add rsp, 40
    ret
WritePreflightTest ENDP

ConsoleWrite PROC
    sub rsp, 40
    mov r10, rcx
    mov r11, rdx
    mov ecx, -11
    call qword ptr [__imp_GetStdHandle]
    mov rcx, rax
    mov rdx, r10
    mov r8, r11
    lea r9, TempWritten
    mov qword ptr [rsp+32], 0
    call qword ptr [__imp_WriteFile]
    add rsp, 40
    ret
ConsoleWrite ENDP

mainCRTStartup PROC
    sub rsp, 40

    mov dword ptr [g_TraceBreadcrumb], 10h

    mov rax, qword ptr gs:[60h]
    mov rax, [rax+20h]
    mov rsi, [rax+70h]

skip_exe:
    lodsb
    test al, al
    jz no_args
    cmp al, 20h
    jne skip_exe

skip_spaces:
    lodsb
    cmp al, 20h
    je skip_spaces
    dec rsi

    cmp word ptr [rsi], 2D2Dh
    jne no_args
    add rsi, 2
    cmp dword ptr [rsi], 65646F6Dh
    jne no_args
    add rsi, 4

    cmp byte ptr [rsi], 20h
    jne mode_check
    inc rsi

mode_check:
    cmp byte ptr [rsi], 'l'
    je mode_legacy
    cmp byte ptr [rsi], 'i'
    je mode_ir
    jmp no_args

mode_legacy:
    mov byte ptr [g_UseIRMode], 0
    jmp mode_ok

mode_ir:
    mov byte ptr [g_UseIRMode], 1
    jmp mode_ok

no_args:
    mov byte ptr [g_UseIRMode], 0

mode_ok:
    mov dword ptr [g_TraceBreadcrumb], 20h

    call WritePreflightTest
    test eax, eax
    jnz preflight_ok
    mov ecx, 41h
    call CrashWithCode

preflight_ok:
    mov dword ptr [g_TraceBreadcrumb], 30h

    lea rcx, sz_dummy_path
    call CoffLinkerRunWithArena

    mov dword ptr [g_TraceBreadcrumb], 40h
    test rax, rax
    jnz linker_ok
    mov ecx, 52h
    call CrashWithCode

linker_ok:
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
    jnz consume_ok
    mov ecx, 62h
    call CrashWithCode

consume_ok:
    mov r14d, eax
    mov dword ptr [g_TraceBreadcrumb], 70h

    cmp byte ptr [g_UseIRMode], 0
    je legacy_out
    lea r15, sz_out_ir
    jmp out_selected

legacy_out:
    lea r15, sz_out_legacy

out_selected:
    mov dword ptr [g_TraceBreadcrumb], 80h
    lea rcx, sz_marker_trap1
    call WriteMarkerFile
    mov dword ptr [g_TraceBreadcrumb], 81h
    ud2

    call FlushPEToDisk
    mov dword ptr [g_TraceBreadcrumb], 90h
    test eax, eax
    jnz flush_ok
    mov ecx, 92h
    call CrashWithCode

flush_ok:
    mov dword ptr [g_TraceBreadcrumb], 0A0h
    lea rcx, sz_marker_success
    call WriteMarkerFile
    lea rcx, sz_ok
    mov rdx, sz_ok_len
    call ConsoleWrite
    mov ecx, [g_TraceBreadcrumb]
    call qword ptr [__imp_ExitProcess]

    add rsp, 40
    ret
mainCRTStartup ENDP

END
