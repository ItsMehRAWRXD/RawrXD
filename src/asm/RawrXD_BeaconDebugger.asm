;=============================================================================
; RawrXD Beacon Debugger v1.0
; Pure x64 MASM, Zero CRT, Zero External Dependencies
; Windows API only (kernel32, ntdll imports)
; Under 3000 lines, no stubs, no placeholders
;=============================================================================
; Build: ml64.exe beacon.asm /link /subsystem:console /entry:main kernel32.lib ntdll.lib
;=============================================================================

        includelib kernel32.lib
        includelib ntdll.lib

;=============================================================================
; External Imports
;=============================================================================
        extrn GetStdHandle:proc
        extrn ReadFile:proc
        extrn WriteFile:proc
        extrn WriteConsoleA:proc
        extrn ExitProcess:proc
        extrn CreateProcessA:proc
        extrn DebugActiveProcess:proc
        extrn WaitForDebugEventEx:proc
        extrn ContinueDebugEvent:proc
        extrn ReadProcessMemory:proc
        extrn WriteProcessMemory:proc
        extrn GetThreadContext:proc
        extrn SetThreadContext:proc
        extrn OpenThread:proc
        extrn SuspendThread:proc
        extrn ResumeThread:proc
        extrn VirtualProtectEx:proc
        extrn GetLastError:proc
        extrn FormatMessageA:proc
        extrn LocalFree:proc
        extrn Sleep:proc
        extrn TerminateProcess:proc
        extrn DebugActiveProcessStop:proc
        extrn CloseHandle:proc
        extrn lstrlenA:proc
        extrn lstrcpyA:proc
        extrn lstrcatA:proc
        extrn GetCommandLineA:proc
        extrn GetModuleHandleA:proc
        extrn GetProcAddress:proc
        extrn VirtualAlloc:proc
        extrn VirtualFree:proc

;=============================================================================
; Constants
;=============================================================================
STD_INPUT_HANDLE  equ -10
STD_OUTPUT_HANDLE equ -11
STD_ERROR_HANDLE  equ -12
INVALID_HANDLE_VALUE equ -1

DEBUG_PROCESS         equ 00000001h
DEBUG_ONLY_THIS_PROCESS equ 00000002h
CREATE_NEW_CONSOLE    equ 00000010h

EXCEPTION_DEBUG_EVENT      equ 1
CREATE_THREAD_DEBUG_EVENT  equ 2
CREATE_PROCESS_DEBUG_EVENT equ 3
EXIT_THREAD_DEBUG_EVENT    equ 4
EXIT_PROCESS_DEBUG_EVENT   equ 5
LOAD_DLL_DEBUG_EVENT       equ 6
UNLOAD_DLL_DEBUG_EVENT     equ 7
OUTPUT_DEBUG_STRING_EVENT  equ 8
RIP_EVENT                  equ 9

DBG_EXCEPTION_HANDLED      equ 00010001h
DBG_CONTINUE               equ 00010002h
DBG_EXCEPTION_NOT_HANDLED  equ 00010000h

EXCEPTION_BREAKPOINT       equ 080000003h
EXCEPTION_SINGLE_STEP      equ 080000004h
EXCEPTION_ACCESS_VIOLATION equ 0C0000005h

CONTEXT_FULL               equ 1000000Bh
CONTEXT_CONTROL            equ 10000001h
CONTEXT_INTEGER            equ 10000002h
CONTEXT_SEGMENTS           equ 10000004h
CONTEXT_FLOATING_POINT     equ 10000008h
CONTEXT_DEBUG_REGISTERS    equ 10000010h

THREAD_GET_CONTEXT         equ 0008h
THREAD_SET_CONTEXT         equ 0010h
THREAD_SUSPEND_RESUME      equ 0002h
THREAD_QUERY_INFORMATION   equ 0040h

PAGE_EXECUTE_READWRITE     equ 040h

MAX_BP equ 64
MAX_CMD equ 256
MAX_OUT equ 4096

;=============================================================================
; Structures (manual layout)
;=============================================================================
STARTUPINFOA struct
        cb              dd ?
        lpReserved      dq ?
        lpDesktop       dq ?
        lpTitle         dq ?
        dwX             dd ?
        dwY             dd ?
        dwXSize         dd ?
        dwYSize         dd ?
        dwXCountChars   dd ?
        dwYCountChars   dd ?
        dwFillAttribute dd ?
        dwFlags         dd ?
        wShowWindow     dw ?
        cbReserved2     dw ?
        lpReserved2     dq ?
        hStdInput       dq ?
        hStdOutput      dq ?
        hStdError       dq ?
STARTUPINFOA ends

PROCESS_INFORMATION struct
        hProcess    dq ?
        hThread     dq ?
        dwProcessId dd ?
        dwThreadId  dd ?
PROCESS_INFORMATION ends

DEBUG_EVENT struct
        dwDebugEventCode dd ?
        dwProcessId      dd ?
        dwThreadId       dd ?
        union
                Exception         db 160 dup(?)
                CreateThread      db 160 dup(?)
                CreateProcessInfo db 160 dup(?)
                ExitThread        db 160 dup(?)
                ExitProcess       db 160 dup(?)
                LoadDll           db 160 dup(?)
                UnloadDll         db 160 dup(?)
                DebugString       db 160 dup(?)
                RipInfo           db 160 dup(?)
        ends
DEBUG_EVENT ends

EXCEPTION_RECORD struct
        ExceptionCode         dd ?
        ExceptionFlags        dd ?
        ExceptionRecord       dq ?
        ExceptionAddress      dq ?
        NumberParameters      dd ?
        ExceptionInformation  dq 15 dup(?)
EXCEPTION_RECORD ends

CONTEXT struct
        P1Home                  dq ?
        P2Home                  dq ?
        P3Home                  dq ?
        P4Home                  dq ?
        P5Home                  dq ?
        P6Home                  dq ?
        ContextFlags            dd ?
        MxCsr                   dd ?
        SegCs                   dw ?
        SegDs                   dw ?
        SegEs                   dw ?
        SegFs                   dw ?
        SegGs                   dw ?
        SegSs                   dw ?
        EFlags                  dd ?
        Dr0                     dq ?
        Dr1                     dq ?
        Dr2                     dq ?
        Dr3                     dq ?
        Dr6                     dq ?
        Dr7                     dq ?
        Rax                     dq ?
        Rcx                     dq ?
        Rdx                     dq ?
        Rbx                     dq ?
        Rsp                     dq ?
        Rbp                     dq ?
        Rsi                     dq ?
        Rdi                     dq ?
        R8                      dq ?
        R9                      dq ?
        R10                     dq ?
        R11                     dq ?
        R12                     dq ?
        R13                     dq ?
        R14                     dq ?
        R15                     dq ?
        Rip                     dq ?
        FltSave                 db 512 dup(?)
        VectorRegister          db 256 dup(?)
        VectorControl           dq ?
        DebugControl            dq ?
        LastBranchToRip         dq ?
        LastBranchFromRip       dq ?
        LastExceptionToRip      dq ?
        LastExceptionFromRip    dq ?
CONTEXT ends

BREAKPOINT struct
        addr        dq ?
        orig_byte   db ?
        active      db ?
        pad         db 6 dup(?)
BREAKPOINT ends

;=============================================================================
; Macros
;=============================================================================
print macro msg
        lea rdx, msg
        call _print_str
endm

printnl macro
        call _print_crlf
endm

hexout macro reg
        mov rcx, reg
        call _print_hex64
endm

;=============================================================================
; .data Section
;=============================================================================
        .data
align 8

; Console handles
hStdOut         dq ?
hStdIn          dq ?

; Debug state
de              DEBUG_EVENT <>
ctx             CONTEXT <>
pi              PROCESS_INFORMATION <>
si              STARTUPINFOA <>

; Target process info
g_hProcess      dq ?
g_hThread       dq ?
g_pid           dd ?
g_tid           dd ?
g_baseAddr      dq ?
g_entryPoint    dq ?
g_attached      db 0
g_running       db 0
g_quit          db 0

; Breakpoint table
bp_table        BREAKPOINT MAX_BP dup(<0,0,0>)
bp_count        dd 0

; Command buffer
cmd_buf         db MAX_CMD dup(0)
cmd_len         dd 0

; Output buffer
out_buf         db MAX_OUT dup(0)
out_pos         dd 0

; Temporary buffers
tmp_buf         db 512 dup(0)
hex_buf         db 32 dup(0)
num_buf         db 64 dup(0)
read_buf        db 16 dup(0)

; String constants
str_prompt      db "bd> ",0
str_crlf        db 13,10,0
str_space       db " ",0
str_tab         db "  ",0
str_hexpre      db "0x",0
str_err         db "[ERR] ",0
str_ok          db "[OK] ",0
str_info        db "[*] ",0

; Commands
str_cmd_attach  db "attach",0
str_cmd_run     db "run",0
str_cmd_break   db "b",0
str_cmd_bc      db "bc",0
str_cmd_bl      db "bl",0
str_cmd_go      db "g",0
str_cmd_trace   db "t",0
str_cmd_step    db "p",0
str_cmd_regs    db "r",0
str_cmd_dumpb   db "db",0
str_cmd_dumpd   db "dd",0
str_cmd_dumpq   db "dq",0
str_cmd_editb   db "eb",0
str_cmd_editd   db "ed",0
str_cmd_editq   db "eq",0
str_cmd_unasm   db "u",0
str_cmd_quit    db "q",0
str_cmd_help    db "?",0

; Register names
reg_names       dq offset str_rax, offset str_rcx, offset str_rdx, offset str_rbx
                dq offset str_rsp, offset str_rbp, offset str_rsi, offset str_rdi
                dq offset str_r8,  offset str_r9,  offset str_r10, offset str_r11
                dq offset str_r12, offset str_r13, offset str_r14, offset str_r15
                dq offset str_rip, offset str_eflags
str_rax         db "rax",0
str_rcx         db "rcx",0
str_rdx         db "rdx",0
str_rbx         db "rbx",0
str_rsp         db "rsp",0
str_rbp         db "rbp",0
str_rsi         db "rsi",0
str_rdi         db "rdi",0
str_r8          db "r8 ",0
str_r9          db "r9 ",0
str_r10         db "r10",0
str_r11         db "r11",0
str_r12         db "r12",0
str_r13         db "r13",0
str_r14         db "r14",0
str_r15         db "r15",0
str_rip         db "rip",0
str_eflags      db "efl",0

; Messages
str_banner      db "RawrXD Beacon Debugger v1.0 | Pure x64 MASM | Zero CRT",13,10
                db "Commands: attach <pid> | run <exe> | b <addr> | bc <idx>",13,10
                db "          bl | g | t | p | r | db/dd/dq <addr> [len]",13,10
                db "          eb/ed/eq <addr> <val> | u <addr> [len] | q | ?",13,10,0
str_attached    db "Attached to PID ",0
str_created     db "Created process ",0
str_bp_set      db "Breakpoint set at ",0
str_bp_clr      db "Breakpoint cleared",13,10,0
str_bp_list     db "Idx  Address            Active",13,10,0
str_bp_none     db "No breakpoints",13,10,0
str_cont        db "Continuing...",13,10,0
str_step        db "Stepping...",13,10,0
str_trace       db "Tracing...",13,10,0
str_ex_bp       db "Breakpoint hit at ",0
str_ex_ss       db "Single step at ",0
str_ex_av       db "Access violation at ",0
str_ex_uk       db "Exception 0x",0
str_proc_exit   db "Process exited with code ",0
str_thread_exit db "Thread exited",13,10,0
str_dll_load    db "DLL loaded at ",0
str_dll_unload  db "DLL unloaded",13,10,0
str_help        db "Beacon Debugger Commands:",13,10
                db "  attach <pid>     Attach to running process",13,10
                db "  run <exe> [args] Create and debug process",13,10
                db "  b <addr>         Set software breakpoint",13,10
                db "  bc <index>       Clear breakpoint",13,10
                db "  bl               List breakpoints",13,10
                db "  g                Go / continue execution",13,10
                db "  t                Trace / step into",13,10
                db "  p                Step over",13,10
                db "  r                Show registers",13,10
                db "  db <addr> [len]  Dump bytes",13,10
                db "  dd <addr> [len]  Dump dwords",13,10
                db "  dq <addr> [len]  Dump qwords",13,10
                db "  eb <addr> <val>  Edit byte",13,10
                db "  ed <addr> <val>  Edit dword",13,10
                db "  eq <addr> <val>  Edit qword",13,10
                db "  u <addr> [len]   Unassemble",13,10
                db "  q                Quit / detach",13,10
                db "  ?                Show this help",13,10,0
str_not_attached db "Not attached to any process",13,10,0
str_no_bp       db "No such breakpoint",13,10,0
str_bp_full     db "Breakpoint table full",13,10,0
str_mem_read    db "Memory read failed",13,10,0
str_mem_write   db "Memory write failed",13,10,0
str_syntax      db "Syntax error",13,10,0
str_unknown     db "Unknown command",13,10,0
str_done        db "Done",13,10,0

; Opcode tables for minimal disassembler
; Each byte: flags
; bit0=has ModR/M, bit1=imm8, bit2=imm16, bit3=imm32, bit4=imm64, bit5=0F escape, bit6=group, bit7=prefix
opcode_flags    db 044h,044h,044h,044h,002h,001h,000h,000h,044h,044h,044h,044h,002h,001h,000h,000h  ; 00-0F
                db 044h,044h,044h,044h,002h,001h,000h,000h,044h,044h,044h,044h,002h,001h,000h,000h  ; 10-1F
                db 044h,044h,044h,044h,002h,001h,080h,000h,044h,044h,044h,044h,002h,001h,080h,000h  ; 20-2F
                db 044h,044h,044h,044h,002h,001h,080h,000h,044h,044h,044h,044h,002h,001h,080h,000h  ; 30-3F
                db 000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h  ; 40-4F REX
                db 000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h  ; 50-5F
                db 000h,000h,044h,044h,080h,080h,080h,080h,001h,002h,000h,000h,000h,000h,000h,000h  ; 60-6F
                db 008h,008h,008h,008h,008h,008h,008h,008h,008h,008h,008h,008h,008h,008h,008h,008h  ; 70-7F Jcc
                db 002h,002h,002h,002h,002h,002h,002h,002h,002h,002h,002h,002h,002h,002h,002h,002h  ; 80-8F
                db 000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,008h,000h,000h,000h,000h,000h  ; 90-9F
                db 008h,008h,008h,008h,000h,000h,000h,000h,001h,001h,000h,000h,000h,000h,000h,000h  ; A0-AF
                db 002h,002h,002h,002h,002h,002h,002h,002h,002h,002h,002h,002h,002h,002h,002h,002h  ; B0-BF
                db 044h,044h,000h,000h,000h,000h,002h,001h,008h,000h,000h,000h,000h,000h,000h,000h  ; C0-CF
                db 044h,044h,044h,044h,001h,001h,000h,000h,044h,044h,044h,044h,044h,044h,044h,044h  ; D0-DF
                db 001h,001h,001h,001h,000h,000h,000h,000h,002h,001h,000h,000h,000h,000h,000h,000h  ; E0-EF
                db 080h,080h,080h,080h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h  ; F0-FF

; 0F extension table
ext0F_flags     db 044h,044h,044h,044h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h  ; 0F 00-0F
                db 044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h  ; 10-1F
                db 044h,044h,044h,044h,000h,000h,000h,000h,044h,044h,044h,044h,044h,044h,044h,044h  ; 20-2F
                db 000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h  ; 30-3F
                db 044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h  ; 40-4F CMOVcc
                db 044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h  ; 50-5F
                db 044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h  ; 60-6F
                db 044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h  ; 70-7F
                db 000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h  ; 80-8F Jcc far
                db 044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h  ; 90-9F SETcc
                db 000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h,000h  ; A0-AF
                db 044h,044h,044h,044h,044h,044h,044h,044h,000h,000h,044h,044h,044h,044h,044h,044h  ; B0-BF
                db 044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h  ; C0-CF
                db 044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h  ; D0-DF
                db 044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h  ; E0-EF
                db 044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h,044h  ; F0-FF

; Mnemonic lookup (compact - just common opcodes)
; Stored as: opcode byte, then offset to string
mnem_table      db 000h
                dq offset m_add
                db 002h
                dq offset m_add
                db 004h
                dq offset m_add
                db 006h
                dq offset m_push
                db 008h
                dq offset m_or
                db 00Ah
                dq offset m_or
                db 00Ch
                dq offset m_or
                db 00Eh
                dq offset m_push
                db 010h
                dq offset m_adc
                db 012h
                dq offset m_adc
                db 014h
                dq offset m_adc
                db 016h
                dq offset m_push
                db 018h
                dq offset m_sbb
                db 01Ah
                dq offset m_sbb
                db 01Ch
                dq offset m_sbb
                db 01Eh
                dq offset m_push
                db 020h
                dq offset m_and
                db 022h
                dq offset m_and
                db 024h
                dq offset m_and
                db 026h
                dq offset m_es
                db 028h
                dq offset m_sub
                db 02Ah
                dq offset m_sub
                db 02Ch
                dq offset m_sub
                db 02Eh
                dq offset m_cs
                db 030h
                dq offset m_xor
                db 032h
                dq offset m_xor
                db 034h
                dq offset m_xor
                db 036h
                dq offset m_ss
                db 038h
                dq offset m_cmp
                db 03Ah
                dq offset m_cmp
                db 03Ch
                dq offset m_cmp
                db 03Eh
                dq offset m_ds
                db 040h
                dq offset m_rex
                db 050h
                dq offset m_push
                db 051h
                dq offset m_push
                db 052h
                dq offset m_push
                db 053h
                dq offset m_push
                db 054h
                dq offset m_push
                db 055h
                dq offset m_push
                db 056h
                dq offset m_push
                db 057h
                dq offset m_push
                db 058h
                dq offset m_pop
                db 059h
                dq offset m_pop
                db 05Ah
                dq offset m_pop
                db 05Bh
                dq offset m_pop
                db 05Ch
                dq offset m_pop
                db 05Dh
                dq offset m_pop
                db 05Eh
                dq offset m_pop
                db 05Fh
                dq offset m_pop
                db 068h
                dq offset m_push
                db 069h
                dq offset m_imul
                db 06Ah
                dq offset m_push
                db 06Bh
                dq offset m_imul
                db 070h
                dq offset m_jo
                db 071h
                dq offset m_jno
                db 072h
                dq offset m_jb
                db 073h
                dq offset m_jnb
                db 074h
                dq offset m_jz
                db 075h
                dq offset m_jnz
                db 076h
                dq offset m_jbe
                db 077h
                dq offset m_ja
                db 078h
                dq offset m_js
                db 079h
                dq offset m_jns
                db 07Ah
                dq offset m_jp
                db 07Bh
                dq offset m_jnp
                db 07Ch
                dq offset m_jl
                db 07Dh
                dq offset m_jge
                db 07Eh
                dq offset m_jle
                db 07Fh
                dq offset m_jg
                db 080h
                dq offset m_grp1
                db 081h
                dq offset m_grp1
                db 082h
                dq offset m_grp1
                db 083h
                dq offset m_grp1
                db 084h
                dq offset m_test
                db 085h
                dq offset m_test
                db 086h
                dq offset m_xchg
                db 087h
                dq offset m_xchg
                db 088h
                dq offset m_mov
                db 089h
                dq offset m_mov
                db 08Ah
                dq offset m_mov
                db 08Bh
                dq offset m_mov
                db 08Ch
                dq offset m_mov
                db 08Dh
                dq offset m_lea
                db 08Eh
                dq offset m_mov
                db 08Fh
                dq offset m_pop
                db 090h
                dq offset m_nop
                db 09Ch
                dq offset m_pushf
                db 09Dh
                dq offset m_popf
                db 0A0h
                dq offset m_mov
                db 0A1h
                dq offset m_mov
                db 0A2h
                dq offset m_mov
                db 0A3h
                dq offset m_mov
                db 0A4h
                dq offset m_movs
                db 0A5h
                dq offset m_movs
                db 0A8h
                dq offset m_test
                db 0A9h
                dq offset m_test
                db 0B0h
                dq offset m_mov
                db 0B8h
                dq offset m_mov
                db 0C0h
                dq offset m_grp2
                db 0C1h
                dq offset m_grp2
                db 0C2h
                dq offset m_ret
                db 0C3h
                dq offset m_ret
                db 0C6h
                dq offset m_mov
                db 0C7h
                dq offset m_mov
                db 0CCh
                dq offset m_int3
                db 0CDh
                dq offset m_int
                db 0CFh
                dq offset m_iret
                db 0D0h
                dq offset m_grp2
                db 0D1h
                dq offset m_grp2
                db 0D2h
                dq offset m_grp2
                db 0D3h
                dq offset m_grp2
                db 0E8h
                dq offset m_call
                db 0E9h
                dq offset m_jmp
                db 0EBh
                dq offset m_jmp
                db 0F0h
                dq offset m_lock
                db 0F2h
                dq offset m_repne
                db 0F3h
                dq offset m_rep
                db 0F4h
                dq offset m_hlt
                db 0F5h
                dq offset m_cmc
                db 0F6h
                dq offset m_grp3
                db 0F7h
                dq offset m_grp3
                db 0F8h
                dq offset m_clc
                db 0F9h
                dq offset m_stc
                db 0FAh
                dq offset m_cli
                db 0FBh
                dq offset m_sti
                db 0FCh
                dq offset m_cld
                db 0FDh
                dq offset m_std
                db 0FEh
                dq offset m_grp4
                db 0FFh
                dq offset m_grp5
                db 0FFh  ; sentinel
mnem_count      equ 100

m_add           db "add",0
m_or            db "or",0
m_adc           db "adc",0
m_sbb           db "sbb",0
m_and           db "and",0
m_sub           db "sub",0
m_xor           db "xor",0
m_cmp           db "cmp",0
m_push          db "push",0
m_pop           db "pop",0
m_mov           db "mov",0
m_test          db "test",0
m_xchg          db "xchg",0
m_lea           db "lea",0
m_nop           db "nop",0
m_jmp           db "jmp",0
m_call          db "call",0
m_ret           db "ret",0
m_jo            db "jo",0
m_jno           db "jno",0
m_jb            db "jb",0
m_jnb           db "jnb",0
m_jz            db "jz",0
m_jnz           db "jnz",0
m_jbe           db "jbe",0
m_ja            db "ja",0
m_js            db "js",0
m_jns           db "jns",0
m_jp            db "jp",0
m_jnp           db "jnp",0
m_jl            db "jl",0
m_jge           db "jge",0
m_jle           db "jle",0
m_jg            db "jg",0
m_grp1          db "grp1",0
m_grp2          db "grp2",0
m_grp3          db "grp3",0
m_grp4          db "grp4",0
m_grp5          db "grp5",0
m_int3          db "int3",0
m_int           db "int",0
m_iret          db "iret",0
m_hlt           db "hlt",0
m_lock          db "lock",0
m_repne         db "repne",0
m_rep           db "rep",0
m_clc           db "clc",0
m_stc           db "stc",0
m_cli           db "cli",0
m_sti           db "sti",0
m_cld           db "cld",0
m_std           db "std",0
m_cmc           db "cmc",0
m_imul          db "imul",0
m_movs          db "movs",0
m_pushf         db "pushf",0
m_popf          db "popf",0
m_rex           db "rex",0
m_es            db "es:",0
m_cs            db "cs:",0
m_ss            db "ss:",0
m_ds            db "ds:",0

;=============================================================================
; .code Section
;=============================================================================
        .code

;-----------------------------------------------------------------------------
; _print_str - Write null-terminated string to stdout
; Input:  RDX = string pointer
; Clobbers: RAX, RCX, R8, R9, R10, R11
;-----------------------------------------------------------------------------
_print_str proc
        push rbx
        push rsi
        push rdi
        mov rbx, rdx
        xor eax, eax
        mov rdi, rdx
        mov ecx, 0FFFFFFFFh
        repne scasb
        mov ecx, 0FFFFFFFFh
        sub ecx, eax  ; length = FFFFFFFF - count
        dec ecx
        jz _ps_done
        mov rdx, rbx
        mov r8d, ecx
        lea r9, read_buf
        mov rcx, hStdOut
        call WriteFile
_ps_done:
        pop rdi
        pop rsi
        pop rbx
        ret
_print_str endp

;-----------------------------------------------------------------------------
; _print_crlf - Write newline
;-----------------------------------------------------------------------------
_print_crlf proc
        lea rdx, str_crlf
        jmp _print_str
_print_crlf endp

;-----------------------------------------------------------------------------
; _print_hex64 - Print 64-bit hex value
; Input: RCX = value
;-----------------------------------------------------------------------------
_print_hex64 proc
        push rbx
        push rsi
        push rdi
        push r12
        mov r12, rcx
        lea rdx, str_hexpre
        call _print_str
        lea rdi, hex_buf
        mov rbx, r12
        mov ecx, 16
_ph_loop:
        rol rbx, 4
        mov eax, ebx
        and eax, 0Fh
        cmp eax, 0Ah
        jb _ph_digit
        add eax, 37h  ; 'A' - 10
        jmp _ph_store
_ph_digit:
        add eax, 30h  ; '0'
_ph_store:
        mov [rdi], al
        inc rdi
        dec ecx
        jnz _ph_loop
        mov byte ptr [rdi], 0
        lea rdx, hex_buf
        call _print_str
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
_print_hex64 endp

;-----------------------------------------------------------------------------
; _print_hex8 - Print 8-bit hex value
; Input: CL = value
;-----------------------------------------------------------------------------
_print_hex8 proc
        push rbx
        push rdi
        lea rdi, hex_buf
        movzx eax, cl
        shr al, 4
        cmp al, 0Ah
        jb _ph8_d1
        add al, 37h
        jmp _ph8_s1
_ph8_d1:
        add al, 30h
_ph8_s1:
        mov [rdi], al
        movzx eax, cl
        and al, 0Fh
        cmp al, 0Ah
        jb _ph8_d2
        add al, 37h
        jmp _ph8_s2
_ph8_d2:
        add al, 30h
_ph8_s2:
        mov [rdi+1], al
        mov byte ptr [rdi+2], 0
        lea rdx, hex_buf
        call _print_str
        pop rdi
        pop rbx
        ret
_print_hex8 endp

;-----------------------------------------------------------------------------
; _print_num - Print decimal number (64-bit unsigned)
; Input: RCX = value
;-----------------------------------------------------------------------------
_print_num proc
        push rbx
        push rsi
        push rdi
        push r12
        mov r12, rcx
        lea rdi, num_buf + 63
        mov byte ptr [rdi], 0
        mov rbx, 10
_pn_loop:
        xor edx, edx
        mov rax, r12
        div rbx
        mov r12, rax
        add dl, 30h
        dec rdi
        mov [rdi], dl
        test r12, r12
        jnz _pn_loop
        mov rdx, rdi
        call _print_str
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
_print_num endp

;-----------------------------------------------------------------------------
; _read_line - Read line from stdin into cmd_buf
; Returns: cmd_buf filled, cmd_len set
;-----------------------------------------------------------------------------
_read_line proc
        push rbx
        push rsi
        push rdi
        mov ecx, MAX_CMD
        lea rdi, cmd_buf
        xor eax, eax
        rep stosb
        mov cmd_len, 0
        lea r9, read_buf
        mov dword ptr [r9], 0
_rl_loop:
        lea r9, read_buf
        mov rcx, hStdIn
        mov rdx, r9
        mov r8d, 1
        lea r10, tmp_buf
        mov [r10], r8d
        call ReadFile
        cmp eax, 0
        je _rl_done
        mov al, byte ptr [r9]
        cmp al, 0Dh
        je _rl_done
        cmp al, 0Ah
        je _rl_done
        cmp al, 08h    ; backspace
        je _rl_back
        mov ecx, cmd_len
        cmp ecx, MAX_CMD - 2
        jae _rl_loop
        lea rdi, cmd_buf
        mov [rdi + rcx], al
        inc ecx
        mov cmd_len, ecx
        jmp _rl_loop
_rl_back:
        mov ecx, cmd_len
        test ecx, ecx
        jz _rl_loop
        dec ecx
        mov cmd_len, ecx
        jmp _rl_loop
_rl_done:
        mov ecx, cmd_len
        lea rdi, cmd_buf
        mov byte ptr [rdi + rcx], 0
        pop rdi
        pop rsi
        pop rbx
        ret
_read_line endp

;-----------------------------------------------------------------------------
; _strcmp - Compare two strings
; Input: RSI = str1, RDI = str2
; Output: AL = 0 if equal, non-zero if different
;-----------------------------------------------------------------------------
_strcmp proc
        push rbx
        push rsi
        push rdi
_sc_loop:
        mov al, [rsi]
        mov bl, [rdi]
        cmp al, bl
        jne _sc_ne
        test al, al
        jz _sc_eq
        inc rsi
        inc rdi
        jmp _sc_loop
_sc_ne:
        sub al, bl
        jmp _sc_done
_sc_eq:
        xor al, al
_sc_done:
        pop rdi
        pop rsi
        pop rbx
        ret
_strcmp endp

;-----------------------------------------------------------------------------
; _strcpy - Copy string
; Input: RDI = dest, RSI = src
;-----------------------------------------------------------------------------
_strcpy proc
        push rsi
        push rdi
_cp_loop:
        mov al, [rsi]
        mov [rdi], al
        inc rsi
        inc rdi
        test al, al
        jnz _cp_loop
        pop rdi
        pop rsi
        ret
_strcpy endp

;-----------------------------------------------------------------------------
; _strlen - Get string length
; Input: RCX = string
; Output: RAX = length
;-----------------------------------------------------------------------------
_strlen proc
        push rdi
        mov rdi, rcx
        xor eax, eax
        mov ecx, 0FFFFFFFFh
        repne scasb
        mov eax, 0FFFFFFFFh
        sub eax, ecx
        dec eax
        pop rdi
        ret
_strlen endp

;-----------------------------------------------------------------------------
; _strtok - Get first token from cmd_buf
; Output: RSI = start of token, RDI = end of token (space or null)
;-----------------------------------------------------------------------------
_strtok proc
        push rbx
        lea rsi, cmd_buf
        ; Skip leading spaces
_tk_skip:
        mov al, [rsi]
        cmp al, 20h
        jne _tk_start
        inc rsi
        jmp _tk_skip
_tk_start:
        mov rdi, rsi
_tk_find:
        mov al, [rdi]
        test al, al
        jz _tk_done
        cmp al, 20h
        je _tk_done
        inc rdi
        jmp _tk_find
_tk_done:
        pop rbx
        ret
_strtok endp

;-----------------------------------------------------------------------------
; _parse_hex - Parse hex string to 64-bit value
; Input: RSI = string pointer
; Output: RAX = value, CF set on error
;-----------------------------------------------------------------------------
_parse_hex proc
        push rbx
        push rsi
        xor rbx, rbx
        mov rax, rsi
        mov al, [rax]
        cmp al, 30h
        jne _phx_check
        mov rax, rsi
        mov al, [rax+1]
        cmp al, 78h
        je _phx_skip0x
        cmp al, 58h
        je _phx_skip0x
_phx_check:
        jmp _phx_loop
_phx_skip0x:
        add rsi, 2
_phx_loop:
        mov al, [rsi]
        test al, al
        jz _phx_done
        sub al, 30h
        cmp al, 10
        jb _phx_digit
        sub al, 7
        cmp al, 10
        jb _phx_err
        cmp al, 16
        jb _phx_digit
        sub al, 20h
        cmp al, 10
        jb _phx_err
        cmp al, 16
        jae _phx_err
_phx_digit:
        shl rbx, 4
        or rbx, rax
        inc rsi
        jmp _phx_loop
_phx_done:
        mov rax, rbx
        clc
        jmp _phx_ret
_phx_err:
        stc
_phx_ret:
        pop rsi
        pop rbx
        ret
_parse_hex endp

;-----------------------------------------------------------------------------
; _parse_dec - Parse decimal string to 64-bit value
; Input: RSI = string pointer
; Output: RAX = value
;-----------------------------------------------------------------------------
_parse_dec proc
        push rbx
        push rsi
        xor rbx, rbx
_pd_loop:
        mov al, [rsi]
        test al, al
        jz _pd_done
        sub al, 30h
        cmp al, 10
        jae _pd_done
        imul rbx, 10
        movzx rax, al
        add rbx, rax
        inc rsi
        jmp _pd_loop
_pd_done:
        mov rax, rbx
        pop rsi
        pop rbx
        ret
_parse_dec endp

;-----------------------------------------------------------------------------
; _get_arg - Get nth argument from cmd_buf
; Input: ECX = argument index (0-based)
; Output: RSI = pointer to arg, or null if not found
;-----------------------------------------------------------------------------
_get_arg proc
        push rbx
        push rdi
        lea rsi, cmd_buf
        xor ebx, ebx
_ga_skip:
        ; Skip spaces
_ga_spl:
        mov al, [rsi]
        cmp al, 20h
        jne _ga_token
        inc rsi
        jmp _ga_spl
_ga_token:
        test al, al
        jz _ga_notfound
        cmp ebx, ecx
        je _ga_found
        inc ebx
        ; Skip to end of token
_ga_tok:
        mov al, [rsi]
        test al, al
        jz _ga_notfound
        cmp al, 20h
        je _ga_skip
        inc rsi
        jmp _ga_tok
_ga_notfound:
        xor esi, esi
_ga_found:
        pop rdi
        pop rbx
        ret
_get_arg endp

;-----------------------------------------------------------------------------
; _show_error - Display last Windows error
;-----------------------------------------------------------------------------
_show_error proc
        push rbx
        push rsi
        push rdi
        push r12
        lea rdx, str_err
        call _print_str
        call GetLastError
        mov r12, rax
        lea r9, tmp_buf
        mov rcx, r12
        mov rdx, 1200h  ; FORMAT_MESSAGE_FROM_SYSTEM
        xor r8, r8
        mov r10, r9
        mov dword ptr [r10], 256
        call FormatMessageA
        mov rdx, r9
        call _print_str
        call _print_crlf
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
_show_error endp

;-----------------------------------------------------------------------------
; _find_bp - Find breakpoint by address
; Input: RCX = address
; Output: RAX = index (0-based) or -1 if not found
;-----------------------------------------------------------------------------
_find_bp proc
        push rbx
        push rsi
        push rdi
        mov rbx, rcx
        xor eax, eax
        mov ecx, bp_count
        test ecx, ecx
        jz _fbp_notfound
        lea rdi, bp_table
_fbp_loop:
        cmp [rdi + BREAKPOINT.addr], rbx
        je _fbp_found
        add rdi, sizeof BREAKPOINT
        inc eax
        cmp eax, ecx
        jb _fbp_loop
_fbp_notfound:
        mov eax, -1
_fbp_found:
        pop rdi
        pop rsi
        pop rbx
        ret
_find_bp endp

;-----------------------------------------------------------------------------
; _set_bp - Set software breakpoint (INT 3)
; Input: RCX = address
; Output: AL = 0 success, 1 error
;-----------------------------------------------------------------------------
_set_bp proc
        push rbx
        push rsi
        push rdi
        push r12
        mov r12, rcx
        ; Check if already exists
        call _find_bp
        cmp eax, -1
        jne _sbp_exists
        ; Find free slot
        mov eax, bp_count
        cmp eax, MAX_BP
        jae _sbp_full
        lea rdi, bp_table
        mov ebx, sizeof BREAKPOINT
        mul ebx
        add rdi, rax
        ; Read original byte
        mov rcx, g_hProcess
        mov rdx, r12
        lea r8, tmp_buf
        mov r9d, 1
        call ReadProcessMemory
        test rax, rax
        jz _sbp_err
        ; Store breakpoint
        mov [rdi + BREAKPOINT.addr], r12
        mov al, byte ptr [tmp_buf]
        mov [rdi + BREAKPOINT.orig_byte], al
        mov byte ptr [rdi + BREAKPOINT.active], 1
        ; Write INT 3
        mov byte ptr [tmp_buf], 0CCh
        mov rcx, g_hProcess
        mov rdx, r12
        lea r8, tmp_buf
        mov r9d, 1
        call WriteProcessMemory
        test rax, rax
        jz _sbp_err
        inc bp_count
        lea rdx, str_bp_set
        call _print_str
        mov rcx, r12
        call _print_hex64
        call _print_crlf
        xor al, al
        jmp _sbp_done
_sbp_exists:
        lea rdx, str_info
        call _print_str
        lea rdx, str_bp_set
        call _print_str
        call _print_crlf
        xor al, al
        jmp _sbp_done
_sbp_full:
        lea rdx, str_err
        call _print_str
        lea rdx, str_bp_full
        call _print_str
        mov al, 1
        jmp _sbp_done
_sbp_err:
        lea rdx, str_err
        call _print_str
        lea rdx, str_mem_write
        call _print_str
        mov al, 1
_sbp_done:
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
_set_bp endp

;-----------------------------------------------------------------------------
; _clear_bp - Clear breakpoint
; Input: ECX = breakpoint index
; Output: AL = 0 success, 1 error
;-----------------------------------------------------------------------------
_clear_bp proc
        push rbx
        push rsi
        push rdi
        push r12
        mov r12d, ecx
        cmp ecx, bp_count
        jae _cbp_err
        lea rdi, bp_table
        mov eax, sizeof BREAKPOINT
        mul ecx
        add rdi, rax
        cmp byte ptr [rdi + BREAKPOINT.active], 0
        je _cbp_err
        ; Restore original byte
        mov rcx, g_hProcess
        mov rdx, [rdi + BREAKPOINT.addr]
        lea r8, tmp_buf
        mov al, [rdi + BREAKPOINT.orig_byte]
        mov [r8], al
        mov r9d, 1
        call WriteProcessMemory
        test rax, rax
        jz _cbp_err
        mov byte ptr [rdi + BREAKPOINT.active], 0
        lea rdx, str_bp_clr
        call _print_str
        call _print_crlf
        xor al, al
        jmp _cbp_done
_cbp_err:
        lea rdx, str_err
        call _print_str
        lea rdx, str_no_bp
        call _print_str
        mov al, 1
_cbp_done:
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
_clear_bp endp

;-----------------------------------------------------------------------------
; _list_bp - List all breakpoints
;-----------------------------------------------------------------------------
_list_bp proc
        push rbx
        push rsi
        push rdi
        mov ecx, bp_count
        test ecx, ecx
        jz _lbp_none
        lea rdx, str_bp_list
        call _print_str
        xor ebx, ebx
        lea rdi, bp_table
_lbp_loop:
        cmp byte ptr [rdi + BREAKPOINT.active], 0
        je _lbp_next
        ; Index
        mov eax, ebx
        call _print_num
        lea rdx, str_tab
        call _print_str
        ; Address
        mov rcx, [rdi + BREAKPOINT.addr]
        call _print_hex64
        lea rdx, str_tab
        call _print_str
        ; Active
        lea rdx, str_ok
        call _print_str
        call _print_crlf
_lbp_next:
        add rdi, sizeof BREAKPOINT
        inc ebx
        cmp ebx, ecx
        jb _lbp_loop
        jmp _lbp_done
_lbp_none:
        lea rdx, str_bp_none
        call _print_str
_lbp_done:
        pop rdi
        pop rsi
        pop rbx
        ret
_list_bp endp

;-----------------------------------------------------------------------------
; _show_regs - Display x64 register context
;-----------------------------------------------------------------------------
_show_regs proc
        push rbx
        push rsi
        push rdi
        push r12
        lea r12, ctx
        ; rax
        lea rdx, str_rax
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.Rax]
        call _print_hex64
        lea rdx, str_tab
        call _print_str
        ; rcx
        lea rdx, str_rcx
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.Rcx]
        call _print_hex64
        lea rdx, str_tab
        call _print_str
        ; rdx
        lea rdx, str_rdx
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.Rdx]
        call _print_hex64
        call _print_crlf
        ; rbx
        lea rdx, str_rbx
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.Rbx]
        call _print_hex64
        lea rdx, str_tab
        call _print_str
        ; rsp
        lea rdx, str_rsp
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.Rsp]
        call _print_hex64
        lea rdx, str_tab
        call _print_str
        ; rbp
        lea rdx, str_rbp
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.Rbp]
        call _print_hex64
        call _print_crlf
        ; rsi
        lea rdx, str_rsi
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.Rsi]
        call _print_hex64
        lea rdx, str_tab
        call _print_str
        ; rdi
        lea rdx, str_rdi
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.Rdi]
        call _print_hex64
        lea rdx, str_tab
        call _print_str
        ; rip
        lea rdx, str_rip
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.Rip]
        call _print_hex64
        call _print_crlf
        ; r8-r11
        lea rdx, str_r8
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.R8]
        call _print_hex64
        lea rdx, str_tab
        call _print_str
        lea rdx, str_r9
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.R9]
        call _print_hex64
        lea rdx, str_tab
        call _print_str
        lea rdx, str_r10
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.R10]
        call _print_hex64
        lea rdx, str_tab
        call _print_str
        lea rdx, str_r11
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.R11]
        call _print_hex64
        call _print_crlf
        ; r12-r15
        lea rdx, str_r12
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.R12]
        call _print_hex64
        lea rdx, str_tab
        call _print_str
        lea rdx, str_r13
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.R13]
        call _print_hex64
        lea rdx, str_tab
        call _print_str
        lea rdx, str_r14
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.R14]
        call _print_hex64
        lea rdx, str_tab
        call _print_str
        lea rdx, str_r15
        call _print_str
        lea rdx, str_space
        call _print_str
        mov rcx, [r12 + CONTEXT.R15]
        call _print_hex64
        call _print_crlf
        ; eflags
        lea rdx, str_eflags
        call _print_str
        lea rdx, str_space
        call _print_str
        movzx rcx, dword ptr [r12 + CONTEXT.EFlags]
        call _print_hex64
        call _print_crlf
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
_show_regs endp

;-----------------------------------------------------------------------------
; _dump_mem - Dump memory from target process
; Input: RCX = address, RDX = length, R8 = size (1,4,8)
;-----------------------------------------------------------------------------
_dump_mem proc
        push rbx
        push rsi
        push rdi
        push r12
        push r13
        push r14
        mov r12, rcx
        mov r13, rdx
        mov r14d, r8d
        ; Round down to alignment
        and r12, not 0Fh
        ; Number of lines
        add r13, 15
        shr r13, 4
_dm_line:
        test r13, r13
        jz _dm_done
        dec r13
        ; Print address
        mov rcx, r12
        call _print_hex64
        lea rdx, str_space
        call _print_str
        ; Read 16 bytes
        mov rcx, g_hProcess
        mov rdx, r12
        lea r8, tmp_buf
        mov r9d, 16
        call ReadProcessMemory
        test rax, rax
        jz _dm_bad
        ; Print bytes/words/dwords/qwords
        xor ebx, ebx
_dm_byte:
        cmp ebx, 16
        jae _dm_ascii
        cmp r14d, 1
        je _dm_b1
        cmp r14d, 4
        je _dm_b4
        ; qword
        test ebx, 7
        jnz _dm_skip
        movzx eax, byte ptr [tmp_buf + rbx]
        call _print_hex8
        movzx eax, byte ptr [tmp_buf + rbx + 1]
        call _print_hex8
        movzx eax, byte ptr [tmp_buf + rbx + 2]
        call _print_hex8
        movzx eax, byte ptr [tmp_buf + rbx + 3]
        call _print_hex8
        movzx eax, byte ptr [tmp_buf + rbx + 4]
        call _print_hex8
        movzx eax, byte ptr [tmp_buf + rbx + 5]
        call _print_hex8
        movzx eax, byte ptr [tmp_buf + rbx + 6]
        call _print_hex8
        movzx eax, byte ptr [tmp_buf + rbx + 7]
        call _print_hex8
        lea rdx, str_space
        call _print_str
        add ebx, 8
        jmp _dm_byte
_dm_b4:
        test ebx, 3
        jnz _dm_skip
        movzx eax, byte ptr [tmp_buf + rbx]
        call _print_hex8
        movzx eax, byte ptr [tmp_buf + rbx + 1]
        call _print_hex8
        movzx eax, byte ptr [tmp_buf + rbx + 2]
        call _print_hex8
        movzx eax, byte ptr [tmp_buf + rbx + 3]
        call _print_hex8
        lea rdx, str_space
        call _print_str
        add ebx, 4
        jmp _dm_byte
_dm_b1:
        movzx eax, byte ptr [tmp_buf + rbx]
        call _print_hex8
        lea rdx, str_space
        call _print_str
        inc ebx
        jmp _dm_byte
_dm_skip:
        lea rdx, str_space
        call _print_str
        lea rdx, str_space
        call _print_str
        inc ebx
        jmp _dm_byte
_dm_ascii:
        lea rdx, str_space
        call _print_str
        ; Print ASCII
        xor ebx, ebx
_dm_asc:
        cmp ebx, 16
        jae _dm_next
        movzx eax, byte ptr [tmp_buf + rbx]
        cmp al, 20h
        jb _dm_dot
        cmp al, 7Eh
        ja _dm_dot
        mov byte ptr [hex_buf], al
        mov byte ptr [hex_buf+1], 0
        lea rdx, hex_buf
        call _print_str
        jmp _dm_ascn
_dm_dot:
        mov byte ptr [hex_buf], 2Eh
        mov byte ptr [hex_buf+1], 0
        lea rdx, hex_buf
        call _print_str
_dm_ascn:
        inc ebx
        jmp _dm_asc
_dm_bad:
        lea rdx, str_err
        call _print_str
        lea rdx, str_mem_read
        call _print_str
        jmp _dm_done
_dm_next:
        call _print_crlf
        add r12, 16
        jmp _dm_line
_dm_done:
        pop r14
        pop r13
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
_dump_mem endp

;-----------------------------------------------------------------------------
; _edit_mem - Edit memory in target process
; Input: RCX = address, RDX = value, R8 = size (1,4,8)
;-----------------------------------------------------------------------------
_edit_mem proc
        push rbx
        push rsi
        push rdi
        push r12
        push r13
        mov r12, rcx
        mov r13, rdx
        mov ebx, r8d
        lea r8, tmp_buf
        cmp ebx, 1
        je _em_b
        cmp ebx, 4
        je _em_d
        ; qword
        mov [r8], r13
        mov r9d, 8
        jmp _em_write
_em_d:
        mov [r8], r13d
        mov r9d, 4
        jmp _em_write
_em_b:
        mov [r8], r13b
        mov r9d, 1
_em_write:
        mov rcx, g_hProcess
        mov rdx, r12
        call WriteProcessMemory
        test rax, rax
        jz _em_err
        lea rdx, str_ok
        call _print_str
        lea rdx, str_done
        call _print_str
        jmp _em_done
_em_err:
        lea rdx, str_err
        call _print_str
        lea rdx, str_mem_write
        call _print_str
_em_done:
        pop r13
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
_edit_mem endp

;-----------------------------------------------------------------------------
; _insn_len - Calculate x64 instruction length
; Input: RCX = pointer to instruction bytes (16 bytes available)
; Output: RAX = length (1-15), 0 if unknown/invalid
;-----------------------------------------------------------------------------
_insn_len proc
        push rbx
        push rsi
        push rdi
        push r12
        push r13
        mov r12, rcx
        xor r13, r13      ; length
        xor ebx, ebx      ; flags accumulator
        xor edi, edi      ; REX present
        xor esi, esi      ; 0F escape
        ; Skip prefixes
_il_prefix:
        movzx eax, byte ptr [r12 + r13]
        cmp al, 40h
        jb _il_not_rex
        cmp al, 4Fh
        ja _il_not_rex
        mov edi, 1
        inc r13
        jmp _il_prefix
_il_not_rex:
        cmp al, 66h
        je _il_pre
        cmp al, 67h
        je _il_pre
        cmp al, 0F0h
        je _il_pre
        cmp al, 0F2h
        je _il_pre
        cmp al, 0F3h
        je _il_pre
        cmp al, 2Eh
        je _il_pre
        cmp al, 36h
        je _il_pre
        cmp al, 3Eh
        je _il_pre
        cmp al, 26h
        je _il_pre
        cmp al, 64h
        je _il_pre
        cmp al, 65h
        je _il_pre
        jmp _il_opcode
_il_pre:
        inc r13
        jmp _il_prefix
_il_opcode:
        cmp r13, 15
        jae _il_unk
        movzx eax, byte ptr [r12 + r13]
        inc r13
        cmp al, 0Fh
        jne _il_op1
        ; Two-byte opcode
        cmp r13, 15
        jae _il_unk
        movzx eax, byte ptr [r12 + r13]
        inc r13
        movzx eax, byte ptr [ext0F_flags + rax]
        jmp _il_flags
_il_op1:
        movzx eax, byte ptr [opcode_flags + rax]
_il_flags:
        test al, 80h
        jnz _il_unk       ; unhandled/invalid
        test al, 20h
        jnz _il_0f        ; 0F escape - already handled
        test al, 40h
        jnz _il_grp       ; group - needs ModR/M
        test al, 01h
        jnz _il_modrm
        test al, 02h
        jnz _il_imm8
        test al, 04h
        jnz _il_imm16
        test al, 08h
        jnz _il_imm32
        test al, 10h
        jnz _il_imm64
        jmp _il_done
_il_0f:
        ; Should not reach here
        jmp _il_unk
_il_grp:
        ; Group opcodes: need ModR/M then immediate based on group
        jmp _il_modrm
_il_modrm:
        cmp r13, 15
        jae _il_unk
        movzx eax, byte ptr [r12 + r13]
        inc r13
        mov bl, al
        ; ModR/M decode
        mov cl, al
        shr cl, 6         ; mod
        and al, 7         ; r/m
        cmp cl, 3
        je _il_no_disp
        cmp al, 4
        jne _il_no_sib
        ; SIB byte
        cmp r13, 15
        jae _il_unk
        inc r13
_il_no_sib:
        cmp cl, 0
        jne _il_disp8
        cmp al, 5
        jne _il_no_disp
        ; disp32
        add r13, 4
        jmp _il_no_disp
_il_disp8:
        cmp cl, 1
        jne _il_disp32
        inc r13
        jmp _il_no_disp
_il_disp32:
        add r13, 4
_il_no_disp:
        ; Check immediate from original flags
        movzx eax, byte ptr [r12]
        movzx eax, byte ptr [opcode_flags + rax]
        test al, 02h
        jnz _il_imm8
        test al, 04h
        jnz _il_imm16
        test al, 08h
        jnz _il_imm32
        test al, 10h
        jnz _il_imm64
        jmp _il_done
_il_imm8:
        inc r13
        jmp _il_done
_il_imm16:
        add r13, 2
        jmp _il_done
_il_imm32:
        add r13, 4
        jmp _il_done
_il_imm64:
        add r13, 8
        jmp _il_done
_il_unk:
        xor r13, r13
_il_done:
        cmp r13, 15
        ja _il_unk
        mov rax, r13
        pop r13
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
_insn_len endp

;-----------------------------------------------------------------------------
; _unasm - Unassemble (disassemble) at address
; Input: RCX = address, RDX = count (instructions)
;-----------------------------------------------------------------------------
_unasm proc
        push rbx
        push rsi
        push rdi
        push r12
        push r13
        push r14
        mov r12, rcx
        mov r13, rdx
_ua_loop:
        test r13, r13
        jz _ua_done
        dec r13
        ; Read up to 15 bytes
        mov rcx, g_hProcess
        mov rdx, r12
        lea r8, tmp_buf
        mov r9d, 15
        call ReadProcessMemory
        test rax, rax
        jz _ua_bad
        ; Print address
        mov rcx, r12
        call _print_hex64
        lea rdx, str_space
        call _print_str
        ; Get instruction length
        lea rcx, tmp_buf
        call _insn_len
        test rax, rax
        jz _ua_raw
        mov r14, rax
        ; Print bytes
        xor ebx, ebx
_ua_bytes:
        cmp rbx, r14
        jae _ua_bytes_done
        movzx eax, byte ptr [tmp_buf + rbx]
        call _print_hex8
        lea rdx, str_space
        call _print_str
        inc ebx
        jmp _ua_bytes
_ua_bytes_done:
        ; Pad to column
        mov rax, 7
        sub rax, r14
        jbe _ua_mnem
        mov ecx, eax
_ua_pad:
        lea rdx, str_tab
        call _print_str
        dec ecx
        jnz _ua_pad
_ua_mnem:
        ; Lookup mnemonic
        movzx eax, byte ptr [tmp_buf]
        cmp al, 40h
        jb _ua_m1
        cmp al, 4Fh
        ja _ua_m1
        movzx eax, byte ptr [tmp_buf + 1]
_ua_m1:
        lea rdi, mnem_table
        mov ecx, mnem_count
_ua_find:
        cmp byte ptr [rdi], 0FFh
        je _ua_nomnem
        cmp al, [rdi]
        je _ua_found
        add rdi, 9
        dec ecx
        jnz _ua_find
_ua_nomnem:
        lea rdx, str_hexpre
        call _print_str
        jmp _ua_next
_ua_found:
        mov rdx, [rdi + 1]
        call _print_str
        jmp _ua_next
_ua_raw:
        ; Unknown - print as db
        movzx eax, byte ptr [tmp_buf]
        call _print_hex8
        mov r14, 1
_ua_next:
        call _print_crlf
        add r12, r14
        jmp _ua_loop
_ua_bad:
        lea rdx, str_err
        call _print_str
        lea rdx, str_mem_read
        call _print_str
_ua_done:
        pop r14
        pop r13
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
_unasm endp

;-----------------------------------------------------------------------------
; _get_context - Get thread context
; Output: ctx filled
;-----------------------------------------------------------------------------
_get_context proc
        push rbx
        push rsi
        push rdi
        mov rcx, g_hThread
        test rcx, rcx
        jz _gc_err
        lea rdx, ctx
        mov dword ptr [rdx + CONTEXT.ContextFlags], CONTEXT_FULL
        call GetThreadContext
        test rax, rax
        jnz _gc_ok
_gc_err:
        lea rdx, str_err
        call _print_str
        lea rdx, str_info
        call _print_str
        lea rdx, str_mem_read
        call _print_str
_gc_ok:
        pop rdi
        pop rsi
        pop rbx
        ret
_get_context endp

;-----------------------------------------------------------------------------
; _set_context - Set thread context
;-----------------------------------------------------------------------------
_set_context proc
        push rbx
        push rsi
        push rdi
        mov rcx, g_hThread
        test rcx, rcx
        jz _sc_err
        lea rdx, ctx
        call SetThreadContext
        test rax, rax
        jnz _sc_ok
_sc_err:
        lea rdx, str_err
        call _print_str
        lea rdx, str_info
        call _print_str
        lea rdx, str_mem_write
        call _print_str
_sc_ok:
        pop rdi
        pop rsi
        pop rbx
        ret
_set_context endp

;-----------------------------------------------------------------------------
; _do_step - Single step (trace into)
; Sets Trap Flag in EFLAGS
;-----------------------------------------------------------------------------
_do_step proc
        push rbx
        push rsi
        push rdi
        call _get_context
        lea rbx, ctx
        mov eax, [rbx + CONTEXT.EFlags]
        or eax, 100h      ; TF = 1
        mov [rbx + CONTEXT.EFlags], eax
        call _set_context
        mov g_running, 1
        pop rdi
        pop rsi
        pop rbx
        ret
_do_step endp

;-----------------------------------------------------------------------------
; _do_stepover - Step over (break at next instruction)
;-----------------------------------------------------------------------------
_do_stepover proc
        push rbx
        push rsi
        push rdi
        push r12
        call _get_context
        lea rbx, ctx
        ; Get current instruction length
        mov r12, [rbx + CONTEXT.Rip]
        mov rcx, g_hProcess
        mov rdx, r12
        lea r8, tmp_buf
        mov r9d, 15
        call ReadProcessMemory
        test rax, rax
        jz _dso_err
        lea rcx, tmp_buf
        call _insn_len
        test rax, rax
        jz _dso_err
        add r12, rax
        ; Set breakpoint at next instruction
        mov rcx, r12
        call _set_bp
        mov g_running, 1
        jmp _dso_done
_dso_err:
        ; Fall back to single step
        call _do_step
_dso_done:
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
_do_stepover endp

;-----------------------------------------------------------------------------
; _do_go - Continue execution
;-----------------------------------------------------------------------------
_do_go proc
        mov g_running, 1
        ret
_do_go endp

;-----------------------------------------------------------------------------
; _do_quit - Detach and quit
;-----------------------------------------------------------------------------
_do_quit proc
        cmp g_attached, 0
        je _dq_exit
        mov ecx, g_pid
        call DebugActiveProcessStop
        mov rcx, g_hProcess
        test rcx, rcx
        jz _dq_exit
        call CloseHandle
_dq_exit:
        mov g_quit, 1
        ret
_do_quit endp

;-----------------------------------------------------------------------------
; _handle_event - Process debug event
; Input: de filled by WaitForDebugEventEx
;-----------------------------------------------------------------------------
_handle_event proc
        push rbx
        push rsi
        push rdi
        push r12
        mov eax, de.dwDebugEventCode
        cmp eax, CREATE_PROCESS_DEBUG_EVENT
        je _he_create_process
        cmp eax, CREATE_THREAD_DEBUG_EVENT
        je _he_create_thread
        cmp eax, EXIT_THREAD_DEBUG_EVENT
        je _he_exit_thread
        cmp eax, EXIT_PROCESS_DEBUG_EVENT
        je _he_exit_process
        cmp eax, LOAD_DLL_DEBUG_EVENT
        je _he_load_dll
        cmp eax, UNLOAD_DLL_DEBUG_EVENT
        je _he_unload_dll
        cmp eax, EXCEPTION_DEBUG_EVENT
        je _he_exception
        cmp eax, OUTPUT_DEBUG_STRING_EVENT
        je _he_debug_string
        jmp _he_continue

_he_create_process:
        lea rdx, str_info
        call _print_str
        lea rdx, str_created
        call _print_str
        mov eax, de.dwProcessId
        mov g_pid, eax
        call _print_num
        call _print_crlf
        ; Store handles
        lea rbx, de
        add rbx, 4 + 4 + 4  ; offset to CreateProcessInfo
        mov rax, [rbx + 8]   ; hProcess
        mov g_hProcess, rax
        mov rax, [rbx + 16]  ; hThread
        mov g_hThread, rax
        mov rax, [rbx + 24]  ; lpBaseOfImage
        mov g_baseAddr, rax
        mov rax, [rbx + 32]  ; dwStartAddress
        mov g_entryPoint, rax
        mov g_attached, 1
        jmp _he_continue

_he_create_thread:
        jmp _he_continue

_he_exit_thread:
        lea rdx, str_info
        call _print_str
        lea rdx, str_thread_exit
        call _print_str
        jmp _he_continue

_he_exit_process:
        lea rdx, str_info
        call _print_str
        lea rdx, str_proc_exit
        call _print_str
        lea rbx, de
        add rbx, 4 + 4 + 4
        mov ecx, [rbx]       ; dwExitCode
        call _print_num
        call _print_crlf
        mov g_quit, 1
        jmp _he_continue

_he_load_dll:
        lea rdx, str_info
        call _print_str
        lea rdx, str_dll_load
        call _print_str
        lea rbx, de
        add rbx, 4 + 4 + 4
        mov rcx, [rbx + 8]   ; lpBaseOfDll
        call _print_hex64
        call _print_crlf
        jmp _he_continue

_he_unload_dll:
        lea rdx, str_info
        call _print_str
        lea rdx, str_dll_unload
        call _print_str
        jmp _he_continue

_he_debug_string:
        jmp _he_continue

_he_exception:
        lea rbx, de
        add rbx, 4 + 4 + 4  ; Exception record
        mov eax, [rbx]       ; ExceptionCode
        cmp eax, EXCEPTION_BREAKPOINT
        je _he_bp
        cmp eax, EXCEPTION_SINGLE_STEP
        je _he_ss
        cmp eax, EXCEPTION_ACCESS_VIOLATION
        je _he_av
        ; Unknown exception
        lea rdx, str_err
        call _print_str
        lea rdx, str_ex_uk
        call _print_str
        mov rcx, rax
        call _print_hex64
        call _print_crlf
        jmp _he_not_handled

_he_bp:
        ; Get exception address
        mov rcx, [rbx + 16]  ; ExceptionAddress
        ; Check if it's one of our breakpoints
        call _find_bp
        cmp eax, -1
        je _he_bp_notours
        ; It's ours - restore original byte, step over, then restore bp
        mov r12d, eax
        lea rdi, bp_table
        mov eax, sizeof BREAKPOINT
        mul r12d
        add rdi, rax
        ; Restore original byte
        mov rcx, g_hProcess
        mov rdx, [rdi + BREAKPOINT.addr]
        lea r8, tmp_buf
        mov al, [rdi + BREAKPOINT.orig_byte]
        mov [r8], al
        mov r9d, 1
        call WriteProcessMemory
        ; Step back RIP to re-execute the original instruction
        call _get_context
        lea rbx, ctx
        mov rax, [rbx + CONTEXT.Rip]
        dec rax
        mov [rbx + CONTEXT.Rip], rax
        call _set_context
        ; Show info
        lea rdx, str_info
        call _print_str
        lea rdx, str_ex_bp
        call _print_str
        mov rcx, [rdi + BREAKPOINT.addr]
        call _print_hex64
        call _print_crlf
        ; Show registers
        call _show_regs
        mov g_running, 0
        jmp _he_handled

_he_bp_notours:
        ; System or other breakpoint
        lea rdx, str_info
        call _print_str
        lea rdx, str_ex_bp
        call _print_str
        mov rcx, [rbx + 16]
        call _print_hex64
        call _print_crlf
        call _show_regs
        mov g_running, 0
        jmp _he_handled

_he_ss:
        lea rdx, str_info
        call _print_str
        lea rdx, str_ex_ss
        call _print_str
        mov rcx, [rbx + 16]
        call _print_hex64
        call _print_crlf
        call _show_regs
        mov g_running, 0
        jmp _he_handled

_he_av:
        lea rdx, str_err
        call _print_str
        lea rdx, str_ex_av
        call _print_str
        mov rcx, [rbx + 16]
        call _print_hex64
        call _print_crlf
        mov g_running, 0
        jmp _he_not_handled

_he_handled:
        mov ecx, de.dwProcessId
        mov edx, de.dwThreadId
        mov r8d, DBG_EXCEPTION_HANDLED
        call ContinueDebugEvent
        jmp _he_ret

_he_not_handled:
        mov ecx, de.dwProcessId
        mov edx, de.dwThreadId
        mov r8d, DBG_EXCEPTION_NOT_HANDLED
        call ContinueDebugEvent
        jmp _he_ret

_he_continue:
        mov ecx, de.dwProcessId
        mov edx, de.dwThreadId
        mov r8d, DBG_CONTINUE
        call ContinueDebugEvent

_he_ret:
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
_handle_event endp

;-----------------------------------------------------------------------------
; _cmd_attach - attach <pid>
;-----------------------------------------------------------------------------
_cmd_attach proc
        push rbx
        push rsi
        push rdi
        mov ecx, 1
        call _get_arg
        test rsi, rsi
        jz _ca_syntax
        call _parse_dec
        jc _ca_syntax
        mov ecx, eax
        call DebugActiveProcess
        test rax, rax
        jz _ca_err
        mov eax, ecx
        mov g_pid, eax
        mov g_attached, 1
        lea rdx, str_ok
        call _print_str
        lea rdx, str_attached
        call _print_str
        movzx rcx, dword ptr g_pid
        call _print_num
        call _print_crlf
        jmp _ca_done
_ca_err:
        call _show_error
        jmp _ca_done
_ca_syntax:
        lea rdx, str_err
        call _print_str
        lea rdx, str_syntax
        call _print_str
_ca_done:
        pop rdi
        pop rsi
        pop rbx
        ret
_cmd_attach endp

;-----------------------------------------------------------------------------
; _cmd_run - run <exe> [args]
;-----------------------------------------------------------------------------
_cmd_run proc
        push rbx
        push rsi
        push rdi
        push r12
        push r13
        ; Get exe path (arg 1)
        mov ecx, 1
        call _get_arg
        test rsi, rsi
        jz _cr_syntax
        mov r12, rsi
        ; Find end of exe path (next space or end)
        mov rdi, rsi
_cr_find:
        mov al, [rdi]
        test al, al
        jz _cr_nospace
        cmp al, 20h
        je _cr_space
        inc rdi
        jmp _cr_find
_cr_space:
        mov byte ptr [rdi], 0
        inc rdi
        mov r13, rdi
        jmp _cr_exec
_cr_nospace:
        xor r13, r13
_cr_exec:
        ; Setup STARTUPINFOA
        lea rbx, si
        mov dword ptr [rbx + STARTUPINFOA.cb], sizeof STARTUPINFOA
        ; Create process with DEBUG_PROCESS
        mov rcx, r12       ; lpApplicationName
        mov rdx, r13       ; lpCommandLine (or null)
        xor r8, r8         ; lpProcessAttributes
        xor r9, r9         ; lpThreadAttributes
        mov qword ptr [rsp + 32 + 0*8], 0   ; bInheritHandles
        mov qword ptr [rsp + 32 + 1*8], DEBUG_PROCESS or DEBUG_ONLY_THIS_PROCESS or CREATE_NEW_CONSOLE
        mov qword ptr [rsp + 32 + 2*8], 0   ; lpEnvironment
        mov qword ptr [rsp + 32 + 3*8], 0   ; lpCurrentDirectory
        lea rax, si
        mov qword ptr [rsp + 32 + 4*8], rax ; lpStartupInfo
        lea rax, pi
        mov qword ptr [rsp + 32 + 5*8], rax ; lpProcessInformation
        sub rsp, 8 + 6*8   ; shadow space + args
        call CreateProcessA
        add rsp, 8 + 6*8
        test rax, rax
        jz _cr_err
        mov g_attached, 1
        mov eax, pi.dwProcessId
        mov g_pid, eax
        mov rax, pi.hProcess
        mov g_hProcess, rax
        mov rax, pi.hThread
        mov g_hThread, rax
        lea rdx, str_ok
        call _print_str
        lea rdx, str_created
        call _print_str
        movzx rcx, dword ptr g_pid
        call _print_num
        call _print_crlf
        jmp _cr_done
_cr_err:
        call _show_error
        jmp _cr_done
_cr_syntax:
        lea rdx, str_err
        call _print_str
        lea rdx, str_syntax
        call _print_str
_cr_done:
        pop r13
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
_cmd_run endp

;-----------------------------------------------------------------------------
; _cmd_break - b <addr>
;-----------------------------------------------------------------------------
_cmd_break proc
        push rbx
        push rsi
        push rdi
        mov ecx, 1
        call _get_arg
        test rsi, rsi
        jz _cb_syntax
        call _parse_hex
        jc _cb_syntax
        mov rcx, rax
        call _set_bp
        jmp _cb_done
_cb_syntax:
        lea rdx, str_err
        call _print_str
        lea rdx, str_syntax
        call _print_str
_cb_done:
        pop rdi
        pop rsi
        pop rbx
        ret
_cmd_break endp

;-----------------------------------------------------------------------------
; _cmd_bc - bc <index>
;-----------------------------------------------------------------------------
_cmd_bc proc
        push rbx
        push rsi
        push rdi
        mov ecx, 1
        call _get_arg
        test rsi, rsi
        jz _cbc_syntax
        call _parse_dec
        jc _cbc_syntax
        mov ecx, eax
        call _clear_bp
        jmp _cbc_done
_cbc_syntax:
        lea rdx, str_err
        call _print_str
        lea rdx, str_syntax
        call _print_str
_cbc_done:
        pop rdi
        pop rsi
        pop rbx
        ret
_cmd_bc endp

;-----------------------------------------------------------------------------
; _cmd_dump - db/dd/dq <addr> [len]
;-----------------------------------------------------------------------------
_cmd_dump proc
        push rbx
        push rsi
        push rdi
        push r12
        push r13
        mov r13d, r8d       ; size
        mov ecx, 1
        call _get_arg
        test rsi, rsi
        jz _cd_syntax
        call _parse_hex
        jc _cd_syntax
        mov r12, rax
        ; Get length
        mov ecx, 2
        call _get_arg
        test rsi, rsi
        jz _cd_default
        call _parse_dec
        jc _cd_default
        mov rdx, rax
        jmp _cd_do
_cd_default:
        mov rdx, 64
_cd_do:
        mov rcx, r12
        mov r8d, r13d
        call _dump_mem
        jmp _cd_done
_cd_syntax:
        lea rdx, str_err
        call _print_str
        lea rdx, str_syntax
        call _print_str
_cd_done:
        pop r13
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
_cmd_dump endp

;-----------------------------------------------------------------------------
; _cmd_edit - eb/ed/eq <addr> <val>
;-----------------------------------------------------------------------------
_cmd_edit proc
        push rbx
        push rsi
        push rdi
        push r12
        push r13
        mov r13d, r8d       ; size
        mov ecx, 1
        call _get_arg
        test rsi, rsi
        jz _ce_syntax
        call _parse_hex
        jc _ce_syntax
        mov r12, rax
        mov ecx, 2
        call _get_arg
        test rsi, rsi
        jz _ce_syntax
        call _parse_hex
        jc _ce_syntax
        mov rcx, r12
        mov rdx, rax
        mov r8d, r13d
        call _edit_mem
        jmp _ce_done
_ce_syntax:
        lea rdx, str_err
        call _print_str
        lea rdx, str_syntax
        call _print_str
_ce_done:
        pop r13
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
_cmd_edit endp

;-----------------------------------------------------------------------------
; _cmd_unasm - u <addr> [len]
;-----------------------------------------------------------------------------
_cmd_unasm proc
        push rbx
        push rsi
        push rdi
        push r12
        mov ecx, 1
        call _get_arg
        test rsi, rsi
        jz _cu_syntax
        call _parse_hex
        jc _cu_syntax
        mov r12, rax
        mov ecx, 2
        call _get_arg
        test rsi, rsi
        jz _cu_default
        call _parse_dec
        jc _cu_default
        mov rdx, rax
        jmp _cu_do
_cu_default:
        mov rdx, 10
_cu_do:
        mov rcx, r12
        call _unasm
        jmp _cu_done
_cu_syntax:
        lea rdx, str_err
        call _print_str
        lea rdx, str_syntax
        call _print_str
_cu_done:
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
_cmd_unasm endp

;-----------------------------------------------------------------------------
; _parse_cmd - Parse and execute command
;-----------------------------------------------------------------------------
_parse_cmd proc
        push rbx
        push rsi
        push rdi
        ; Get first token
        call _strtok
        test rsi, rsi
        jz _pc_done
        ; Check commands
        lea rdi, str_cmd_attach
        call _strcmp
        test al, al
        jz _pc_attach
        lea rdi, str_cmd_run
        call _strcmp
        test al, al
        jz _pc_run
        lea rdi, str_cmd_break
        call _strcmp
        test al, al
        jz _pc_break
        lea rdi, str_cmd_bc
        call _strcmp
        test al, al
        jz _pc_bc
        lea rdi, str_cmd_bl
        call _strcmp
        test al, al
        jz _pc_bl
        lea rdi, str_cmd_go
        call _strcmp
        test al, al
        jz _pc_go
        lea rdi, str_cmd_trace
        call _strcmp
        test al, al
        jz _pc_trace
        lea rdi, str_cmd_step
        call _strcmp
        test al, al
        jz _pc_step
        lea rdi, str_cmd_regs
        call _strcmp
        test al, al
        jz _pc_regs
        lea rdi, str_cmd_dumpb
        call _strcmp
        test al, al
        jz _pc_db
        lea rdi, str_cmd_dumpd
        call _strcmp
        test al, al
        jz _pc_dd
        lea rdi, str_cmd_dumpq
        call _strcmp
        test al, al
        jz _pc_dq
        lea rdi, str_cmd_editb
        call _strcmp
        test al, al
        jz _pc_eb
        lea rdi, str_cmd_editd
        call _strcmp
        test al, al
        jz _pc_ed
        lea rdi, str_cmd_editq
        call _strcmp
        test al, al
        jz _pc_eq
        lea rdi, str_cmd_unasm
        call _strcmp
        test al, al
        jz _pc_u
        lea rdi, str_cmd_quit
        call _strcmp
        test al, al
        jz _pc_quit
        lea rdi, str_cmd_help
        call _strcmp
        test al, al
        jz _pc_help
        ; Unknown
        lea rdx, str_err
        call _print_str
        lea rdx, str_unknown
        call _print_str
        jmp _pc_done

_pc_attach:
        call _cmd_attach
        jmp _pc_done
_pc_run:
        call _cmd_run
        jmp _pc_done
_pc_break:
        call _cmd_break
        jmp _pc_done
_pc_bc:
        call _cmd_bc
        jmp _pc_done
_pc_bl:
        call _list_bp
        jmp _pc_done
_pc_go:
        call _do_go
        jmp _pc_done
_pc_trace:
        call _do_step
        jmp _pc_done
_pc_step:
        call _do_stepover
        jmp _pc_done
_pc_regs:
        call _get_context
        call _show_regs
        jmp _pc_done
_pc_db:
        mov r8d, 1
        call _cmd_dump
        jmp _pc_done
_pc_dd:
        mov r8d, 4
        call _cmd_dump
        jmp _pc_done
_pc_dq:
        mov r8d, 8
        call _cmd_dump
        jmp _pc_done
_pc_eb:
        mov r8d, 1
        call _cmd_edit
        jmp _pc_done
_pc_ed:
        mov r8d, 4
        call _cmd_edit
        jmp _pc_done
_pc_eq:
        mov r8d, 8
        call _cmd_edit
        jmp _pc_done
_pc_u:
        call _cmd_unasm
        jmp _pc_done
_pc_quit:
        call _do_quit
        jmp _pc_done
_pc_help:
        lea rdx, str_help
        call _print_str
        jmp _pc_done

_pc_done:
        pop rdi
        pop rsi
        pop rbx
        ret
_parse_cmd endp

;-----------------------------------------------------------------------------
; _debug_loop - Main debug event loop
;-----------------------------------------------------------------------------
_debug_loop proc
        push rbx
        push rsi
        push rdi
        mov g_running, 1
_dl_loop:
        cmp g_quit, 0
        jne _dl_done
        cmp g_running, 0
        je _dl_prompt
        ; Wait for debug event
        lea rcx, de
        mov edx, 100       ; 100ms timeout
        call WaitForDebugEventEx
        test rax, rax
        jnz _dl_event
        ; Timeout - check if still running
        jmp _dl_loop
_dl_event:
        call _handle_event
        jmp _dl_loop
_dl_prompt:
        ; Show prompt and wait for command
        lea rdx, str_prompt
        call _print_str
        call _read_line
        call _parse_cmd
        jmp _dl_loop
_dl_done:
        pop rdi
        pop rsi
        pop rbx
        ret
_debug_loop endp

;-----------------------------------------------------------------------------
; main - Entry point
;-----------------------------------------------------------------------------
main proc
        sub rsp, 28h       ; shadow space + alignment
        ; Get console handles
        mov ecx, STD_OUTPUT_HANDLE
        call GetStdHandle
        mov hStdOut, rax
        mov ecx, STD_INPUT_HANDLE
        call GetStdHandle
        mov hStdIn, rax
        ; Print banner
        lea rdx, str_banner
        call _print_str
        call _print_crlf
        ; Check command line for auto-attach or auto-run
        call GetCommandLineA
        mov rsi, rax
        ; Skip exe name
        mov al, [rsi]
        cmp al, 22h        ; quote
        jne _m_nospace
        inc rsi
_m_skipq:
        mov al, [rsi]
        inc rsi
        cmp al, 22h
        jne _m_skipq
        jmp _m_skipsp
_m_nospace:
_m_skipn:
        mov al, [rsi]
        inc rsi
        cmp al, 20h
        jne _m_skipn
_m_skipsp:
        mov al, [rsi]
        cmp al, 20h
        jne _m_check
        inc rsi
        jmp _m_skipsp
_m_check:
        test al, al
        jz _m_interactive
        ; Parse auto command
        lea rdi, cmd_buf
_m_copy:
        mov al, [rsi]
        mov [rdi], al
        inc rsi
        inc rdi
        test al, al
        jnz _m_copy
        call _parse_cmd
        cmp g_attached, 0
        je _m_interactive
        call _debug_loop
        jmp _m_exit
_m_interactive:
        ; Interactive mode
        lea rdx, str_prompt
        call _print_str
        call _read_line
        call _parse_cmd
        cmp g_quit, 0
        je _m_interactive
_m_exit:
        xor ecx, ecx
        call ExitProcess
main endp

        end

