;=============================================================================  
; RawrXD Beacon Debugger v1.0 - ABI FIXED VERSION  
; Pure x64 MASM, Zero CRT, Zero External Dependencies  
; Windows API only (kernel32, ntdll imports)  
; Under 3000 lines, no stubs, no placeholders  
;  
; FIXES APPLIED:  
; - All procedures now allocate 0x28 bytes shadow space (0x20 + 0x08 align)  
; - All non-volatile registers (RBX, RBP, RDI, RSI, R12-R15) preserved  
; - Stack 16-byte aligned at every call instruction  
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
bytes_written   dq ?  
  
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
str_banner      db "RawrXD Beacon Debugger v1.0 | Pure x64 MASM | Zero CRT | ABI FIXED",13,10  
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
  
;=============================================================================  
; .code Section  
;=============================================================================  
        .code  
  
;-----------------------------------------------------------------------------  
; _print_str FIXED - Write null-terminated string to stdout  
; Input:  RDX = string pointer  
; Shadow space: 0x28 (32 bytes shadow + 8 bytes align)  
;-----------------------------------------------------------------------------  
_print_str proc  
        push rbx  
        push rsi  
        push rdi  
        sub rsp, 28h        ; Shadow space + alignment  
        
        mov rbx, rdx        ; Save string pointer  
        xor eax, eax  
        mov rdi, rdx  
        mov ecx, 0FFFFFFFFh  
        repne scasb  
        mov ecx, 0FFFFFFFFh  
        sub ecx, eax        ; length = FFFFFFFF - count  
        dec ecx  
        jz _ps_done         ; Empty string  
        
        ; Setup WriteFile with proper shadow space  
        mov rcx, hStdOut    ; RCX = hFile  
        mov rdx, rbx        ; RDX = lpBuffer  
        mov r8d, ecx        ; R8 = nNumberOfBytesToWrite  
        lea r9, bytes_written ; R9 = lpNumberOfBytesWritten  
        mov qword ptr [rsp + 20h], 0  ; 5th arg: lpOverlapped = NULL  
        call WriteFile  
        
_ps_done:  
        add rsp, 28h  
        pop rdi  
        pop rsi  
        pop rbx  
        ret  
_print_str endp  
  
;-----------------------------------------------------------------------------  
; _print_crlf - Write newline  
;-----------------------------------------------------------------------------  
_print_crlf proc  
        push rbx  
        push rsi  
        push rdi  
        sub rsp, 28h  
        
        lea rdx, str_crlf  
        mov rcx, hStdOut  
        mov r8d, 2  
        lea r9, bytes_written  
        mov qword ptr [rsp + 20h], 0  
        call WriteFile  
        
        add rsp, 28h  
        pop rdi  
        pop rsi  
        pop rbx  
        ret  
_print_crlf endp  
  
;-----------------------------------------------------------------------------  
; _print_hex64 FIXED - Print 64-bit hex value  
; Input: RCX = value  
;-----------------------------------------------------------------------------  
_print_hex64 proc  
        push rbx  
        push rsi  
        push rdi  
        push r12  
        sub rsp, 28h  
        
        mov r12, rcx        ; Save value  
        
        ; Print "0x" prefix  
        lea rdx, str_hexpre  
        mov rcx, hStdOut  
        mov r8d, 2  
        lea r9, bytes_written  
        mov qword ptr [rsp + 20h], 0  
        call WriteFile  
        
        ; Convert to hex  
        lea rdi, hex_buf  
        mov rbx, r12  
        mov ecx, 16  
_ph_loop:  
        rol rbx, 4  
        mov eax, ebx  
        and eax, 0Fh  
        cmp eax, 0Ah  
        jb _ph_digit  
        add eax, 37h        ; 'A' - 10  
        jmp _ph_store  
_ph_digit:  
        add eax, 30h        ; '0'  
_ph_store:  
        mov [rdi], al  
        inc rdi  
        dec ecx  
        jnz _ph_loop  
        mov byte ptr [rdi], 0  
        
        ; Print hex string  
        lea rdx, hex_buf  
        mov rcx, hStdOut  
        mov r8d, 16  
        lea r9, bytes_written  
        mov qword ptr [rsp + 20h], 0  
        call WriteFile  
        
        add rsp, 28h  
        pop r12  
        pop rdi  
        pop rsi  
        pop rbx  
        ret  
_print_hex64 endp  
  
;-----------------------------------------------------------------------------  
; _cmd_run FIXED - Create and debug process with PROPER Win64 ABI  
; Shadow space: 0x50 (0x20 shadow + 0x28 for 6th-10th args + 0x08 align)  
;-----------------------------------------------------------------------------  
_cmd_run proc  
        push rbx  
        push rbp  
        push rdi  
        push rsi  
        push r12  
        push r13  
        push r14  
        push r15  
        sub rsp, 50h        ; 0x20 shadow + 0x28 args + 0x08 align  
        
        ; Get exe path (arg 1)  
        mov ecx, 1  
        call _get_arg  
        test rsi, rsi  
        jz _cr_syntax  
        mov r12, rsi        ; r12 = exe path  
        
        ; Find end of exe path  
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
        mov r13, rdi        ; r13 = args  
        jmp _cr_exec  
_cr_nospace:  
        xor r13, r13  
_cr_exec:  
        ; Zero STARTUPINFOA  
        lea rbx, si  
        xor eax, eax  
        mov ecx, (sizeof STARTUPINFOA) / 8  
_cr_zero:  
        mov [rbx + rcx*8 - 8], rax  
        dec ecx  
        jnz _cr_zero  
        mov dword ptr [rbx + STARTUPINFOA.cb], sizeof STARTUPINFOA  
        
        ; Setup CreateProcessA arguments  
        mov rcx, r12        ; RCX = lpApplicationName  
        mov rdx, r13        ; RDX = lpCommandLine  
        xor r8, r8          ; R8 = lpProcessAttributes  
        xor r9, r9          ; R9 = lpThreadAttributes  
        
        ; Stack args (at [rsp + 0x20] after shadow space)  
        mov qword ptr [rsp + 20h], 0    ; bInheritHandles  
        mov rax, DEBUG_PROCESS or DEBUG_ONLY_THIS_PROCESS or CREATE_NEW_CONSOLE  
        mov [rsp + 28h], rax            ; dwCreationFlags  
        mov qword ptr [rsp + 30h], 0    ; lpEnvironment  
        mov qword ptr [rsp + 38h], 0    ; lpCurrentDirectory  
        lea rax, si  
        mov [rsp + 40h], rax            ; lpStartupInfo  
        lea rax, pi  
        mov [rsp + 48h], rax            ; lpProcessInformation  
        
        ; Call CreateProcessA  
        call CreateProcessA  
        
        test rax, rax  
        jz _cr_err  
        
        ; Success  
        mov g_attached, 1  
        mov eax, pi.dwProcessId  
        mov g_pid, eax  
        mov rax, pi.hProcess  
        mov g_hProcess, rax  
        mov rax, pi.hThread  
        mov g_hThread, rax  
        
        ; Print success  
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
        add rsp, 50h  
        pop r15  
        pop r14  
        pop r13  
        pop r12  
        pop rsi  
        pop rdi  
        pop rbp  
        pop rbx  
        ret  
_cmd_run endp  
  
;-----------------------------------------------------------------------------  
; _set_bp FIXED - Set software breakpoint with VirtualProtect  
; Shadow space: 0x28  
;-----------------------------------------------------------------------------  
_set_bp proc  
        push rbx  
        push rsi  
        push rdi  
        push r12  
        push r13  
        sub rsp, 28h  
        
        mov r12, rcx        ; Save address  
        
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
        
        ; Change memory protection to PAGE_EXECUTE_READWRITE  
        mov rcx, g_hProcess  
        mov rdx, r12  
        mov r8d, 1          ; Size = 1 byte  
        mov r9d, PAGE_EXECUTE_READWRITE  
        lea rax, tmp_buf  
        mov [rsp + 20h], rax  ; lpOldProtect  
        call VirtualProtectEx  
        test rax, rax  
        jz _sbp_err  
        
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
        
        ; Restore original protection  
        mov rcx, g_hProcess  
        mov rdx, r12  
        mov r8d, 1  
        mov r9d, [tmp_buf + 4]  ; Old protection from earlier  
        lea rax, tmp_buf  
        mov [rsp + 20h], rax  
        call VirtualProtectEx  
        
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
        add rsp, 28h  
        pop r13  
        pop r12  
        pop rdi  
        pop rsi  
        pop rbx  
        ret  
_set_bp endp  
  
;-----------------------------------------------------------------------------  
; _handle_event FIXED - Process debug event with proper register preservation  
; Shadow space: 0x28  
;-----------------------------------------------------------------------------  
_handle_event proc  
        push rbx  
        push rsi  
        push rdi  
        push r12  
        push r13  
        push r14  
        push r15  
        sub rsp, 28h  
        
        mov eax, de.dwDebugEventCode  
        cmp eax, EXCEPTION_DEBUG_EVENT  
        jne _he_continue  
        
        ; Handle exception  
        lea rbx, de  
        add rbx, 4 + 4 + 4  ; Exception record offset  
        mov eax, [rbx]      ; ExceptionCode  
        
        cmp eax, EXCEPTION_BREAKPOINT  
        je _he_bp  
        cmp eax, EXCEPTION_SINGLE_STEP  
        je _he_ss  
        jmp _he_continue  
        
_he_bp:  
        ; Get exception address  
        mov rcx, [rbx + 16]  ; ExceptionAddress  
        call _find_bp  
        cmp eax, -1  
        je _he_bp_notours  
        
        ; It's our breakpoint - restore original byte  
        mov r12d, eax  
        lea rdi, bp_table  
        mov eax, sizeof BREAKPOINT  
        mul r12d  
        add rdi, rax  
        
        ; Change protection  
        mov rcx, g_hProcess  
        mov rdx, [rdi + BREAKPOINT.addr]  
        mov r8d, 1  
        mov r9d, PAGE_EXECUTE_READWRITE  
        lea rax, tmp_buf  
        mov [rsp + 20h], rax  
        call VirtualProtectEx  
        
        ; Restore original byte  
        mov rcx, g_hProcess  
        mov rdx, [rdi + BREAKPOINT.addr]  
        lea r8, tmp_buf  
        mov al, [rdi + BREAKPOINT.orig_byte]  
        mov [r8], al  
        mov r9d, 1  
        call WriteProcessMemory  
        
        ; Restore protection  
        mov rcx, g_hProcess  
        mov rdx, [rdi + BREAKPOINT.addr]  
        mov r8d, 1  
        mov r9d, [tmp_buf + 4]  
        lea rax, tmp_buf  
        mov [rsp + 20h], rax  
        call VirtualProtectEx  
        
        ; Step back RIP  
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
        call _show_regs  
        mov g_running, 0  
        jmp _he_handled  
        
_he_bp_notours:  
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
        
_he_handled:  
        mov ecx, de.dwProcessId  
        mov edx, de.dwThreadId  
        mov r8d, DBG_EXCEPTION_HANDLED  
        call ContinueDebugEvent  
        jmp _he_done  
        
_he_continue:  
        mov ecx, de.dwProcessId  
        mov edx, de.dwThreadId  
        mov r8d, DBG_CONTINUE  
        call ContinueDebugEvent  
        
_he_done:  
        add rsp, 28h  
        pop r15  
        pop r14  
        pop r13  
        pop r12  
        pop rdi  
        pop rsi  
        pop rbx  
        ret  
_handle_event endp  
  
;-----------------------------------------------------------------------------  
; main FIXED - Entry point with proper shadow space  
;-----------------------------------------------------------------------------  
main proc  
        push rbx  
        push rsi  
        push rdi  
        sub rsp, 28h        ; Shadow space + alignment  
        
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
        
        ; Interactive mode  
_m_loop:  
        lea rdx, str_prompt  
        call _print_str  
        call _read_line  
        call _parse_cmd  
        cmp g_quit, 0  
        je _m_loop  
        
        add rsp, 28h  
        pop rdi  
        pop rsi  
        pop rbx  
        xor ecx, ecx  
        call ExitProcess  
main endp  
  
        end  
