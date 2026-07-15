;=============================================================================  
; Victim.exe - Minimal Test Target for Beacon Debugger  
; Purpose: Provide predictable breakpoint targets for debugger validation  
; Build: ml64.exe victim.asm /link /subsystem:console /entry:main kernel32.lib  
;=============================================================================  
  
        includelib kernel32.lib  
  
        extrn GetStdHandle:proc  
        extrn WriteFile:proc  
        extrn Sleep:proc  
        extrn ExitProcess:proc  
  
STD_OUTPUT_HANDLE equ -11  
  
        .data  
align 8  
  
; Markers for breakpoint locations  
; These labels are at predictable offsets for testing  
msg_hello       db "Victim: Hello from entry point!", 13, 10  
msg_len         equ $ - msg_hello  
  
msg_loop        db "Victim: Loop iteration...", 13, 10  
msg_loop_len    equ $ - msg_loop  
  
hStdOut         dq ?  
bytes_written   dq ?  
loop_counter    dd 0  
  
        .code  
  
;=============================================================================  
; BREAKPOINT TARGET 1: Entry Point  
; Address: main  
; Expected RIP: Near image base + small offset  
;=============================================================================  
main proc  
        ; Allocate shadow space (Win64 ABI)  
        sub rsp, 28h  
        
        ; Get stdout handle  
        mov ecx, STD_OUTPUT_HANDLE  
        call GetStdHandle  
        mov hStdOut, rax  
        
        ; === BREAKPOINT TARGET ===  
        ; Debugger should stop here for Test #1  
        ; Label: __bp_entry_point  
__bp_entry_point:  
        
        ; Print entry message  
        mov rcx, hStdOut  
        lea rdx, msg_hello  
        mov r8d, msg_len  
        lea r9, bytes_written  
        mov qword ptr [rsp + 20h], 0  
        call WriteFile  
        
        ; === BREAKPOINT TARGET ===  
        ; Debugger should stop here for Test #2  
        ; Label: __bp_loop_start  
__bp_loop_start:  
        
        ; Loop 10 times with delays  
        mov dword ptr [loop_counter], 0  
        
_loop_begin:  
        cmp dword ptr [loop_counter], 10  
        jge _loop_end  
        
        ; === BREAKPOINT TARGET ===  
        ; Debugger should stop here for Test #3  
        ; Label: __bp_loop_body  
__bp_loop_body:  
        
        ; Print loop message  
        mov rcx, hStdOut  
        lea rdx, msg_loop  
        mov r8d, msg_loop_len  
        lea r9, bytes_written  
        mov qword ptr [rsp + 20h], 0  
        call WriteFile  
        
        ; Delay 500ms  
        mov ecx, 500  
        call Sleep  
        
        ; Increment counter  
        inc dword ptr [loop_counter]  
        jmp _loop_begin  
        
_loop_end:  
        ; === BREAKPOINT TARGET ===  
        ; Debugger should stop here for Test #4  
        ; Label: __bp_exit_point  
__bp_exit_point:  
        
        ; Restore stack and exit  
        add rsp, 28h  
        xor ecx, ecx  
        call ExitProcess  
main endp  
  
        end  
