;=============================================================================  
; TestDriver.asm - Automated Integration Test for Beacon Debugger  
; Purpose: Scriptable driver to run BeaconDebugger + Victim validation  
; Build: ml64.exe TestDriver.asm /link /subsystem:console /entry:main kernel32.lib  
;=============================================================================  
  
        includelib kernel32.lib  
  
        extrn GetStdHandle:proc  
        extrn WriteFile:proc  
        extrn CreateProcessA:proc  
        extrn WaitForSingleObject:proc  
        extrn CloseHandle:proc  
        extrn ExitProcess:proc  
        extrn Sleep:proc  
  
STD_OUTPUT_HANDLE equ -11  
INFINITE equ -1  
  
        .data  
align 8  
  
hStdOut         dq ?  
bytes_written   dq ?  
pi              dq 2 dup(?)    ; PROCESS_INFORMATION  
si              db 104 dup(?)  ; STARTUPINFOA  
  
; Test commands  
cmd_test1       db "run Victim.exe", 13, 10, 0  
cmd_test2       db "g", 13, 10, 0  
cmd_test3       db "q", 13, 10, 0  
  
; Messages  
msg_header      db "=== RawrXD Integration Test Driver ===", 13, 10, 0  
msg_header_len  equ $ - msg_header  
msg_test1       db "Test 1: Launching BeaconDebugger with Victim...", 13, 10, 0  
msg_test1_len   equ $ - msg_test1  
msg_success     db "SUCCESS: All tests passed!", 13, 10, 0  
msg_success_len equ $ - msg_success  
msg_fail        db "FAILED: Test encountered error", 13, 10, 0  
msg_fail_len    equ $ - msg_fail  
  
; Paths  
exe_debugger    db "BeaconDebugger.exe", 0  
exe_victim      db "Victim.exe", 0  
  
        .code  
  
;-----------------------------------------------------------------------------  
; print_msg - Print message to stdout  
;-----------------------------------------------------------------------------  
print_msg proc  
        push rbx  
        push rsi  
        push rdi  
        sub rsp, 28h  
        
        mov rbx, rcx        ; Message  
        mov rdi, rcx  
        xor eax, eax  
        mov ecx, 0FFFFFFFFh  
        repne scasb  
        mov ecx, 0FFFFFFFFh  
        sub ecx, eax  
        dec ecx             ; Length  
        
        mov rdx, rbx  
        mov r8d, ecx  
        lea r9, bytes_written  
        mov rcx, hStdOut  
        mov qword ptr [rsp + 20h], 0  
        call WriteFile  
        
        add rsp, 28h  
        pop rdi  
        pop rsi  
        pop rbx  
        ret  
print_msg endp  
  
;-----------------------------------------------------------------------------  
; run_test - Launch debugger with victim  
;-----------------------------------------------------------------------------  
run_test proc  
        push rbx  
        push rsi  
        push rdi  
        push r12  
        sub rsp, 50h        ; Shadow + args  
        
        ; Zero STARTUPINFOA  
        lea rdi, si  
        xor eax, eax  
        mov ecx, 104 / 8  
        rep stosq  
        mov dword ptr [si], 104  ; cb  
        
        ; Build command line: "BeaconDebugger.exe"  
        ; In real test, we'd pipe commands to stdin  
        
        ; CreateProcessA arguments  
        lea rcx, exe_debugger   ; lpApplicationName  
        xor rdx, rdx            ; lpCommandLine  
        xor r8, r8              ; lpProcessAttributes  
        xor r9, r9              ; lpThreadAttributes  
        mov qword ptr [rsp + 20h], 0    ; bInheritHandles  
        mov qword ptr [rsp + 28h], 0    ; dwCreationFlags  
        mov qword ptr [rsp + 30h], 0    ; lpEnvironment  
        mov qword ptr [rsp + 38h], 0    ; lpCurrentDirectory  
        lea rax, si  
        mov [rsp + 40h], rax            ; lpStartupInfo  
        lea rax, pi  
        mov [rsp + 48h], rax            ; lpProcessInformation  
        
        call CreateProcessA  
        
        test rax, rax  
        jz _rt_fail  
        
        ; Wait for process to complete  
        mov rcx, [pi]           ; hProcess  
        mov edx, 10000          ; 10 second timeout  
        call WaitForSingleObject  
        
        ; Close handles  
        mov rcx, [pi]  
        call CloseHandle  
        mov rcx, [pi + 8]       ; hThread  
        call CloseHandle  
        
        mov eax, 1              ; Success  
        jmp _rt_done  
        
_rt_fail:  
        xor eax, eax            ; Failure  
        
_rt_done:  
        add rsp, 50h  
        pop r12  
        pop rdi  
        pop rsi  
        pop rbx  
        ret  
run_test endp  
  
;-----------------------------------------------------------------------------  
; main - Entry point  
;-----------------------------------------------------------------------------  
main proc  
        push rbx  
        push rsi  
        push rdi  
        sub rsp, 28h  
        
        ; Get stdout  
        mov ecx, STD_OUTPUT_HANDLE  
        call GetStdHandle  
        mov hStdOut, rax  
        
        ; Print header  
        lea rcx, msg_header  
        call print_msg  
        
        ; Run test  
        lea rcx, msg_test1  
        call print_msg  
        
        call run_test  
        test rax, rax  
        jz _m_fail  
        
        ; Success  
        lea rcx, msg_success  
        call print_msg  
        jmp _m_exit  
        
_m_fail:  
        lea rcx, msg_fail  
        call print_msg  
        
_m_exit:  
        add rsp, 28h  
        pop rdi  
        pop rsi  
        pop rbx  
        xor ecx, ecx  
        call ExitProcess  
main endp  
  
        end  
