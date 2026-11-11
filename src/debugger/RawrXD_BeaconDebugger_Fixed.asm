;-----------------------------------------------------------------------------  
; _cmd_run FIXED - Proper Win64 ABI Compliance  
; Shadow Space: 32 bytes (0x20) + 8 bytes alignment = 0x28 total  
; Preserves all non-volatile registers (RBX, RBP, RDI, RSI, R12-R15)  
;-----------------------------------------------------------------------------  
_cmd_run proc  
        ; Save all non-volatile registers  
        push rbx  
        push rbp  
        push rdi  
        push rsi  
        push r12  
        push r13  
        push r14  
        push r15  
        
        ; Allocate shadow space + alignment  
        ; We need 0x20 (shadow) + 0x28 (6th-10th args on stack) + 0x8 (align) = 0x50  
        sub rsp, 50h  
        
        ; Get exe path (arg 1)  
        mov ecx, 1  
        call _get_arg  
        test rsi, rsi  
        jz _cr_syntax  
        mov r12, rsi        ; r12 = exe path (non-volatile, preserved)  
        
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
        mov r13, rdi        ; r13 = args (non-volatile, preserved)  
        jmp _cr_exec  
_cr_nospace:  
        xor r13, r13  
_cr_exec:  
        ; Setup STARTUPINFOA  
        ; Zero the structure first  
        lea rbx, si  
        xor eax, eax  
        mov ecx, (sizeof STARTUPINFOA) / 8  
_cr_zero:  
        mov [rbx + rcx*8 - 8], rax  
        dec ecx  
        jnz _cr_zero  
        
        mov dword ptr [rbx + STARTUPINFOA.cb], sizeof STARTUPINFOA  
        
        ; Setup arguments for CreateProcessA  
        ; RCX = lpApplicationName  
        mov rcx, r12  
        ; RDX = lpCommandLine  
        mov rdx, r13  
        ; R8 = lpProcessAttributes  
        xor r8, r8  
        ; R9 = lpThreadAttributes  
        xor r9, r9  
        
        ; 5th argument (bInheritHandles) -> [rsp + 0x20]  
        mov qword ptr [rsp + 20h], 0  
        ; 6th argument (dwCreationFlags) -> [rsp + 0x28]  
        mov rax, DEBUG_PROCESS or DEBUG_ONLY_THIS_PROCESS or CREATE_NEW_CONSOLE  
        mov [rsp + 28h], rax  
        ; 7th argument (lpEnvironment) -> [rsp + 0x30]  
        mov qword ptr [rsp + 30h], 0  
        ; 8th argument (lpCurrentDirectory) -> [rsp + 0x38]  
        mov qword ptr [rsp + 38h], 0  
        ; 9th argument (lpStartupInfo) -> [rsp + 0x40]  
        lea rax, si  
        mov [rsp + 40h], rax  
        ; 10th argument (lpProcessInformation) -> [rsp + 0x48]  
        lea rax, pi  
        mov [rsp + 48h], rax  
        
        ; Call CreateProcessA with proper shadow space  
        call CreateProcessA  
        
        ; Check result  
        test rax, rax  
        jz _cr_err  
        
        ; Success - store handles  
        mov g_attached, 1  
        mov eax, pi.dwProcessId  
        mov g_pid, eax  
        mov rax, pi.hProcess  
        mov g_hProcess, rax  
        mov rax, pi.hThread  
        mov g_hThread, rax  
        
        ; Print success message  
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
        ; Deallocate shadow space  
        add rsp, 50h  
        
        ; Restore non-volatile registers  
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
