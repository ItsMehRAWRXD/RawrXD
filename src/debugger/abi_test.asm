;=============================================================================  
; RawrXD ABI Test - Minimal Win64 ABI Verification  
; Build: ml64.exe abi_test.asm /link /subsystem:console /entry:main kernel32.lib  
;=============================================================================  
  
        includelib kernel32.lib  
  
        extrn GetStdHandle:proc  
        extrn WriteFile:proc  
        extrn ExitProcess:proc  
  
STD_OUTPUT_HANDLE equ -11  
  
        .data  
msg     db "Win64 ABI Test: PASS", 13, 10  
msg_len equ $ - msg  
hStdOut dq ?  
bytes_written dq ?  
  
        .code  
  
;-----------------------------------------------------------------------------  
; main - Entry point with PROPER Win64 ABI  
;-----------------------------------------------------------------------------  
main proc  
        ; Allocate shadow space (32 bytes) + alignment (8 bytes) = 40 bytes (0x28)  
        sub rsp, 28h  
        
        ; Get stdout handle  
        mov ecx, STD_OUTPUT_HANDLE  
        call GetStdHandle  
        mov [hStdOut], rax  
        
        ; Setup WriteFile arguments  
        ; RCX = hFile  
        mov rcx, [hStdOut]  
        ; RDX = lpBuffer  
        lea rdx, msg  
        ; R8 = nNumberOfBytesToWrite  
        mov r8d, msg_len  
        ; R9 = lpNumberOfBytesWritten  
        lea r9, bytes_written  
        ; 5th argument (lpOverlapped) -> [rsp + 0x20]  
        mov qword ptr [rsp + 20h], 0  
        
        ; Call WriteFile with proper shadow space  
        call WriteFile  
        
        ; Restore stack  
        add rsp, 28h  
        
        ; Exit  
        xor ecx, ecx  
        call ExitProcess  
main endp  
  
        end  
