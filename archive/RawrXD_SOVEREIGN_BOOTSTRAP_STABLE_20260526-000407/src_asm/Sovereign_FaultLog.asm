; Sovereign_FaultLog.asm - Atomic NVMe telemetry flush
; ABI: Zero-CRT, Win64, kernel32.lib only
; Writes g_BlackBoxBuffer (4096 bytes, page-aligned) via unbuffered I/O

.CODE

PUBLIC XR_FaultLog_Flush
XR_FaultLog_Flush PROC
    push rbx
    sub rsp, 64                     ; 32 shadow + 24 stack args + 8 scratch, aligned

    ; --- CreateFileW: OPEN_ALWAYS, unbuffered, write-through ---
    lea rcx, [log_path]             ; lpFileName (UTF-16)
    mov edx, 40100000h              ; GENERIC_WRITE | SYNCHRONIZE
    xor r8d, r8d                    ; dwShareMode = 0 (exclusive)
    xor r9d, r9d                    ; lpSecurityAttributes = NULL
    mov qword ptr [rsp+32], 4       ; dwCreationDisposition = OPEN_ALWAYS
    mov qword ptr [rsp+40], 80h     ; dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+48], 0A0000000h ; FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH
    call CreateFileW
    cmp rax, -1
    je flush_done                  ; Silent fail - can't log a log failure
    mov [rsp+56], rax               ; Save hLog in scratch slot

    ; --- WriteFile: Synchronous, 4096-byte sector-aligned write ---
    mov dword ptr [rsp+40], 0       ; Dummy DWORD for lpNumberOfBytesWritten
    mov rcx, [rsp+56]               ; hFile
    lea rdx, [g_BlackBoxBuffer]     ; lpBuffer (page-aligned from _BBOX segment)
    mov r8d, 1000h                  ; nNumberOfBytesToWrite = 4096
    lea r9, [rsp+40]                ; lpNumberOfBytesWritten
    mov qword ptr [rsp+32], 0       ; lpOverlapped = NULL (synchronous)
    call WriteFile

    ; --- CloseHandle ---
    mov rcx, [rsp+56]
    call CloseHandle

flush_done:
    add rsp, 64
    pop rbx
    ret
XR_FaultLog_Flush ENDP

EXTERN CreateFileW : PROC
EXTERN WriteFile : PROC
EXTERN CloseHandle : PROC
EXTERN g_BlackBoxBuffer : BYTE

.DATA
align 2
log_path            dw 'D',':','\\','r','a','w','r','x','d','\\','l','o','g','s','\\','s','o','v','e','r','e','i','g','n','_','f','a','u','l','t','.','l','o','g',0
END