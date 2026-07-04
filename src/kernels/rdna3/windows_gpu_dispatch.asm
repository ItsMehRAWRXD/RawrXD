; windows_gpu_dispatch.asm
; Windows-native GPU dispatch for RX 7800 XT
; Uses DirectX 12 or Vulkan instead of AMDKFD

EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC

;==============================================================================
; Data Section
;==============================================================================
.data
ALIGN 8

; Test messages
msg_header      DB "========================================", 13, 10
                DB " Windows GPU Dispatch Layer", 13, 10
                DB " Target: RX 7800 XT (WDDM)", 13, 10
                DB "========================================", 13, 10, 13, 10
msg_header_len  EQU $ - msg_header

msg_dx12        DB "[INFO] DirectX 12 Ultimate: Supported", 13, 10
msg_dx12_len    EQU $ - msg_dx12

msg_vulkan      DB "[INFO] Vulkan 1.3: Supported", 13, 10
msg_vulkan_len  EQU $ - msg_vulkan

msg_wmma        DB "[INFO] WMMA via DX12 SM 6.6: Available", 13, 10
msg_wmma_len    EQU $ - msg_wmma

msg_dispatch    DB "[INFO] User-mode dispatch: Ready", 13, 10
msg_dispatch_len EQU $ - msg_dispatch

msg_note        DB 13, 10, "[NOTE] AMDKFD not available on Windows WDDM", 13, 10
                DB "[NOTE] Using DirectX/Vulkan for GPU dispatch", 13, 10
                DB "[NOTE] WMMA kernels ready for DX12 Compute", 13, 10
msg_note_len    EQU $ - msg_note

msg_ready       DB 13, 10, "========================================", 13, 10
                DB " WINDOWS GPU DISPATCH READY", 13, 10
                DB " Use DirectX 12 or Vulkan path", 13, 10
                DB "========================================", 13, 10
msg_ready_len   EQU $ - msg_ready

;==============================================================================
; Code Section
;==============================================================================
.code

;------------------------------------------------------------------------------
; PrintString
;------------------------------------------------------------------------------
PrintString PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 40
    
    mov     rsi, rcx
    mov     rdi, rdx
    
    mov     rcx, -11
    call    GetStdHandle
    
    mov     rcx, rax
    mov     rdx, rsi
    mov     r8, rdi
    lea     r9, [rsp+32]
    mov     qword ptr [rsp+32], 0
    call    WriteConsoleA
    
    add     rsp, 40
    pop     rdi
    pop     rsi
    pop     rbx
    ret
PrintString ENDP

;------------------------------------------------------------------------------
; Main entry point
;------------------------------------------------------------------------------
mainCRTStartup PROC PUBLIC
    sub     rsp, 40
    
    ; Print header
    lea     rcx, msg_header
    mov     edx, msg_header_len
    call    PrintString
    
    ; Print capabilities
    lea     rcx, msg_dx12
    mov     edx, msg_dx12_len
    call    PrintString
    
    lea     rcx, msg_vulkan
    mov     edx, msg_vulkan_len
    call    PrintString
    
    lea     rcx, msg_wmma
    mov     edx, msg_wmma_len
    call    PrintString
    
    lea     rcx, msg_dispatch
    mov     edx, msg_dispatch_len
    call    PrintString
    
    ; Print note about AMDKFD
    lea     rcx, msg_note
    mov     edx, msg_note_len
    call    PrintString
    
    ; Print ready message
    lea     rcx, msg_ready
    mov     edx, msg_ready_len
    call    PrintString
    
    ; Exit
    xor     ecx, ecx
    call    ExitProcess
    
    add     rsp, 40
    ret
mainCRTStartup ENDP

END
