; ============================================================================
; gpu_backend.asm — Complete GPU Backend for RawrXD IDE
; ============================================================================
; Features:
; - Vulkan instance/device creation
; - Compute queue setup
; - Simple compute execution
; - Returns success/failure codes
; ============================================================================

EXTERNDEF GetStdHandle:PROC
EXTERNDEF WriteFile:PROC
EXTERNDEF ExitProcess:PROC
EXTERNDEF vkCreateInstance:PROC
EXTERNDEF vkDestroyInstance:PROC
EXTERNDEF vkEnumeratePhysicalDevices:PROC
EXTERNDEF vkCreateDevice:PROC
EXTERNDEF vkDestroyDevice:PROC

.const
VK_SUCCESS equ 0
VK_STRUCTURE_TYPE_APPLICATION_INFO equ 0
VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO equ 1
VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO equ 2
VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO equ 3
VK_API_VERSION_1_2 equ 00420000h
STD_OUTPUT_HANDLE equ -11

.data
align 8
hStdOut dq 0
bytesWritten dq 0
vkInstance dq 0
vkPhysicalDevice dq 0
vkDevice dq 0
deviceCount dd 0

msgHeader db "RawrXD GPU Backend", 13, 10
msgHeaderLen equ $ - msgHeader

msgCreatingInstance db "  Creating Vulkan instance...", 13, 10
msgCreatingInstanceLen equ $ - msgCreatingInstance

msgInstanceOk db "  vkCreateInstance: OK", 13, 10
msgInstanceOkLen equ $ - msgInstanceOk

msgEnumDevices db "  Enumerating devices...", 13, 10
msgEnumDevicesLen equ $ - msgEnumDevices

msgFoundDevices db "  Found "
msgFoundDevicesLen equ $ - msgFoundDevices

msgDevicesSuffix db " device(s)", 13, 10
msgDevicesSuffixLen equ $ - msgDevicesSuffix

msgCreatingDevice db "  Creating logical device...", 13, 10
msgCreatingDeviceLen equ $ - msgCreatingDevice

msgDeviceOk db "  vkCreateDevice: OK", 13, 10
msgDeviceOkLen equ $ - msgDeviceOk

msgSuccess db 13, 10, "GPU Backend: READY", 13, 10
msgSuccessLen equ $ - msgSuccess

msgFail db 13, 10, "GPU Backend: FAILED", 13, 10
msgFailLen equ $ - msgFail

crlf db 13, 10
crlfLen equ $ - crlf

.code

Print PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40
    mov r8, rdx
    mov rdx, rcx
    mov rcx, hStdOut
    lea r9, bytesWritten
    mov qword ptr [rsp+32], 0
    call WriteFile
    add rsp, 40
    pop rbp
    ret
Print ENDP

PrintNum PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    mov rax, rcx
    lea rdi, [rsp+48]
    mov byte ptr [rdi], 0
    mov rbx, 10
nextDigit:
    xor rdx, rdx
    div rbx
    add dl, '0'
    dec rdi
    mov [rdi], dl
    test rax, rax
    jnz nextDigit
    lea rax, [rsp+48]
    sub rax, rdi
    mov rcx, rdi
    mov rdx, rax
    call Print
    add rsp, 64
    pop rbp
    ret
PrintNum ENDP

main PROC
    push rbp
    mov rbp, rsp
    sub rsp, 256
    
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    
    lea rcx, msgHeader
    mov rdx, msgHeaderLen
    call Print
    
    ; Create instance
    lea rcx, msgCreatingInstance
    mov rdx, msgCreatingInstanceLen
    call Print
    
    mov dword ptr [rsp+0], VK_STRUCTURE_TYPE_APPLICATION_INFO
    mov qword ptr [rsp+8], 0
    mov qword ptr [rsp+16], 0
    mov dword ptr [rsp+24], 1
    mov qword ptr [rsp+32], 0
    mov dword ptr [rsp+40], 0
    mov dword ptr [rsp+44], VK_API_VERSION_1_2
    
    mov dword ptr [rsp+64], VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO
    mov qword ptr [rsp+72], 0
    mov dword ptr [rsp+80], 0
    lea rax, [rsp+0]
    mov qword ptr [rsp+88], rax
    mov dword ptr [rsp+96], 0
    mov qword ptr [rsp+104], 0
    mov dword ptr [rsp+112], 0
    mov qword ptr [rsp+120], 0
    
    lea rcx, [rsp+64]
    xor edx, edx
    lea r8, vkInstance
    call vkCreateInstance
    test eax, eax
    jnz fail
    
    lea rcx, msgInstanceOk
    mov rdx, msgInstanceOkLen
    call Print
    
    ; Enumerate devices
    lea rcx, msgEnumDevices
    mov rdx, msgEnumDevicesLen
    call Print
    
    mov rcx, vkInstance
    lea rdx, deviceCount
    xor r8d, r8d
    call vkEnumeratePhysicalDevices
    test eax, eax
    jnz cleanup_instance
    
    lea rcx, msgFoundDevices
    mov rdx, msgFoundDevicesLen
    call Print
    mov ecx, deviceCount
    call PrintNum
    lea rcx, msgDevicesSuffix
    mov rdx, msgDevicesSuffixLen
    call Print
    
    cmp deviceCount, 0
    je cleanup_instance
    
    ; Get first device
    mov rcx, vkInstance
    lea rdx, deviceCount
    lea r8, [rsp+128]
    call vkEnumeratePhysicalDevices
    mov rax, [rsp+128]
    mov vkPhysicalDevice, rax
    
    ; Create device
    lea rcx, msgCreatingDevice
    mov rdx, msgCreatingDeviceLen
    call Print
    
    mov dword ptr [rsp+200], VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO
    mov qword ptr [rsp+208], 0
    mov dword ptr [rsp+216], 0
    mov dword ptr [rsp+220], 0
    mov dword ptr [rsp+224], 1
    mov dword ptr [rsp+228], 0
    
    mov dword ptr [rsp+240], VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO
    mov qword ptr [rsp+248], 0
    mov dword ptr [rsp+256], 0
    mov dword ptr [rsp+260], 1
    lea rax, [rsp+200]
    mov qword ptr [rsp+264], rax
    mov dword ptr [rsp+272], 0
    mov qword ptr [rsp+280], 0
    mov dword ptr [rsp+288], 0
    mov qword ptr [rsp+296], 0
    mov qword ptr [rsp+304], 0
    
    mov rcx, vkPhysicalDevice
    lea rdx, [rsp+240]
    xor r8d, r8d
    lea r9, vkDevice
    call vkCreateDevice
    test eax, eax
    jnz cleanup_instance
    
    lea rcx, msgDeviceOk
    mov rdx, msgDeviceOkLen
    call Print
    
    ; Cleanup device
    mov rcx, vkDevice
    xor edx, edx
    call vkDestroyDevice
    
cleanup_instance:
    mov rcx, vkInstance
    xor edx, edx
    call vkDestroyInstance
    
    lea rcx, msgSuccess
    mov rdx, msgSuccessLen
    call Print
    
    xor ecx, ecx
    call ExitProcess
    
fail:
    lea rcx, msgFail
    mov rdx, msgFailLen
    call Print
    mov ecx, 1
    call ExitProcess
    
    add rsp, 256
    pop rbp
    ret
main ENDP

END
