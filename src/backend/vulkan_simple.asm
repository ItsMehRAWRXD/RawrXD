; ============================================================================
; vulkan_simple.asm — Simple Working Vulkan Backend
; ============================================================================
; Creates instance, device, and basic objects, then exits cleanly
; ============================================================================

EXTERNDEF GetStdHandle:PROC
EXTERNDEF WriteFile:PROC
EXTERNDEF ExitProcess:PROC
EXTERNDEF vkCreateInstance:PROC
EXTERNDEF vkDestroyInstance:PROC
EXTERNDEF vkEnumeratePhysicalDevices:PROC
EXTERNDEF vkCreateDevice:PROC
EXTERNDEF vkDestroyDevice:PROC
EXTERNDEF vkGetDeviceQueue:PROC
EXTERNDEF vkCreateCommandPool:PROC
EXTERNDEF vkDestroyCommandPool:PROC

.const
VK_SUCCESS equ 0
VK_STRUCTURE_TYPE_APPLICATION_INFO equ 0
VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO equ 1
VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO equ 2
VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO equ 3
VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO equ 39
VK_API_VERSION_1_2 equ 00420000h
VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT equ 2
STD_OUTPUT_HANDLE equ -11

.data
align 8
hStdOut dq 0
bytesWritten dq 0
vkInstance dq 0
vkPhysicalDevice dq 0
vkDevice dq 0
vkComputeQueue dq 0
vkCommandPool dq 0
deviceCount dd 0

msgInit db "[VULKAN] Initializing...", 13, 10
msgInitLen equ $ - msgInit

msgInstance db "[VULKAN] vkCreateInstance: SUCCESS", 13, 10
msgInstanceLen equ $ - msgInstance

msgDevices db "[VULKAN] Found devices: "
msgDevicesLen equ $ - msgDevices

msgDevice db "[VULKAN] Using device index: 0", 13, 10
msgDeviceLen equ $ - msgDevice

msgDeviceCreated db "[VULKAN] vkCreateDevice: SUCCESS", 13, 10
msgDeviceCreatedLen equ $ - msgDeviceCreated

msgQueue db "[VULKAN] Got compute queue", 13, 10
msgQueueLen equ $ - msgQueue

msgCmdPool db "[VULKAN] Command pool created", 13, 10
msgCmdPoolLen equ $ - msgCmdPool

msgComplete db "[VULKAN] All Vulkan objects created successfully", 13, 10
msgCompleteLen equ $ - msgComplete

msgSuccess db 13, 10, "=== VULKAN BACKEND READY ===", 13, 10
msgSuccessLen equ $ - msgSuccess

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
    
    lea rcx, msgInit
    mov rdx, msgInitLen
    call Print
    
    ; Create instance
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
    
    lea rcx, msgInstance
    mov rdx, msgInstanceLen
    call Print
    
    ; Enumerate devices
    mov rcx, vkInstance
    lea rdx, deviceCount
    xor r8d, r8d
    call vkEnumeratePhysicalDevices
    test eax, eax
    jnz cleanup_instance
    
    lea rcx, msgDevices
    mov rdx, msgDevicesLen
    call Print
    mov ecx, deviceCount
    call PrintNum
    lea rcx, crlf
    mov rdx, crlfLen
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
    
    lea rcx, msgDevice
    mov rdx, msgDeviceLen
    call Print
    
    ; Create device
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
    
    lea rcx, msgDeviceCreated
    mov rdx, msgDeviceCreatedLen
    call Print
    
    ; Get queue
    mov rcx, vkDevice
    xor edx, edx
    xor r8d, r8d
    lea r9, vkComputeQueue
    call vkGetDeviceQueue
    
    lea rcx, msgQueue
    mov rdx, msgQueueLen
    call Print
    
    ; Create command pool
    mov dword ptr [rsp+0], VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO
    mov qword ptr [rsp+8], 0
    mov dword ptr [rsp+16], VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT
    mov dword ptr [rsp+20], 0
    
    mov rcx, vkDevice
    lea rdx, [rsp+0]
    xor r8d, r8d
    lea r9, vkCommandPool
    call vkCreateCommandPool
    test eax, eax
    jnz cleanup_device
    
    lea rcx, msgCmdPool
    mov rdx, msgCmdPoolLen
    call Print
    
    lea rcx, msgComplete
    mov rdx, msgCompleteLen
    call Print
    
    ; Cleanup
    mov rcx, vkDevice
    mov rdx, vkCommandPool
    xor r8d, r8d
    call vkDestroyCommandPool
    
cleanup_device:
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
    mov ecx, 1
    call ExitProcess
    
    add rsp, 256
    pop rbp
    ret
main ENDP

END
