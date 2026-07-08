; ============================================================================
; vulkan_test.asm — Minimal Vulkan Test in x64 MASM
; ============================================================================
; Assemble: ml64.exe /c /W3 /nologo /Fo vulkan_test.obj vulkan_test.asm
; Link: link.exe /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:vulkan_test.exe vulkan_test.obj kernel32.lib vulkan-1.lib
; ============================================================================

EXTERNDEF GetStdHandle:PROC
EXTERNDEF WriteFile:PROC
EXTERNDEF ExitProcess:PROC
EXTERNDEF vkCreateInstance:PROC
EXTERNDEF vkEnumeratePhysicalDevices:PROC
EXTERNDEF vkDestroyInstance:PROC

.const
VK_SUCCESS equ 0
VK_STRUCTURE_TYPE_APPLICATION_INFO equ 0
VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO equ 1
VK_API_VERSION_1_2 equ 00420000h
STD_OUTPUT_HANDLE equ -11

.data
align 8
vkInstance dq 0
deviceCount dd 0
hStdOut dq 0
bytesWritten dq 0

msgInit db "[VULKAN] Initializing...", 13, 10
msgInitLen equ $ - msgInit

msgInstance db "[VULKAN] vkCreateInstance: SUCCESS", 13, 10
msgInstanceLen equ $ - msgInstance

msgDevices db "[VULKAN] Found devices: "
msgDevicesLen equ $ - msgDevices

msgComplete db "[VULKAN] Initialization complete", 13, 10
msgCompleteLen equ $ - msgComplete

msgSuccess db 13, 10, "=== VULKAN TEST PASSED ===", 13, 10
msgSuccessLen equ $ - msgSuccess

msgFail db 13, 10, "=== VULKAN TEST FAILED ===", 13, 10
msgFailLen equ $ - msgFail

crlf db 13, 10
crlfLen equ $ - crlf

; Application info structure
appInfo_sType dd 0
appInfo_pNext dq 0
appInfo_pApplicationName dq 0
appInfo_applicationVersion dd 0
appInfo_pEngineName dq 0
appInfo_engineVersion dd 0
appInfo_apiVersion dd 0

; Instance create info structure
instanceCreate_sType dd 0
instanceCreate_pNext dq 0
instanceCreate_flags dd 0
instanceCreate_pApplicationInfo dq 0
instanceCreate_enabledLayerCount dd 0
instanceCreate_ppEnabledLayerNames dq 0
instanceCreate_enabledExtensionCount dd 0
instanceCreate_ppEnabledExtensionNames dq 0

.code

; Print string to stdout
; RCX = string address, RDX = length
PrintString PROC
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
PrintString ENDP

; Print number as ASCII
; RCX = number
PrintNumber PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    mov rax, rcx
    lea rdi, [rsp+48]
    mov byte ptr [rdi], 0
    mov rbx, 10
convertLoop:
    xor rdx, rdx
    div rbx
    add dl, '0'
    dec rdi
    mov [rdi], dl
    test rax, rax
    jnz convertLoop
    lea rax, [rsp+48]
    sub rax, rdi
    mov rcx, rdi
    mov rdx, rax
    call PrintString
    add rsp, 64
    pop rbp
    ret
PrintNumber ENDP

; Initialize Vulkan
InitVulkan PROC
    push rbp
    mov rbp, rsp
    sub rsp, 256
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    lea rcx, msgInit
    mov rdx, msgInitLen
    call PrintString
    mov appInfo_sType, VK_STRUCTURE_TYPE_APPLICATION_INFO
    mov appInfo_apiVersion, 00420000h
    mov instanceCreate_sType, VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO
    lea rax, appInfo_sType
    mov instanceCreate_pApplicationInfo, rax
    lea rcx, instanceCreate_sType
    xor edx, edx
    lea r8, vkInstance
    call vkCreateInstance
    test eax, eax
    jnz initFail
    lea rcx, msgInstance
    mov rdx, msgInstanceLen
    call PrintString
    mov rcx, vkInstance
    lea rdx, deviceCount
    xor r8d, r8d
    call vkEnumeratePhysicalDevices
    test eax, eax
    jnz initFail
    lea rcx, msgDevices
    mov rdx, msgDevicesLen
    call PrintString
    mov ecx, deviceCount
    call PrintNumber
    lea rcx, crlf
    mov rdx, crlfLen
    call PrintString
    cmp deviceCount, 0
    je initFail
    lea rcx, msgComplete
    mov rdx, msgCompleteLen
    call PrintString
    mov rax, 1
    jmp initDone
initFail:
    xor rax, rax
initDone:
    add rsp, 256
    pop rbp
    ret
InitVulkan ENDP

; Cleanup Vulkan
CleanupVulkan PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    mov rcx, vkInstance
    xor edx, edx
    call vkDestroyInstance
    add rsp, 32
    pop rbp
    ret
CleanupVulkan ENDP

; Main entry point
main PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    call InitVulkan
    test rax, rax
    jz mainFail
    call CleanupVulkan
    lea rcx, msgSuccess
    mov rdx, msgSuccessLen
    call PrintString
    xor ecx, ecx
    call ExitProcess
mainFail:
    lea rcx, msgFail
    mov rdx, msgFailLen
    call PrintString
    mov ecx, 1
    call ExitProcess
    add rsp, 64
    pop rbp
    ret
main ENDP

END
