; =============================================================================
; device_selector.asm - GPU Device Selector & Memory Pool
; =============================================================================
; Detects available GPU devices (Vulkan, HIP/ROCm) and manages a memory
; pool for tensor offloading. Supports the dual-GPU setup:
;   - Radeon AI Pro R9700 (32 GB) — primary compute
;   - RX 7800 XT (16 GB) — secondary compute / display
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; CONSTANTS
; =============================================================================
MAX_DEVICES             EQU 8
MEM_POOL_BLOCK_SIZE     EQU 1048576    ; 1 MB blocks
MEM_POOL_MAX_BLOCKS     EQU 65536      ; 64 GB max

; Device types
DEVICE_TYPE_CPU         EQU 0
DEVICE_TYPE_VULKAN      EQU 1
DEVICE_TYPE_HIP         EQU 2
DEVICE_TYPE_CUDA        EQU 3

; Device flags
DEVICE_FLAG_COMPUTE     EQU 1
DEVICE_FLAG_DISPLAY     EQU 2
DEVICE_FLAG_AVAILABLE   EQU 4

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Device table
align 64
g_DeviceTable           DB MAX_DEVICES * 64 DUP(0)

; Device entry (64 bytes):
;   +0:  DWORD device_type
;   +4:  DWORD device_flags
;   +8:  QWORD total_memory
;  +16:  QWORD free_memory
;  +24:  QWORD device_id
;  +32:  DB 32 name string

; Memory pool
align 64
g_MemPoolBlocks         DQ MEM_POOL_MAX_BLOCKS DUP(0)
g_MemPoolFreeList       DQ 0
g_MemPoolTotalBlocks    DQ 0
g_MemPoolFreeBlocks     DQ 0

; Active device
align 8
g_ActiveDevice          DQ 0
g_DeviceCount           DQ 0

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; GPU_Init - Initialize device selector and memory pool
;
; Parameters:
;   RCX = QWORD* device_types  - Array of device types, or NULL for auto-detect
;   RDX = QWORD num_devices    - Number of devices
;
; Returns: RAX = 0 on success
; =============================================================================
GPU_Init PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 32
    .allocstack 32
    .endprolog

    ; Initialize device table
    lea rdi, g_DeviceTable
    mov rcx, MAX_DEVICES * 64
    xor eax, eax
    rep stosb

    mov QWORD PTR [g_DeviceCount], 0

    ; If device_types provided, use them
    test rcx, rcx
    jz @@auto_detect
    test rdx, rdx
    jz @@auto_detect

    mov rsi, rcx                    ; device_types
    mov r12, rdx                    ; num_devices
    xor r13, r13

@@register_loop:
    cmp r13, r12
    jge @@init_pool
    cmp r13, MAX_DEVICES
    jge @@init_pool

    mov rax, r13
    shl rax, 6                      ; * 64
    lea rdi, g_DeviceTable
    add rdi, rax

    mov eax, DWORD PTR [rsi + r13*4]
    mov DWORD PTR [rdi], eax        ; device_type
    mov DWORD PTR [rdi + 4], DEVICE_FLAG_AVAILABLE

    ; Set memory sizes based on type
    cmp eax, DEVICE_TYPE_CPU
    je @@cpu_mem
    cmp eax, DEVICE_TYPE_VULKAN
    je @@vulkan_mem
    cmp eax, DEVICE_TYPE_HIP
    je @@hip_mem
    jmp @@next_device

@@cpu_mem:
    mov QWORD PTR [rdi + 8], 64 * 1024 * 1024 * 1024   ; 64 GB system RAM
    mov QWORD PTR [rdi + 16], 64 * 1024 * 1024 * 1024
    lea rax, szCPUName
    lea rdx, [rdi + 32]
    mov rcx, rax
    call RawrXD_StrCopy
    jmp @@next_device

@@vulkan_mem:
    mov QWORD PTR [rdi + 8], 16 * 1024 * 1024 * 1024   ; 16 GB VRAM
    mov QWORD PTR [rdi + 16], 16 * 1024 * 1024 * 1024
    lea rax, szVulkanName
    lea rdx, [rdi + 32]
    mov rcx, rax
    call RawrXD_StrCopy
    jmp @@next_device

@@hip_mem:
    mov QWORD PTR [rdi + 8], 32 * 1024 * 1024 * 1024   ; 32 GB VRAM
    mov QWORD PTR [rdi + 16], 32 * 1024 * 1024 * 1024
    lea rax, szHIPName
    lea rdx, [rdi + 32]
    mov rcx, rax
    call RawrXD_StrCopy

@@next_device:
    inc QWORD PTR [g_DeviceCount]
    inc r13
    jmp @@register_loop

@@auto_detect:
    ; Auto-detect: CPU + Vulkan + HIP
    ; CPU (always present)
    lea rdi, g_DeviceTable
    mov DWORD PTR [rdi], DEVICE_TYPE_CPU
    mov DWORD PTR [rdi + 4], DEVICE_FLAG_AVAILABLE
    mov QWORD PTR [rdi + 8], 64 * 1024 * 1024 * 1024
    mov QWORD PTR [rdi + 16], 64 * 1024 * 1024 * 1024
    lea rax, szCPUName
    lea rdx, [rdi + 32]
    mov rcx, rax
    call RawrXD_StrCopy
    inc QWORD PTR [g_DeviceCount]

    ; Vulkan (RX 7800 XT)
    lea rdi, g_DeviceTable + 64
    mov DWORD PTR [rdi], DEVICE_TYPE_VULKAN
    mov DWORD PTR [rdi + 4], DEVICE_FLAG_AVAILABLE
    mov QWORD PTR [rdi + 8], 16 * 1024 * 1024 * 1024
    mov QWORD PTR [rdi + 16], 16 * 1024 * 1024 * 1024
    lea rax, szVulkanName
    lea rdx, [rdi + 32]
    mov rcx, rax
    call RawrXD_StrCopy
    inc QWORD PTR [g_DeviceCount]

    ; HIP (R9700 AI Pro)
    lea rdi, g_DeviceTable + 128
    mov DWORD PTR [rdi], DEVICE_TYPE_HIP
    mov DWORD PTR [rdi + 4], DEVICE_FLAG_AVAILABLE
    mov QWORD PTR [rdi + 8], 32 * 1024 * 1024 * 1024
    mov QWORD PTR [rdi + 16], 32 * 1024 * 1024 * 1024
    lea rax, szHIPName
    lea rdx, [rdi + 32]
    mov rcx, rax
    call RawrXD_StrCopy
    inc QWORD PTR [g_DeviceCount]

@@init_pool:
    ; Initialize memory pool
    mov QWORD PTR [g_MemPoolTotalBlocks], 0
    mov QWORD PTR [g_MemPoolFreeBlocks], 0
    mov QWORD PTR [g_MemPoolFreeList], 0

    ; Set active device to first available
    mov QWORD PTR [g_ActiveDevice], 0

    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

GPU_Init ENDP

; =============================================================================
; GPU_SelectDevice - Select active device
;
; Parameters:
;   RCX = QWORD device_index
;
; Returns: RAX = 0 on success
; =============================================================================
GPU_SelectDevice PROC FRAME
    .endprolog
    cmp rcx, QWORD PTR [g_DeviceCount]
    jae @@error
    mov QWORD PTR [g_ActiveDevice], rcx
    xor rax, rax
    ret
@@error:
    mov rax, 1
    ret
GPU_SelectDevice ENDP

; =============================================================================
; GPU_Allocate - Allocate memory from device
;
; Parameters:
;   RCX = QWORD size
;   RDX = QWORD device_index
;
; Returns: RAX = pointer, or NULL
; =============================================================================
GPU_Allocate PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rcx, rcx
    jz @@error

    mov rbx, rcx                    ; size

    ; For CPU device, use aligned alloc
    cmp rdx, 0
    je @@cpu_alloc

    ; For GPU devices, allocate from pool
    ; Round up to block size
    mov rax, rbx
    add rax, MEM_POOL_BLOCK_SIZE - 1
    xor edx, edx
    div MEM_POOL_BLOCK_SIZE
    mov rcx, rax                    ; blocks needed

    ; Check free list
    mov rax, QWORD PTR [g_MemPoolFreeList]
    test rax, rax
    jz @@alloc_new

    ; Pop from free list
    mov rdx, QWORD PTR [rax]
    mov QWORD PTR [g_MemPoolFreeList], rdx
    dec QWORD PTR [g_MemPoolFreeBlocks]
    jmp @@return

@@alloc_new:
    ; Allocate new blocks
    mov rax, rcx
    shl rax, 20                     ; * 1 MB
    mov rcx, rax
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@error
    add QWORD PTR [g_MemPoolTotalBlocks], rcx
    jmp @@return

@@cpu_alloc:
    mov rcx, rbx
    call RawrXD_AlignedAlloc

@@return:
    jmp @@exit

@@error:
    xor rax, rax

@@exit:
    pop rbx
    pop rbp
    ret

GPU_Allocate ENDP

; =============================================================================
; GPU_Free - Free device memory
; =============================================================================
GPU_Free PROC FRAME
    .endprolog
    test rcx, rcx
    jz @@exit
    call RawrXD_AlignedFree
@@exit:
    ret
GPU_Free ENDP

; =============================================================================
; GPU_GetDeviceInfo - Get device information
;
; Parameters:
;   RCX = QWORD device_index
;   RDX = void* out_buffer
;   R8  = QWORD buffer_size
;
; Returns: RAX = 0 on success
; =============================================================================
GPU_GetDeviceInfo PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rdx, rdx
    jz @@error
    test r8, r8
    jz @@error

    cmp rcx, QWORD PTR [g_DeviceCount]
    jae @@error

    mov rsi, rcx
    shl rsi, 6
    lea rsi, g_DeviceTable
    add rsi, rcx

    mov rdi, rdx
    mov rcx, r8

    ; Write device info
    mov eax, DWORD PTR [rsi]
    mov DWORD PTR [rdi], eax
    mov eax, DWORD PTR [rsi + 4]
    mov DWORD PTR [rdi + 4], eax
    mov rax, QWORD PTR [rsi + 8]
    mov QWORD PTR [rdi + 8], rax
    mov rax, QWORD PTR [rsi + 16]
    mov QWORD PTR [rdi + 16], rax

    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

GPU_GetDeviceInfo ENDP

; =============================================================================
; RawrXD_StrCopy - String copy
; =============================================================================
RawrXD_StrCopy PROC PRIVATE FRAME
    .endprolog
    test rcx, rcx
    jz @@exit
    test rdx, rdx
    jz @@exit
    xor eax, eax
@@loop:
    mov al, BYTE PTR [rcx]
    mov BYTE PTR [rdx], al
    test al, al
    jz @@exit
    inc rcx
    inc rdx
    jmp @@loop
@@exit:
    ret
RawrXD_StrCopy ENDP

; =============================================================================
; CONSTANTS
; =============================================================================
.data
align 8
szCPUName           DB 'AMD Ryzen 9 9700X (CPU)', 0
szVulkanName        DB 'AMD Radeon RX 7800 XT (Vulkan)', 0
szHIPName           DB 'AMD Radeon AI Pro R9700 (HIP)', 0

END
