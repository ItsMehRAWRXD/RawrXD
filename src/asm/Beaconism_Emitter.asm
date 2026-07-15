; Beaconism_Emitter.asm - MASM implementation of Beaconism signaling
; Assemble: ml64 /c Beaconism_Emitter.asm
; Link with: link /subsystem:console Beaconism_Emitter.obj

include \masm64\macros\macros.asm

; External Windows API functions
extern CreateFileMappingW:proc
extern OpenFileMappingW:proc
extern MapViewOfFile:proc
extern UnmapViewOfFile:proc
extern CloseHandle:proc
extern GetLastError:proc
extern GetTickCount64:proc
extern RtlGetCurrentPeb:proc

; Constants
FILE_MAP_ALL_ACCESS equ 0xF001F
PAGE_READWRITE equ 0x04
INVALID_HANDLE_VALUE equ -1
ERROR_ALREADY_EXISTS equ 183

; Beaconism shared memory layout
BEACONISM_MAX_BEACONS equ 1024
SIZEOF_BEACON equ 16  ; 4 + 8 + 4 bytes

; Beacon IDs (must match C++ enum)
BEACON_KV_START equ 0x100
BEACON_KV_DONE equ 0x101
BEACON_EXPERT_START equ 0x200
BEACON_EXPERT_DONE equ 0x201
BEACON_ATTENTION_START equ 0x300
BEACON_ATTENTION_DONE equ 0x301
BEACON_MOE_START equ 0x400
BEACON_MOE_DONE equ 0x401
BEACON_NVME_START equ 0x500
BEACON_NVME_DONE equ 0x501
BEACON_VULKAN_START equ 0x600
BEACON_VULKAN_DONE equ 0x601
BEACON_QUANT_START equ 0x700
BEACON_QUANT_DONE equ 0x701
BEACON_MODEL_START equ 0x800
BEACON_MODEL_DONE equ 0x801
BEACON_REPLAY_START equ 0x900
BEACON_REPLAY_DONE equ 0x901
BEACON_TELEMETRY_START equ 0xA00
BEACON_TELEMETRY_DONE equ 0xA01
BEACON_BEACONISM_TEST equ 0xFF00

; .data section
.data
align 8

; Shared memory handle and pointer
g_hMMF dq 0
g_pShared dq 0
g_initialized db 0

; MMF name (wide string)
g_mmfName dw 'R','a','w','r','X','D','_','B','e','a','c','o','n','i','s','m','_','v','1',0

; .code section
.code

;--------------------------------------------------------
; Beaconism_Init - Initialize shared memory
; Returns: rax = 1 (success), 0 (failure)
;--------------------------------------------------------
Beaconism_Init proc
    push rbx
    push rsi
    push rdi
    
    ; Check if already initialized
    cmp g_initialized, 1
    je init_success
    
    ; Try to create file mapping
    xor ecx, ecx                    ; lpSecurityAttributes = NULL
    mov edx, PAGE_READWRITE         ; flProtect
    xor r8d, r8d                    ; dwMaximumSizeHigh
    mov r9d, 4096 + (BEACONISM_MAX_BEACONS * SIZEOF_BEACON)  ; dwMaximumSizeLow
    sub rsp, 40
    lea rax, g_mmfName
    mov qword ptr [rsp+32], rax     ; lpName
    call CreateFileMappingW
    add rsp, 40
    
    mov g_hMMF, rax
    
    ; Check if creation succeeded
    test rax, rax
    jnz create_succeeded
    
    ; Try to open existing
    mov ecx, FILE_MAP_ALL_ACCESS    ; dwDesiredAccess
    xor edx, edx                    ; bInheritHandle = FALSE
    lea r8, g_mmfName               ; lpName
    sub rsp, 40
    call OpenFileMappingW
    add rsp, 40
    
    mov g_hMMF, rax
    test rax, rax
    jz init_failed
    
create_succeeded:
    ; Map view of file
    mov rcx, g_hMMF                 ; hFileMappingObject
    mov edx, FILE_MAP_ALL_ACCESS    ; dwDesiredAccess
    xor r8d, r8d                    ; dwFileOffsetHigh
    xor r9d, r9d                    ; dwFileOffsetLow
    sub rsp, 40
    mov qword ptr [rsp+32], 0       ; dwNumberOfBytesToMap (0 = all)
    call MapViewOfFile
    add rsp, 40
    
    mov g_pShared, rax
    test rax, rax
    jz init_failed
    
    ; Initialize if first (check GetLastError)
    sub rsp, 40
    call GetLastError
    add rsp, 40
    
    cmp eax, ERROR_ALREADY_EXISTS
    je already_exists
    
    ; First creator - initialize structure
    mov rax, g_pShared
    mov dword ptr [rax], 0          ; writeIndex = 0
    mov dword ptr [rax+4], 0          ; readIndex = 0
    
already_exists:
    mov g_initialized, 1
    
init_success:
    mov rax, 1
    jmp init_done
    
init_failed:
    xor rax, rax
    
init_done:
    pop rdi
    pop rsi
    pop rbx
    ret
Beaconism_Init endp

;--------------------------------------------------------
; Beaconism_Shutdown - Cleanup
;--------------------------------------------------------
Beaconism_Shutdown proc
    push rbx
    
    cmp g_initialized, 0
    je shutdown_done
    
    ; Unmap view
    mov rcx, g_pShared
    test rcx, rcx
    jz skip_unmap
    sub rsp, 40
    call UnmapViewOfFile
    add rsp, 40
    mov g_pShared, 0
    
skip_unmap:
    ; Close handle
    mov rcx, g_hMMF
    test rcx, rcx
    jz skip_close
    sub rsp, 40
    call CloseHandle
    add rsp, 40
    mov g_hMMF, 0
    
skip_close:
    mov g_initialized, 0
    
shutdown_done:
    pop rbx
    ret
Beaconism_Shutdown endp

;--------------------------------------------------------
; Beaconism_Emit - Emit a beacon
; rcx = BeaconID (uint32_t)
; rdx = payload (uint32_t)
;--------------------------------------------------------
Beaconism_Emit proc
    push rbx
    push rsi
    push rdi
    
    ; Check initialized
    cmp g_initialized, 0
    je emit_done
    
    mov rbx, rcx                    ; Save BeaconID
    mov rsi, rdx                    ; Save payload
    
    ; Get shared memory pointer
    mov rdi, g_pShared
    test rdi, rdi
    jz emit_done
    
    ; Get current write index
    mov eax, dword ptr [rdi]
    
    ; Increment (atomic)
    lock inc dword ptr [rdi]
    
    ; Calculate index (wrap around)
    and eax, (BEACONISM_MAX_BEACONS - 1)
    
    ; Calculate beacon address
    ; Skip writeIndex (4 bytes) + readIndex (4 bytes) = 8 bytes
    ; Then beacons array
    mov rcx, rax
    imul rcx, SIZEOF_BEACON
    add rcx, 8                      ; Skip header
    add rcx, rdi                    ; Add base address
    
    ; Fill beacon
    mov dword ptr [rcx], ebx        ; id
    
    ; Get timestamp (RDTSC)
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov qword ptr [rcx+4], rax      ; timestamp
    
    mov dword ptr [rcx+12], esi     ; payload
    
    ; Memory barrier
    sfence
    
emit_done:
    pop rdi
    pop rsi
    pop rbx
    ret
Beaconism_Emit endp

;--------------------------------------------------------
; Beaconism_Test - Simple test function
;--------------------------------------------------------
Beaconism_Test proc
    push rbx
    
    ; Initialize
    call Beaconism_Init
    test rax, rax
    jz test_failed
    
    ; Emit test beacons
    mov rcx, BEACON_KV_START
    xor rdx, rdx
    call Beaconism_Emit
    
    mov rcx, BEACON_KV_DONE
    mov rdx, 1234
    call Beaconism_Emit
    
    mov rcx, BEACON_EXPERT_START
    xor rdx, rdx
    call Beaconism_Emit
    
    mov rcx, BEACON_EXPERT_DONE
    mov rdx, 5678
    call Beaconism_Emit
    
    ; Success
    mov rax, 1
    jmp test_done
    
test_failed:
    xor rax, rax
    
test_done:
    pop rbx
    ret
Beaconism_Test endp

;--------------------------------------------------------
; DllMain - Entry point
;--------------------------------------------------------
DllMain proc
    mov rax, 1                      ; Always succeed
    ret
DllMain endp

end
