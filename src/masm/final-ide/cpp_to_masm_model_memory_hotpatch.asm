; model_memory_hotpatch_masm.asm
; Pure MASM x64 - Model Memory Hotpatch (converted from C++ ModelMemoryHotpatch class)
; Live RAM model patching with cross-platform memory protection

option casemap:none

EXTERN malloc:PROC
EXTERN free:PROC
EXTERN memset:PROC
EXTERN memcpy:PROC
EXTERN strlen:PROC
EXTERN strcpy:PROC
EXTERN sprintf:PROC
EXTERN console_log:PROC
EXTERN VirtualProtect:PROC
EXTERN GetSystemTimeAsFileTime:PROC

; Hotpatch constants
MAX_PATCHES EQU 100
MAX_MEMORY_REGIONS EQU 50
PATCH_BUFFER_SIZE EQU 1048576       ; 1 MB

; ============================================================================
; DATA STRUCTURES
; ============================================================================

; PATCH_RESULT - Patch operation result
PATCH_RESULT STRUCT
    success BYTE ?                  ; True if successful
    detail QWORD ?                  ; Result detail
    errorCode DWORD ?               ; Error code
    elapsedMs QWORD ?               ; Execution time
ENDS

; MEMORY_PATCH - Memory patch definition
MEMORY_PATCH STRUCT
    name QWORD ?                    ; Patch name
    description QWORD ?             ; Patch description
    type DWORD ?                    ; Patch type enum
    address QWORD ?                 ; Memory address
    size QWORD ?                    ; Patch size
    originalData QWORD ?            ; Original data buffer
    patchData QWORD ?               ; Patch data buffer
    enabled BYTE ?                  ; Whether patch is enabled
    applied BYTE ?                  ; Whether patch is applied
    timesApplied DWORD ?            ; Number of times applied
ENDS

; MEMORY_REGION - Memory region information
MEMORY_REGION STRUCT
    baseAddress QWORD ?             ; Base address
    size QWORD ?                    ; Region size
    protection DWORD ?              ; Current protection
    originalProtection DWORD ?      ; Original protection
    description QWORD ?             ; Region description
ENDS

; MODEL_MEMORY_HOTPATCH - Hotpatch state
MODEL_MEMORY_HOTPATCH STRUCT
    patches QWORD ?                 ; Array of MEMORY_PATCH
    patchCount DWORD ?              ; Current patch count
    maxPatches DWORD ?              ; Capacity
    
    regions QWORD ?                 ; Array of MEMORY_REGION
    regionCount DWORD ?             ; Current region count
    maxRegions DWORD ?              ; Capacity
    
    modelPtr QWORD ?                ; Model pointer
    modelSize QWORD ?               ; Model size
    
    ; Statistics
    totalPatchesApplied QWORD ?
    totalBytesPatched QWORD ?
    totalErrors DWORD ?
    
    ; Callbacks
    patchAppliedCallback QWORD ?    ; Called when patch applied
    errorOccurredCallback QWORD ?   ; Called on error
    
    initialized BYTE ?
ENDS

; ============================================================================
; GLOBAL DATA
; ============================================================================

.data
    szHotpatchCreated DB "[MEMORY_HOTPATCH] Created for model: %llx (%lld bytes)", 0
    szPatchApplied DB "[MEMORY_HOTPATCH] Patch applied: %s (%lld bytes)", 0
    szPatchFailed DB "[MEMORY_HOTPATCH] Patch failed: %s (error=%d)", 0
    szMemoryProtected DB "[MEMORY_HOTPATCH] Memory protected: %llx-%llx", 0
    szMemoryUnprotected DB "[MEMORY_HOTPATCH] Memory unprotected: %llx-%llx", 0
    szRegionAdded DB "[MEMORY_HOTPATCH] Region added: %s (%lld bytes)", 0

; Patch types
PATCH_TYPE_WEIGHT_MODIFICATION EQU 0
PATCH_TYPE_QUANTIZATION_CHANGE EQU 1
PATCH_TYPE_LAYER_BYPASS EQU 2
PATCH_TYPE_ATTENTION_SCALE EQU 3
PATCH_TYPE_BIAS_ADJUSTMENT EQU 4
PATCH_TYPE_GRAPH_REDIRECTION EQU 5
PATCH_TYPE_VOCABULARY_PATCH EQU 6
PATCH_TYPE_CUSTOM EQU 7

; Memory protection constants
PROTECTION_READ_ONLY EQU 0x02       ; PAGE_READONLY
PROTECTION_READ_WRITE EQU 0x04      ; PAGE_READWRITE

.code

; ============================================================================
; PUBLIC API
; ============================================================================

; model_memory_hotpatch_create(RCX = modelPtr, RDX = modelSize)
; Create memory hotpatch
; Returns: RAX = pointer to MODEL_MEMORY_HOTPATCH
PUBLIC model_memory_hotpatch_create
model_memory_hotpatch_create PROC
    push rbx
    
    mov rbx, rcx                    ; rbx = modelPtr
    mov r9, rdx                     ; r9 = modelSize
    
    ; Allocate hotpatch
    mov rcx, SIZEOF MODEL_MEMORY_HOTPATCH
    call malloc
    mov r10, rax
    
    ; Allocate patches array
    mov rcx, MAX_PATCHES
    imul rcx, SIZEOF MEMORY_PATCH
    call malloc
    mov [r10 + MODEL_MEMORY_HOTPATCH.patches], rax
    
    ; Allocate regions array
    mov rcx, MAX_MEMORY_REGIONS
    imul rcx, SIZEOF MEMORY_REGION
    call malloc
    mov [r10 + MODEL_MEMORY_HOTPATCH.regions], rax
    
    ; Initialize
    mov [r10 + MODEL_MEMORY_HOTPATCH.modelPtr], rbx
    mov [r10 + MODEL_MEMORY_HOTPATCH.modelSize], r9
    mov [r10 + MODEL_MEMORY_HOTPATCH.patchCount], 0
    mov [r10 + MODEL_MEMORY_HOTPATCH.maxPatches], MAX_PATCHES
    mov [r10 + MODEL_MEMORY_HOTPATCH.regionCount], 0
    mov [r10 + MODEL_MEMORY_HOTPATCH.maxRegions], MAX_MEMORY_REGIONS
    mov [r10 + MODEL_MEMORY_HOTPATCH.totalPatchesApplied], 0
    mov [r10 + MODEL_MEMORY_HOTPATCH.totalBytesPatched], 0
    mov [r10 + MODEL_MEMORY_HOTPATCH.totalErrors], 0
    
    mov byte [r10 + MODEL_MEMORY_HOTPATCH.initialized], 1
    
    ; Log
    lea rcx, [szHotpatchCreated]
    mov rdx, rbx
    mov r8, r9
    call console_log
    
    mov rax, r10
    pop rbx
    ret
model_memory_hotpatch_create ENDP

; ============================================================================

; memory_hotpatch_apply_patch(RCX = hotpatch, RDX = patch)
; Apply memory patch
; Returns: RAX = pointer to PATCH_RESULT
PUBLIC memory_hotpatch_apply_patch
memory_hotpatch_apply_patch PROC
    push rbx
    push rsi
    
    mov rbx, rcx                    ; rbx = hotpatch
    mov rsi, rdx                    ; rsi = patch
    
    ; Check if patch enabled
    cmp byte [rsi + MEMORY_PATCH.enabled], 1
    jne .patch_disabled
    
    ; Get start time
    call GetSystemTimeAsFileTime
    mov r8, rax                     ; r8 = start time
    
    ; Allocate result
    mov rcx, SIZEOF PATCH_RESULT
    call malloc
    mov r9, rax                     ; r9 = result
    
    ; Change memory protection to writable
    mov rcx, [rsi + MEMORY_PATCH.address]
    mov rdx, [rsi + MEMORY_PATCH.size]
    mov r10d, PROTECTION_READ_WRITE
    mov r11, 0                      ; lpflOldProtect
    call VirtualProtect
    
    test rax, rax
    jz .protection_failed
    
    ; Log protection change
    lea rcx, [szMemoryUnprotected]
    mov rdx, [rsi + MEMORY_PATCH.address]
    mov r8, [rsi + MEMORY_PATCH.address]
    add r8, [rsi + MEMORY_PATCH.size]
    call console_log
    
    ; Apply patch
    mov rcx, [rsi + MEMORY_PATCH.address]
    mov rdx, [rsi + MEMORY_PATCH.patchData]
    mov r8, [rsi + MEMORY_PATCH.size]
    call memcpy
    
    ; Restore original protection
    mov rcx, [rsi + MEMORY_PATCH.address]
    mov rdx, [rsi + MEMORY_PATCH.size]
    mov r10d, PROTECTION_READ_ONLY
    mov r11, 0
    call VirtualProtect
    
    test rax, rax
    jz .restore_failed
    
    ; Log protection restore
    lea rcx, [szMemoryProtected]
    mov rdx, [rsi + MEMORY_PATCH.address]
    mov r8, [rsi + MEMORY_PATCH.address]
    add r8, [rsi + MEMORY_PATCH.size]
    call console_log
    
    ; Get end time
    call GetSystemTimeAsFileTime
    sub rax, r8                     ; rax = elapsed time
    mov [r9 + PATCH_RESULT.elapsedMs], rax
    
    ; Set result
    mov byte [r9 + PATCH_RESULT.success], 1
    lea rax, [szPatchAppliedDetail]
    mov [r9 + PATCH_RESULT.detail], rax
    mov [r9 + PATCH_RESULT.errorCode], 0
    
    ; Update patch status
    mov byte [rsi + MEMORY_PATCH.applied], 1
    inc dword [rsi + MEMORY_PATCH.timesApplied]
    
    ; Update statistics
    inc qword [rbx + MODEL_MEMORY_HOTPATCH.totalPatchesApplied]
    mov rax, [rsi + MEMORY_PATCH.size]
    add [rbx + MODEL_MEMORY_HOTPATCH.totalBytesPatched], rax
    
    ; Log success
    lea rcx, [szPatchApplied]
    mov rdx, [rsi + MEMORY_PATCH.name]
    mov r8, [rsi + MEMORY_PATCH.size]
    call console_log
    
    mov rax, r9                     ; Return result
    pop rsi
    pop rbx
    ret
    
.protection_failed:
.restore_failed:
.patch_disabled:
    ; Set error result
    mov byte [r9 + PATCH_RESULT.success], 0
    lea rax, [szPatchFailedDetail]
    mov [r9 + PATCH_RESULT.detail], rax
    mov [r9 + PATCH_RESULT.errorCode], 1
    
    ; Log failure
    lea rcx, [szPatchFailed]
    mov rdx, [rsi + MEMORY_PATCH.name]
    mov r8d, 1
    call console_log
    
    inc dword [rbx + MODEL_MEMORY_HOTPATCH.totalErrors]
    
    mov rax, r9
    pop rsi
    pop rbx
    ret
memory_hotpatch_apply_patch ENDP

; ============================================================================

; memory_hotpatch_add_patch(RCX = hotpatch, RDX = name, R8 = description, R9d = type)
; Add memory patch
; Returns: RAX = patch ID (0 on error)
PUBLIC memory_hotpatch_add_patch
memory_hotpatch_add_patch PROC
    push rbx
    push rsi
    
    mov rbx, rcx                    ; rbx = hotpatch
    mov rsi, rdx                    ; rsi = name
    mov r10, r8                     ; r10 = description
    mov r11d, r9d                   ; r11d = type
    
    ; Check capacity
    mov r12d, [rbx + MODEL_MEMORY_HOTPATCH.patchCount]
    cmp r12d, [rbx + MODEL_MEMORY_HOTPATCH.maxPatches]
    jge .capacity_exceeded
    
    ; Get patch slot
    mov r13, [rbx + MODEL_MEMORY_HOTPATCH.patches]
    mov r14, r12
    imul r14, SIZEOF MEMORY_PATCH
    add r13, r14
    
    ; Store patch name
    mov rcx, rsi
    call strlen
    inc rax
    call malloc
    mov [r13 + MEMORY_PATCH.name], rax
    
    mov rcx, rsi
    mov rdx, rax
    call strcpy
    
    ; Store patch description
    mov rcx, r10
    call strlen
    inc rax
    call malloc
    mov [r13 + MEMORY_PATCH.description], rax
    
    mov rcx, r10
    mov rdx, rax
    call strcpy
    
    ; Set patch properties
    mov [r13 + MEMORY_PATCH.type], r11d
    mov byte [r13 + MEMORY_PATCH.enabled], 1
    mov byte [r13 + MEMORY_PATCH.applied], 0
    mov [r13 + MEMORY_PATCH.timesApplied], 0
    
    ; Set default address and size
    mov rax, [rbx + MODEL_MEMORY_HOTPATCH.modelPtr]
    mov [r13 + MEMORY_PATCH.address], rax
    mov [r13 + MEMORY_PATCH.size], 1024
    
    ; Allocate patch data buffer
    mov rcx, 1024
    call malloc
    mov [r13 + MEMORY_PATCH.patchData], rax
    
    ; Allocate original data buffer
    mov rcx, 1024
    call malloc
    mov [r13 + MEMORY_PATCH.originalData], rax
    
    ; Increment patch count
    inc dword [rbx + MODEL_MEMORY_HOTPATCH.patchCount]
    
    mov eax, r12d                   ; Return patch ID
    pop rsi
    pop rbx
    ret
    
.capacity_exceeded:
    xor rax, rax
    pop rsi
    pop rbx
    ret
memory_hotpatch_add_patch ENDP

; ============================================================================

; memory_hotpatch_add_region(RCX = hotpatch, RDX = baseAddress, R8 = size, R9 = description)
; Add memory region
; Returns: RAX = region ID (0 on error)
PUBLIC memory_hotpatch_add_region
memory_hotpatch_add_region PROC
    push rbx
    push rsi
    
    mov rbx, rcx                    ; rbx = hotpatch
    mov rsi, rdx                    ; rsi = baseAddress
    mov r10, r8                     ; r10 = size
    mov r11, r9                     ; r11 = description
    
    ; Check capacity
    mov r12d, [rbx + MODEL_MEMORY_HOTPATCH.regionCount]
    cmp r12d, [rbx + MODEL_MEMORY_HOTPATCH.maxRegions]
    jge .capacity_exceeded
    
    ; Get region slot
    mov r13, [rbx + MODEL_MEMORY_HOTPATCH.regions]
    mov r14, r12
    imul r14, SIZEOF MEMORY_REGION
    add r13, r14
    
    ; Store region properties
    mov [r13 + MEMORY_REGION.baseAddress], rsi
    mov [r13 + MEMORY_REGION.size], r10
    mov [r13 + MEMORY_REGION.protection], PROTECTION_READ_ONLY
    mov [r13 + MEMORY_REGION.originalProtection], PROTECTION_READ_ONLY
    
    ; Store description
    mov rcx, r11
    call strlen
    inc rax
    call malloc
    mov [r13 + MEMORY_REGION.description], rax
    
    mov rcx, r11
    mov rdx, rax
    call strcpy
    
    ; Increment region count
    inc dword [rbx + MODEL_MEMORY_HOTPATCH.regionCount]
    
    ; Log
    lea rcx, [szRegionAdded]
    mov rdx, r11
    mov r8, r10
    call console_log
    
    mov eax, r12d                   ; Return region ID
    pop rsi
    pop rbx
    ret
    
.capacity_exceeded:
    xor rax, rax
    pop rsi
    pop rbx
    ret
memory_hotpatch_add_region ENDP

; ============================================================================

; memory_hotpatch_get_patch(RCX = hotpatch, RDX = patchId)
; Get patch by ID
; Returns: RAX = pointer to MEMORY_PATCH
PUBLIC memory_hotpatch_get_patch
memory_hotpatch_get_patch PROC
    mov r8, [rcx + MODEL_MEMORY_HOTPATCH.patches]
    mov r9d, [rcx + MODEL_MEMORY_HOTPATCH.patchCount]
    xor r10d, r10d
    
.find_patch:
    cmp r10d, r9d
    jge .patch_not_found
    
    mov r11, r8
    mov r12, r10
    imul r12, SIZEOF MEMORY_PATCH
    add r11, r12
    
    cmp r10d, edx
    je .patch_found
    
    inc r10d
    jmp .find_patch
    
.patch_found:
    mov rax, r11
    ret
    
.patch_not_found:
    xor rax, rax
    ret
memory_hotpatch_get_patch ENDP

; ============================================================================

; memory_hotpatch_get_region(RCX = hotpatch, RDX = regionId)
; Get region by ID
; Returns: RAX = pointer to MEMORY_REGION
PUBLIC memory_hotpatch_get_region
memory_hotpatch_get_region PROC
    mov r8, [rcx + MODEL_MEMORY_HOTPATCH.regions]
    mov r9d, [rcx + MODEL_MEMORY_HOTPATCH.regionCount]
    xor r10d, r10d
    
.find_region:
    cmp r10d, r9d
    jge .region_not_found
    
    mov r11, r8
    mov r12, r10
    imul r12, SIZEOF MEMORY_REGION
    add r11, r12
    
    cmp r10d, edx
    je .region_found
    
    inc r10d
    jmp .find_region
    
.region_found:
    mov rax, r11
    ret
    
.region_not_found:
    xor rax, rax
    ret
memory_hotpatch_get_region ENDP

; ============================================================================

; memory_hotpatch_get_statistics(RCX = hotpatch, RDX = statsBuffer)
; Get hotpatch statistics
PUBLIC memory_hotpatch_get_statistics
memory_hotpatch_get_statistics PROC
    mov [rdx + 0], qword [rcx + MODEL_MEMORY_HOTPATCH.totalPatchesApplied]
    mov [rdx + 8], qword [rcx + MODEL_MEMORY_HOTPATCH.totalBytesPatched]
    mov [rdx + 16], dword [rcx + MODEL_MEMORY_HOTPATCH.totalErrors]
    ret
memory_hotpatch_get_statistics ENDP

; ============================================================================

; memory_hotpatch_destroy(RCX = hotpatch)
; Free memory hotpatch
PUBLIC memory_hotpatch_destroy
memory_hotpatch_destroy PROC
    push rbx
    
    mov rbx, rcx
    
    ; Free patches array
    mov r10, [rbx + MODEL_MEMORY_HOTPATCH.patches]
    mov r11d, [rbx + MODEL_MEMORY_HOTPATCH.patchCount]
    xor r12d, r12d
    
.free_patches:
    cmp r12d, r11d
    jge .patches_freed
    
    mov r13, r10
    mov r14, r12
    imul r14, SIZEOF MEMORY_PATCH
    add r13, r14
    
    mov rcx, [r13 + MEMORY_PATCH.name]
    cmp rcx, 0
    je .skip_patch_name
    call free
    
.skip_patch_name:
    mov rcx, [r13 + MEMORY_PATCH.description]
    cmp rcx, 0
    je .skip_patch_desc
    call free
    
.skip_patch_desc:
    mov rcx, [r13 + MEMORY_PATCH.originalData]
    cmp rcx, 0
    je .skip_original
    call free
    
.skip_original:
    mov rcx, [r13 + MEMORY_PATCH.patchData]
    cmp rcx, 0
    je .skip_patch
    call free
    
.skip_patch:
    inc r12d
    jmp .free_patches
    
.patches_freed:
    mov rcx, [rbx + MODEL_MEMORY_HOTPATCH.patches]
    cmp rcx, 0
    je .skip_patches_array
    call free
    
.skip_patches_array:
    ; Free regions array
    mov rcx, [rbx + MODEL_MEMORY_HOTPATCH.regions]
    cmp rcx, 0
    je .skip_regions
    call free
    
.skip_regions:
    ; Free hotpatch
    mov rcx, rbx
    call free
    
    pop rbx
    ret
memory_hotpatch_destroy ENDP

; ============================================================================

.data
    szPatchAppliedDetail DB "Patch applied successfully", 0
    szPatchFailedDetail DB "Patch application failed", 0

END
