;==============================================================================
; hotpatch_system.inc - MASM Hotpatch System Header
; Purpose: Declare exported functions and constants for hotpatching
; Author: RawrXD CI/CD
; Date: Dec 29, 2025
;==============================================================================

IFNDEF HOTPATCH_SYSTEM_INC
HOTPATCH_SYSTEM_INC EQU 1

;==============================================================================
; CONSTANTS
;==============================================================================

; Patch operation types
PATCH_OP_REPLACE        EQU 1
PATCH_OP_XOR            EQU 2
PATCH_OP_SWAP           EQU 3
PATCH_OP_ROTATE         EQU 4
PATCH_OP_REVERSE        EQU 5
PATCH_OP_SCALE          EQU 6

; Memory protection modes
PROTECT_READ_WRITE      EQU 4       ; PAGE_READWRITE
PROTECT_READ_EXECUTE    EQU 32      ; PAGE_EXECUTE_READ
PROTECT_READ_WRITE_EXEC EQU 64      ; PAGE_EXECUTE_READWRITE

; Patch states
PATCH_STATE_PENDING     EQU 0
PATCH_STATE_APPLIED     EQU 1
PATCH_STATE_VERIFIED    EQU 2
PATCH_STATE_ROLLED_BACK EQU 3
PATCH_STATE_ERROR       EQU 4

; Maximum limits
MAX_PATCHES             EQU 256
MAX_PATTERN_SIZE        EQU 1024
MAX_REPLACEMENT_SIZE    EQU 2048

;==============================================================================
; FUNCTION PROTOTYPES
;==============================================================================

; Initialize the hotpatch system
; Returns: 1 = success, 0 = failure
EXTERN masm_hotpatch_init:PROC

; Shut down the hotpatch system
; Returns: 1 = success, 0 = failure
EXTERN masm_hotpatch_shutdown:PROC

; Add a new patch descriptor
; Args: RCX = patch type, RDX = pattern ptr, R8 = pattern size, R9 = replacement ptr, [rsp+32] = replacement size
; Returns: patch ID or 0 if failure
EXTERN masm_hotpatch_add_patch:PROC

; Apply a patch to memory
; Args: RCX = patch ID
; Returns: 1 = success, 0 = failure
EXTERN masm_hotpatch_apply_patch:PROC

; Remove a patch descriptor
; Args: RCX = patch ID
; Returns: 1 = success, 0 = failure
EXTERN masm_hotpatch_remove_patch:PROC

; Rollback a previously applied patch
; Args: RCX = patch ID
; Returns: 1 = success, 0 = failure
EXTERN masm_hotpatch_rollback_patch:PROC

; Verify a patch was applied correctly
; Args: RCX = patch ID
; Returns: 1 = verified, 0 = mismatch, -1 = error
EXTERN masm_hotpatch_verify_patch:PROC

; List all patches
; Args: RCX = output buffer (DWORD array), RDX = max count
; Returns: actual count filled
EXTERN masm_hotpatch_list_patches:PROC

; Get status of a patch
; Args: RCX = patch ID
; Returns: patch state (PATCH_STATE_*)
EXTERN masm_hotpatch_get_patch_status:PROC

; Find pattern in memory (Boyer-Moore)
; Args: RCX = search buffer, RDX = buffer size, R8 = pattern, R9 = pattern size
; Returns: offset in buffer, or -1 if not found
EXTERN masm_hotpatch_find_pattern:PROC

; Protect memory region
; Args: RCX = address, RDX = size, R8 = new protect mode
; Returns: 1 = success, 0 = failure
EXTERN masm_hotpatch_protect_memory:PROC

; Unprotect memory region
; Args: RCX = address, RDX = size, R8 = old protect mode
; Returns: 1 = success, 0 = failure
EXTERN masm_hotpatch_unprotect_memory:PROC

ENDIF


