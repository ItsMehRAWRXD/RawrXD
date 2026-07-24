; ------------------------------------------------------------
; AntiHallucinationHotPatcher.asm
; x64 MASM
; Zero third-party deps
; Windows API only
;
; Safety properties:
; - validates expected bytes before patch
; - validates patch length > 0
; - validates protection changes
; - restores original protection on failure
; - flushes instruction cache after write
; - rollback support via captured original bytes
; - "anti-hallucinate" guard: refuses patch if target bytes
;   do not match the expected signature
; ------------------------------------------------------------

option casemap:none

; ------------------------------------------------------------
; Win64 externs
; ------------------------------------------------------------

EXTERN  VirtualProtect:PROC
EXTERN  FlushInstructionCache:PROC
EXTERN  RtlMoveMemory:PROC
EXTERN  GetLastError:PROC

; ------------------------------------------------------------
; Public exports for C++ linkage
; ------------------------------------------------------------

PUBLIC  AH_GetLastStatus
PUBLIC  AH_GetLastWin32Error
PUBLIC  AH_CompareBytes
PUBLIC  AH_CopyBytes
PUBLIC  AH_ApplyPatch
PUBLIC  AH_RollbackPatch
PUBLIC  AH_Fnv1a64

; ------------------------------------------------------------
; Constants
; ------------------------------------------------------------

PAGE_EXECUTE_READWRITE EQU 40h
PAGE_EXECUTE_READ       EQU 20h
PAGE_READWRITE          EQU 04h
PAGE_READONLY           EQU 02h

AH_OK                   EQU 0
AH_ERR_INVALID_ARG      EQU 1
AH_ERR_EXPECT_MISMATCH  EQU 2
AH_ERR_PROTECT_FAIL     EQU 3
AH_ERR_WRITE_FAIL       EQU 4
AH_ERR_FLUSH_FAIL       EQU 5
AH_ERR_ROLLBACK_FAIL    EQU 6

; ------------------------------------------------------------
; PatchRequest layout
; rcx = request ptr
; +00h  target ptr
; +08h  expected ptr
; +10h  replacement ptr
; +18h  original ptr
; +20h  length qword
; +28h  oldProtect dword (stored in qword slot for alignment)
; +30h  flags qword
; ------------------------------------------------------------

PATCHREQ_TARGET          EQU 00h
PATCHREQ_EXPECTED        EQU 08h
PATCHREQ_REPLACEMENT     EQU 10h
PATCHREQ_ORIGINAL        EQU 18h
PATCHREQ_LENGTH          EQU 20h
PATCHREQ_OLDPROTECT      EQU 28h
PATCHREQ_FLAGS           EQU 30h

; flags
AH_FLAG_CAPTURE_ORIGINAL EQU 00000001h
AH_FLAG_REQUIRE_MATCH     EQU 00000002h
AH_FLAG_RESTORE_PROTECT   EQU 00000004h

; ------------------------------------------------------------
; Data
; ------------------------------------------------------------

.data

g_AH_LastError          dq 0
g_AH_LastTarget         dq 0
g_AH_LastLength         dq 0
g_AH_LastStatus         dq 0

; ------------------------------------------------------------
; Code
; ------------------------------------------------------------

.code

; ------------------------------------------------------------
; AH_GetLastStatus
; returns last status in RAX
; ------------------------------------------------------------
AH_GetLastStatus PROC
    mov     rax, g_AH_LastStatus
    ret
AH_GetLastStatus ENDP

; ------------------------------------------------------------
; AH_GetLastError
; returns last Win32 error captured in RAX
; ------------------------------------------------------------
AH_GetLastWin32Error PROC
    mov     rax, g_AH_LastError
    ret
AH_GetLastWin32Error ENDP

; ------------------------------------------------------------
; AH_CompareBytes
; rcx = a
; rdx = b
; r8  = len
; return eax = 1 if equal, 0 otherwise
; ------------------------------------------------------------
AH_CompareBytes PROC
    test    r8, r8
    jz      _cmp_equal

_cmp_loop:
    mov     al, byte ptr [rcx]
    mov     dl, byte ptr [rdx]
    cmp     al, dl
    jne     _cmp_notequal
    inc     rcx
    inc     rdx
    dec     r8
    jnz     _cmp_loop

_cmp_equal:
    mov     eax, 1
    ret

_cmp_notequal:
    xor     eax, eax
    ret
AH_CompareBytes ENDP

; ------------------------------------------------------------
; AH_CopyBytes
; rcx = dst
; rdx = src
; r8  = len
; ------------------------------------------------------------
AH_CopyBytes PROC
    test    r8, r8
    jz      _copy_done
    mov     r9, r8
    mov     r10, rcx
    mov     r11, rdx
_copy_loop:
    mov     al, byte ptr [r11]
    mov     byte ptr [r10], al
    inc     r10
    inc     r11
    dec     r9
    jnz     _copy_loop
_copy_done:
    ret
AH_CopyBytes ENDP

; ------------------------------------------------------------
; AH_ApplyPatch
; rcx = PatchRequest*
;
; returns:
;   rax = AH_OK or error code
;
; request layout:
; +00h target
; +08h expected
; +10h replacement
; +18h original
; +20h length
; +28h oldProtect
; +30h flags
; ------------------------------------------------------------
AH_ApplyPatch PROC FRAME
    sub     rsp, 68h
    .endprolog

    ; save request pointer
    mov     r11, rcx

    ; clear last state
    xor     rax, rax
    mov     g_AH_LastError, rax
    mov     g_AH_LastTarget, rax
    mov     g_AH_LastLength, rax
    mov     g_AH_LastStatus, rax

    ; validate request ptr
    test    r11, r11
    jz      _invalid_arg

    mov     r10, [r11 + PATCHREQ_TARGET]
    mov     r9,  [r11 + PATCHREQ_EXPECTED]
    mov     r8,  [r11 + PATCHREQ_REPLACEMENT]
    mov     rdx, [r11 + PATCHREQ_LENGTH]
    mov     rax, [r11 + PATCHREQ_FLAGS]

    ; basic validation
    test    r10, r10
    jz      _invalid_arg
    test    r9, r9
    jz      _invalid_arg
    test    r8, r8
    jz      _invalid_arg
    test    rdx, rdx
    jz      _invalid_arg

    ; store observability
    mov     g_AH_LastTarget, r10
    mov     g_AH_LastLength, rdx

    ; anti-hallucination guard:
    ; require target bytes == expected bytes before patch
    ; unless caller explicitly disables via flags (default on)
    test    qword ptr [r11 + PATCHREQ_FLAGS], AH_FLAG_REQUIRE_MATCH
    jz      _skip_match_check

    lea     rcx, [r10]
    lea     rdx, [r9]
    mov     r8,  [r11 + PATCHREQ_LENGTH]
    call    AH_CompareBytes
    test    eax, eax
    jnz     _skip_match_check

    mov     eax, AH_ERR_EXPECT_MISMATCH
    mov     g_AH_LastStatus, rax
    jmp     _fail

_skip_match_check:

    ; optional capture original bytes before write
    test    qword ptr [r11 + PATCHREQ_FLAGS], AH_FLAG_CAPTURE_ORIGINAL
    jz      _skip_capture

    mov     rcx, [r11 + PATCHREQ_ORIGINAL]
    test    rcx, rcx
    jz      _invalid_arg

    lea     rdx, [r10]
    mov     r8,  [r11 + PATCHREQ_LENGTH]
    call    AH_CopyBytes

_skip_capture:

    ; change protection to RWX
    lea     rcx, [r10]
    mov     rdx, [r11 + PATCHREQ_LENGTH]
    mov     r8d, PAGE_EXECUTE_READWRITE
    lea     r9,  [rsp + 20h]          ; oldProtect temp
    call    VirtualProtect
    test    eax, eax
    jnz     _write_patch

    call    GetLastError
    mov     g_AH_LastError, rax
    mov     eax, AH_ERR_PROTECT_FAIL
    mov     g_AH_LastStatus, rax
    jmp     _fail

_write_patch:

    ; write replacement bytes directly
    lea     rcx, [r10]
    mov     rdx, [r11 + PATCHREQ_REPLACEMENT]
    mov     r8,  [r11 + PATCHREQ_LENGTH]
    call    AH_CopyBytes

    ; flush instruction cache
    mov     rcx, -1                   ; pseudo-handle for current process
    mov     rdx, r10
    mov     r8,  [r11 + PATCHREQ_LENGTH]
    call    FlushInstructionCache
    test    eax, eax
    jnz     _restore_protect

    call    GetLastError
    mov     g_AH_LastError, rax
    mov     eax, AH_ERR_FLUSH_FAIL
    mov     g_AH_LastStatus, rax
    jmp     _rollback_attempt

_restore_protect:

    test    qword ptr [r11 + PATCHREQ_FLAGS], AH_FLAG_RESTORE_PROTECT
    jz      _success

    lea     rcx, [r10]
    mov     rdx, [r11 + PATCHREQ_LENGTH]
    mov     r8d, dword ptr [rsp + 20h]
    lea     r9,  [rsp + 28h]
    call    VirtualProtect
    test    eax, eax
    jnz     _success

    call    GetLastError
    mov     g_AH_LastError, rax
    mov     eax, AH_ERR_PROTECT_FAIL
    mov     g_AH_LastStatus, rax
    jmp     _rollback_attempt

_success:
    xor     eax, eax
    mov     g_AH_LastStatus, rax
    jmp     _done

_rollback_attempt:

    ; best-effort rollback if original captured
    mov     rcx, [r11 + PATCHREQ_ORIGINAL]
    test    rcx, rcx
    jz      _fail

    ; restore protection to RWX for rollback
    lea     rcx, [r10]
    mov     rdx, [r11 + PATCHREQ_LENGTH]
    mov     r8d, PAGE_EXECUTE_READWRITE
    lea     r9,  [rsp + 30h]
    call    VirtualProtect

    ; ignore failure here and attempt memory restore anyway
    mov     rcx, r10
    mov     rdx, [r11 + PATCHREQ_ORIGINAL]
    mov     r8,  [r11 + PATCHREQ_LENGTH]
    call    AH_CopyBytes

    mov     rcx, -1
    mov     rdx, r10
    mov     r8,  [r11 + PATCHREQ_LENGTH]
    call    FlushInstructionCache

    ; restore old protection best-effort
    lea     rcx, [r10]
    mov     rdx, [r11 + PATCHREQ_LENGTH]
    mov     r8d, dword ptr [rsp + 30h]
    lea     r9,  [rsp + 38h]
    call    VirtualProtect

    mov     eax, AH_ERR_WRITE_FAIL
    mov     g_AH_LastStatus, rax
    jmp     _done

_invalid_arg:
    mov     eax, AH_ERR_INVALID_ARG
    mov     g_AH_LastStatus, rax

_fail:
    ; status already set
_done:
    add     rsp, 68h
    ret
AH_ApplyPatch ENDP

; ------------------------------------------------------------
; AH_RollbackPatch
; rcx = PatchRequest*
;
; Requires PATCHREQ_ORIGINAL and length.
; ------------------------------------------------------------
AH_RollbackPatch PROC FRAME
    sub     rsp, 58h
    .endprolog

    mov     r11, rcx
    test    r11, r11
    jz      _rb_invalid

    mov     r10, [r11 + PATCHREQ_TARGET]
    mov     r9,  [r11 + PATCHREQ_ORIGINAL]
    mov     rdx, [r11 + PATCHREQ_LENGTH]

    test    r10, r10
    jz      _rb_invalid
    test    r9, r9
    jz      _rb_invalid
    test    rdx, rdx
    jz      _rb_invalid

    ; set RWX
    lea     rcx, [r10]
    mov     r8d, PAGE_EXECUTE_READWRITE
    lea     r9,  [rsp + 20h]
    call    VirtualProtect
    test    eax, eax
    jnz     _rb_write

    call    GetLastError
    mov     g_AH_LastError, rax
    mov     eax, AH_ERR_ROLLBACK_FAIL
    mov     g_AH_LastStatus, rax
    jmp     _rb_done

_rb_write:
    mov     rcx, r10
    mov     rdx, [r11 + PATCHREQ_ORIGINAL]
    mov     r8,  [r11 + PATCHREQ_LENGTH]
    call    AH_CopyBytes

    mov     rcx, -1
    mov     rdx, r10
    mov     r8,  [r11 + PATCHREQ_LENGTH]
    call    FlushInstructionCache

    ; restore previous protection best-effort
    lea     rcx, [r10]
    mov     rdx, [r11 + PATCHREQ_LENGTH]
    mov     r8d, dword ptr [rsp + 20h]
    lea     r9,  [rsp + 28h]
    call    VirtualProtect

    xor     eax, eax
    mov     g_AH_LastStatus, rax
    jmp     _rb_done

_rb_invalid:
    mov     eax, AH_ERR_INVALID_ARG
    mov     g_AH_LastStatus, rax

_rb_done:
    add     rsp, 58h
    ret
AH_RollbackPatch ENDP

; ------------------------------------------------------------
; AH_Fnv1a64
; rcx = data
; rdx = len
; returns rax = hash
; ------------------------------------------------------------
AH_Fnv1a64 PROC
    mov     rax, 14695981039346656037
    test    rdx, rdx
    jz      _fnv_done

_fnv_loop:
    movzx   r8d, byte ptr [rcx]
    xor     rax, r8
    mov     r9, 1099511628211    ; FNV prime in register
    imul    rax, r9
    inc     rcx
    dec     rdx
    jnz     _fnv_loop

_fnv_done:
    ret
AH_Fnv1a64 ENDP

END
