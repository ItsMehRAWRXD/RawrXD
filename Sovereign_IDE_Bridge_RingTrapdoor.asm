; ============================================================================
; Sovereign_IDE_Bridge_RingTrapdoor.asm
; Pure x64 MASM bridge primitives (no CRT deps)
; - Bridge_Initialize
; - SPSC ordering primitives
; - Atomic trapdoor cancellation primitives
; ============================================================================

OPTION CASEMAP:NONE
OPTION DOTNAME

EXTRN CreateFileMappingA:PROC
EXTRN OpenFileMappingA:PROC
EXTRN MapViewOfFile:PROC
EXTRN UnmapViewOfFile:PROC
EXTRN CloseHandle:PROC
EXTRN QueryPerformanceCounter:PROC
EXTRN GetLastError:PROC

PAGE_READWRITE        EQU 04h
FILE_MAP_ALL_ACCESS   EQU 0F001Fh
SHMEM_SIZE            EQU 00100000h

BRIDGE_MAGIC          EQU 05352565F49444531h  ; "SRV_IDE1"
BRIDGE_STATE_INIT     EQU 0
BRIDGE_STATE_READY    EQU 1
BRIDGE_STATE_DEGRADED EQU 2

BR_OFF_MAGIC                 EQU 0000h
BR_OFF_VERSION_MAJOR         EQU 0008h
BR_OFF_VERSION_MINOR         EQU 000Ch
BR_OFF_BRIDGE_STATE          EQU 0010h
BR_OFF_FEATURE_BITS          EQU 0014h
BR_OFF_HEARTBEAT_QPC         EQU 0018h
BR_OFF_REQ_HEAD              EQU 0020h
BR_OFF_REQ_TAIL              EQU 0024h
BR_OFF_RESP_HEAD             EQU 0028h
BR_OFF_RESP_TAIL             EQU 002Ch
BR_OFF_DROPPED_REQ           EQU 0030h
BR_OFF_DROPPED_RESP          EQU 0038h
BR_OFF_CANCEL_EPOCH          EQU 0040h
BR_OFF_CANCEL_TARGET_REQ_ID  EQU 0048h
BR_OFF_CANCEL_FLAGS          EQU 0050h
BR_OFF_CANCEL_ACK_EPOCH      EQU 0054h

RESP_RING_BASE               EQU 081000h
RESP_SLOT_SIZE               EQU 01000h
RESP_SLOT_COUNT              EQU 64
RESP_SLOT_MASK               EQU (RESP_SLOT_COUNT - 1)
RESP_PAYLOAD_CAP             EQU 4064

RESP_SLOT_OFF_REQ_ID         EQU 0000h
RESP_SLOT_OFF_STATUS         EQU 0008h
RESP_SLOT_OFF_FLAGS          EQU 000Ch
RESP_SLOT_OFF_PAYLOAD_LEN    EQU 0010h
RESP_SLOT_OFF_MODEL_STATE    EQU 0014h
RESP_SLOT_OFF_LATENCY_US     EQU 0018h
RESP_SLOT_OFF_PAYLOAD        EQU 0020h

FLAGS_MORE_DATA              EQU 00000001h
FLAGS_FINAL_CHUNK            EQU 00000002h

; Runtime structure owned by caller.
BRIDGE_RUNTIME STRUCT
    hMap                DQ ?
    pMap                DQ ?
    LastError           DD ?
    Reserved0           DD ?
BRIDGE_RUNTIME ENDS

; 64-byte aligned control blocks (false-sharing protection)
BRIDGE_RING_CTRL STRUCT
    Head                DD ?
    Tail                DD ?
    Pad                 DB 56 DUP(?)
BRIDGE_RING_CTRL ENDS

.DATA
ALIGN 16

g_IdeBridgeName        DB "SOVEREIGN_IDE_BRIDGE_V1",0

.CODE

; ----------------------------------------------------------------------------
; Bridge_UpdateHeartbeat
; RCX = pBridgeHeader
; Returns EAX=1 on success, EAX=0 on failure
; ----------------------------------------------------------------------------
PUBLIC Bridge_UpdateHeartbeat
Bridge_UpdateHeartbeat PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    test rcx, rcx
    jz hb_fail

    mov r10, rcx

    lea rdx, [rbp - 8]
    mov rcx, rdx
    call QueryPerformanceCounter
    test eax, eax
    jz hb_fail

    mov rax, qword ptr [rbp - 8]
    mov qword ptr [r10 + BR_OFF_HEARTBEAT_QPC], rax
    mov eax, 1
    leave
    ret

hb_fail:
    xor eax, eax
    leave
    ret
Bridge_UpdateHeartbeat ENDP

; ----------------------------------------------------------------------------
; Bridge_StoreReleaseTail
; RCX = pointer to tail (DWORD)
; EDX = new tail value
; ----------------------------------------------------------------------------
PUBLIC Bridge_StoreReleaseTail
Bridge_StoreReleaseTail PROC
    sfence
    mov dword ptr [rcx], edx
    ret
Bridge_StoreReleaseTail ENDP

; ----------------------------------------------------------------------------
; Bridge_LoadAcquireTail
; RCX = pointer to tail (DWORD)
; Returns EAX = tail value
; ----------------------------------------------------------------------------
PUBLIC Bridge_LoadAcquireTail
Bridge_LoadAcquireTail PROC
    mov eax, dword ptr [rcx]
    lfence
    ret
Bridge_LoadAcquireTail ENDP

; ----------------------------------------------------------------------------
; Bridge_StoreReleaseHead
; RCX = pointer to head (DWORD)
; EDX = new head value
; ----------------------------------------------------------------------------
PUBLIC Bridge_StoreReleaseHead
Bridge_StoreReleaseHead PROC
    sfence
    mov dword ptr [rcx], edx
    ret
Bridge_StoreReleaseHead ENDP

; ----------------------------------------------------------------------------
; Bridge_LoadAcquireHead
; RCX = pointer to head (DWORD)
; Returns EAX = head value
; ----------------------------------------------------------------------------
PUBLIC Bridge_LoadAcquireHead
Bridge_LoadAcquireHead PROC
    mov eax, dword ptr [rcx]
    lfence
    ret
Bridge_LoadAcquireHead ENDP

; ----------------------------------------------------------------------------
; Bridge_IncrementCancelEpoch
; RCX = pointer to cancel_epoch (QWORD)
; Returns RAX = new epoch value
; ----------------------------------------------------------------------------
PUBLIC Bridge_IncrementCancelEpoch
Bridge_IncrementCancelEpoch PROC
    mov rax, 1
    lock xadd qword ptr [rcx], rax
    inc rax
    ret
Bridge_IncrementCancelEpoch ENDP

; ----------------------------------------------------------------------------
; Bridge_TrapdoorCancel
; RCX = pBridgeHeader
; RDX = cancel_target_req_id (0 = active)
; R8D = cancel_flags
; Returns RAX = new cancel_epoch
; ----------------------------------------------------------------------------
PUBLIC Bridge_TrapdoorCancel
Bridge_TrapdoorCancel PROC
    mov qword ptr [rcx + BR_OFF_CANCEL_TARGET_REQ_ID], rdx
    mov dword ptr [rcx + BR_OFF_CANCEL_FLAGS], r8d
    sfence

    lea rcx, [rcx + BR_OFF_CANCEL_EPOCH]
    call Bridge_IncrementCancelEpoch
    ret
Bridge_TrapdoorCancel ENDP

; ----------------------------------------------------------------------------
; Bridge_PushResponseChunk
; RCX = pBridgeHeader
; RDX = req_id
; R8D = status
; R9D = model_state
; [caller_rsp+20h] = pSrc (QWORD)
; [caller_rsp+28h] = srcLen (DWORD)
; [caller_rsp+30h] = baseFlags (DWORD)
; Returns:
;   EAX = bytes written (or FFFFFFFFh if ring full / invalid args)
;   EDX = final flags written for the slot
; ----------------------------------------------------------------------------
PUBLIC Bridge_PushResponseChunk
Bridge_PushResponseChunk PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    test rcx, rcx
    jz bprc_fail

    ; Validate source pointer only when srcLen > 0.
    mov r11, qword ptr [rbp + 3Ch]  ; pSrc
    mov eax, dword ptr [rbp + 44h]  ; srcLen
    test eax, eax
    jz bprc_src_ok
    test r11, r11
    jz bprc_fail

bprc_src_ok:
    mov qword ptr [rbp - 8], rdx     ; preserve req_id
    mov r10, rcx                    ; keep pBridgeHeader

    ; Ring full check using response head/tail.
    mov ebx, dword ptr [r10 + BR_OFF_RESP_HEAD]
    mov ecx, dword ptr [r10 + BR_OFF_RESP_TAIL]
    mov esi, ecx
    inc esi
    and esi, RESP_SLOT_MASK
    cmp esi, ebx
    je bprc_full

    ; slot = base + RESP_RING_BASE + (tail * RESP_SLOT_SIZE)
    mov eax, ecx
    shl eax, 12
    lea rdi, [r10 + RESP_RING_BASE]
    add rdi, rax

    ; copyLen = min(srcLen, RESP_PAYLOAD_CAP)
    mov eax, dword ptr [rbp + 44h]
    mov ecx, eax
    cmp ecx, RESP_PAYLOAD_CAP
    jbe bprc_len_ready
    mov ecx, RESP_PAYLOAD_CAP

bprc_len_ready:
    ; finalFlags = baseFlags | (MORE_DATA or FINAL_CHUNK)
    mov edx, dword ptr [rbp + 48h]  ; baseFlags
    cmp eax, RESP_PAYLOAD_CAP
    jbe bprc_mark_final
    or edx, FLAGS_MORE_DATA
    jmp bprc_flags_ready

bprc_mark_final:
    or edx, FLAGS_FINAL_CHUNK

bprc_flags_ready:
    mov rax, qword ptr [rbp - 8]
    mov qword ptr [rdi + RESP_SLOT_OFF_REQ_ID], rax
    mov dword ptr [rdi + RESP_SLOT_OFF_STATUS], r8d
    mov dword ptr [rdi + RESP_SLOT_OFF_FLAGS], edx
    mov dword ptr [rdi + RESP_SLOT_OFF_PAYLOAD_LEN], ecx
    mov dword ptr [rdi + RESP_SLOT_OFF_MODEL_STATE], r9d
    mov qword ptr [rdi + RESP_SLOT_OFF_LATENCY_US], 0

    test ecx, ecx
    jz bprc_publish

    mov rsi, r11
    lea rdi, [rdi + RESP_SLOT_OFF_PAYLOAD]
    rep movsb

bprc_publish:
    sfence
    mov dword ptr [r10 + BR_OFF_RESP_TAIL], esi

    ; Return copyLen in EAX and final flags in EDX.
    mov eax, dword ptr [rbp + 44h]
    cmp eax, RESP_PAYLOAD_CAP
    jbe bprc_ret_len
    mov eax, RESP_PAYLOAD_CAP

bprc_ret_len:
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

bprc_full:
    mov rcx, qword ptr [r10 + BR_OFF_DROPPED_RESP]
    inc rcx
    mov qword ptr [r10 + BR_OFF_DROPPED_RESP], rcx

bprc_fail:
    mov eax, 0FFFFFFFFh
    xor edx, edx
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Bridge_PushResponseChunk ENDP

; ----------------------------------------------------------------------------
; Bridge_Initialize
; RCX = pBRIDGE_RUNTIME (out)
; RDX = optional bridge map name (ASCIIZ), null => default
; R8D = create map if non-zero, else open existing
; Returns EAX = 1 success, 0 failure
; ----------------------------------------------------------------------------
PUBLIC Bridge_Initialize
Bridge_Initialize PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 58h
    .allocstack 58h
    .endprolog

    mov qword ptr [rbp - 08h], rcx  ; saved pRuntime
    mov qword ptr [rbp - 10h], rdx  ; saved name

    test rcx, rcx
    jz bi_fail

    ; Clear runtime outputs.
    mov qword ptr [rcx + BRIDGE_RUNTIME.hMap], 0
    mov qword ptr [rcx + BRIDGE_RUNTIME.pMap], 0
    mov dword ptr [rcx + BRIDGE_RUNTIME.LastError], 0

    ; Select map name.
    mov r9, rdx
    test r9, r9
    jnz bi_name_ready
    lea r9, [g_IdeBridgeName]

bi_name_ready:
    test r8d, r8d
    jz bi_open_existing

    ; CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SHMEM_SIZE, name)
    mov rcx, -1
    xor rdx, rdx
    mov r8d, PAGE_READWRITE
    mov dword ptr [rsp + 20h], 0
    mov dword ptr [rsp + 28h], SHMEM_SIZE
    mov qword ptr [rsp + 30h], r9
    call CreateFileMappingA
    jmp bi_have_map

bi_open_existing:
    mov rcx, FILE_MAP_ALL_ACCESS
    xor rdx, rdx
    mov r8, r9
    call OpenFileMappingA

bi_have_map:
    test rax, rax
    jz bi_set_last_error

    mov rcx, qword ptr [rbp - 08h]
    mov qword ptr [rcx + BRIDGE_RUNTIME.hMap], rax

    ; pMap = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, SHMEM_SIZE)
    mov rcx, rax
    mov edx, FILE_MAP_ALL_ACCESS
    xor r8d, r8d
    xor r9d, r9d
    mov qword ptr [rsp + 20h], SHMEM_SIZE
    call MapViewOfFile
    test rax, rax
    jz bi_cleanup_map_fail

    mov rcx, qword ptr [rbp - 08h]
    mov qword ptr [rcx + BRIDGE_RUNTIME.pMap], rax

    ; Initialize bridge header.
    mov rbx, rax
    mov rax, BRIDGE_MAGIC
    mov qword ptr [rbx + BR_OFF_MAGIC], rax
    mov dword ptr [rbx + BR_OFF_VERSION_MAJOR], 1
    mov dword ptr [rbx + BR_OFF_VERSION_MINOR], 0
    mov dword ptr [rbx + BR_OFF_BRIDGE_STATE], BRIDGE_STATE_READY
    mov dword ptr [rbx + BR_OFF_REQ_HEAD], 0
    mov dword ptr [rbx + BR_OFF_REQ_TAIL], 0
    mov dword ptr [rbx + BR_OFF_RESP_HEAD], 0
    mov dword ptr [rbx + BR_OFF_RESP_TAIL], 0
    mov qword ptr [rbx + BR_OFF_DROPPED_REQ], 0
    mov qword ptr [rbx + BR_OFF_DROPPED_RESP], 0
    mov qword ptr [rbx + BR_OFF_CANCEL_EPOCH], 0
    mov qword ptr [rbx + BR_OFF_CANCEL_TARGET_REQ_ID], 0
    mov dword ptr [rbx + BR_OFF_CANCEL_FLAGS], 0
    mov dword ptr [rbx + BR_OFF_CANCEL_ACK_EPOCH], 0

    lea rcx, [rbp - 20h]
    call QueryPerformanceCounter
    test eax, eax
    jz bi_success

    mov rax, qword ptr [rbp - 20h]
    mov qword ptr [rbx + BR_OFF_HEARTBEAT_QPC], rax

bi_success:
    mov eax, 1
    add rsp, 58h
    pop rbx
    pop rbp
    ret

bi_cleanup_map_fail:
    mov rcx, qword ptr [rbp - 08h]
    mov rdx, qword ptr [rcx + BRIDGE_RUNTIME.hMap]
    test rdx, rdx
    jz bi_set_last_error
    mov rcx, rdx
    call CloseHandle
    mov rcx, qword ptr [rbp - 08h]
    mov qword ptr [rcx + BRIDGE_RUNTIME.hMap], 0

bi_set_last_error:
    call GetLastError
    mov rcx, qword ptr [rbp - 08h]
    mov dword ptr [rcx + BRIDGE_RUNTIME.LastError], eax

bi_fail:
    xor eax, eax
    add rsp, 58h
    pop rbx
    pop rbp
    ret
Bridge_Initialize ENDP

; ----------------------------------------------------------------------------
; Bridge_Shutdown
; RCX = pBRIDGE_RUNTIME
; ----------------------------------------------------------------------------
PUBLIC Bridge_Shutdown
Bridge_Shutdown PROC
    test rcx, rcx
    jz bs_done

    mov r10, rcx

    mov rax, qword ptr [r10 + BRIDGE_RUNTIME.pMap]
    test rax, rax
    jz bs_skip_unmap
    mov rcx, rax
    call UnmapViewOfFile
    mov qword ptr [r10 + BRIDGE_RUNTIME.pMap], 0

bs_skip_unmap:
    mov rax, qword ptr [r10 + BRIDGE_RUNTIME.hMap]
    test rax, rax
    jz bs_done
    mov rcx, rax
    call CloseHandle
    mov qword ptr [r10 + BRIDGE_RUNTIME.hMap], 0

bs_done:
    ret
Bridge_Shutdown ENDP

END
