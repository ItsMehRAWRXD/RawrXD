; ============================================================================
; Sovereign_IDE_Bridge_RingTrapdoor_Smoke.asm
; Pure MASM smoke test for ring chunking + trapdoor atomics.
; Exit code 0 = pass. Non-zero = failure code.
; ============================================================================

OPTION CASEMAP:NONE
OPTION DOTNAME

EXTRN Bridge_Initialize:PROC
EXTRN Bridge_Shutdown:PROC
EXTRN Bridge_PushResponseChunk:PROC
EXTRN Bridge_TrapdoorCancel:PROC
EXTRN ExitProcess:PROC

BR_OFF_RESP_TAIL             EQU 002Ch
BR_OFF_CANCEL_EPOCH          EQU 0040h
RESP_RING_BASE               EQU 081000h
RESP_SLOT_SIZE               EQU 01000h
RESP_SLOT_OFF_REQ_ID         EQU 0000h
RESP_SLOT_OFF_FLAGS          EQU 000Ch
FLAGS_MORE_DATA              EQU 00000001h
FLAGS_FINAL_CHUNK            EQU 00000002h

BRIDGE_RUNTIME STRUCT
    hMap                DQ ?
    pMap                DQ ?
    LastError           DD ?
    Reserved0           DD ?
BRIDGE_RUNTIME ENDS

.DATA
ALIGN 16

g_Runtime              BRIDGE_RUNTIME <>
g_Source               DB 7000 DUP('A')
g_ReqId                DQ 1122334455667788h

.CODE
PUBLIC main
main PROC
    and rsp, -16
    sub rsp, 80h

    ; Bridge_Initialize(&runtime, NULL, 1)
    lea rcx, [g_Runtime]
    xor rdx, rdx
    mov r8d, 1
    call Bridge_Initialize
    test eax, eax
    jz fail_init

    mov r10, qword ptr [g_Runtime.pMap]
    test r10, r10
    jz fail_map

    ; First chunk: expect MORE_DATA, not FINAL_CHUNK
    lea rcx, [r10]
    mov rdx, qword ptr [g_ReqId]
    xor r8d, r8d              ; status
    mov r9d, 2                ; model_state READY
    lea rax, [g_Source]
    mov qword ptr [rsp + 20h], rax
    mov dword ptr [rsp + 28h], 7000
    mov dword ptr [rsp + 30h], 0
    call Bridge_PushResponseChunk

    cmp eax, 0FFFFFFFFh
    je fail_chunk1
    test edx, FLAGS_MORE_DATA
    jz fail_chunk1
    test edx, FLAGS_FINAL_CHUNK
    jnz fail_chunk1

    ; Second chunk: expect FINAL_CHUNK
    lea rcx, [r10]
    mov rdx, qword ptr [g_ReqId]
    xor r8d, r8d
    mov r9d, 2
    lea rax, [g_Source + 4064]
    mov qword ptr [rsp + 20h], rax
    mov dword ptr [rsp + 28h], (7000 - 4064)
    mov dword ptr [rsp + 30h], 0
    call Bridge_PushResponseChunk

    cmp eax, 2936
    jne fail_chunk2
    test edx, FLAGS_FINAL_CHUNK
    jz fail_chunk2

    ; Tail should now be 2.
    cmp dword ptr [r10 + BR_OFF_RESP_TAIL], 2
    jne fail_tail

    ; Validate req_id persisted in slot 0 and slot 1.
    mov rax, 1122334455667788h
    cmp qword ptr [r10 + RESP_RING_BASE + RESP_SLOT_OFF_REQ_ID], rax
    jne fail_reqid
    cmp qword ptr [r10 + RESP_RING_BASE + RESP_SLOT_SIZE + RESP_SLOT_OFF_REQ_ID], rax
    jne fail_reqid

    ; Trapdoor epoch increments: 0 -> 1 -> 2
    lea rcx, [r10]
    xor rdx, rdx
    mov r8d, 1
    call Bridge_TrapdoorCancel
    cmp rax, 1
    jne fail_trapdoor

    lea rcx, [r10]
    mov rdx, 0
    mov r8d, 1
    call Bridge_TrapdoorCancel
    cmp rax, 2
    jne fail_trapdoor

    cmp qword ptr [r10 + BR_OFF_CANCEL_EPOCH], 2
    jne fail_trapdoor

    ; Clean shutdown.
    lea rcx, [g_Runtime]
    call Bridge_Shutdown

    xor ecx, ecx
    call ExitProcess

fail_init:
    mov ecx, 1
    call ExitProcess
fail_map:
    mov ecx, 2
    call ExitProcess
fail_chunk1:
    mov ecx, 3
    call ExitProcess
fail_chunk2:
    mov ecx, 4
    call ExitProcess
fail_tail:
    mov ecx, 5
    call ExitProcess
fail_reqid:
    mov ecx, 6
    call ExitProcess
fail_trapdoor:
    mov ecx, 7
    call ExitProcess

main ENDP
END
