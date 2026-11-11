OPTION CASEMAP:NONE

EXTERN WSAStartup      : PROC
EXTERN WSACleanup      : PROC
EXTERN socket          : PROC
EXTERN bind            : PROC
EXTERN sendto          : PROC
EXTERN recvfrom        : PROC
EXTERN closesocket     : PROC
EXTERN ioctlsocket     : PROC
EXTERN WSAGetLastError : PROC

PUBLIC NetLockstep_Init
PUBLIC NetLockstep_Shutdown
PUBLIC NetLockstep_SetRemote
PUBLIC NetLockstep_SetJitterTicks
PUBLIC NetLockstep_SendSync
PUBLIC NetLockstep_PollRecv
PUBLIC NetLockstep_VerifyTick
PUBLIC NetLockstep_CanStep
PUBLIC NetLockstep_GetRemoteContigTick
PUBLIC NetLockstep_GetRemoteHighestTick
PUBLIC NetLockstep_GetStats

AF_INET            EQU 2
SOCK_DGRAM         EQU 2
IPPROTO_UDP        EQU 17
INVALID_SOCKET     EQU -1
FIONBIO            EQU 8004667Eh
WSAEWOULDBLOCK     EQU 10035

SOCKADDR_IN_SIZE   EQU 16
PACKET_BYTES       EQU 16

WINDOW_SIZE        EQU 256
WINDOW_MASK        EQU 255

; 16-byte packet layout
; +0  DWORD tick
; +4  QWORD crc64
; +12 WORD inputDigest
; +14 WORD flags

.data
ALIGN 16
NL_Socket              dq INVALID_SOCKET
NL_LocalSockAddr       db SOCKADDR_IN_SIZE dup(0)
NL_RemoteSockAddr      db SOCKADDR_IN_SIZE dup(0)

NL_TxPacket            db PACKET_BYTES dup(0)
NL_RxPacket            db PACKET_BYTES dup(0)

NL_RemoteSeen          dd 0
NL_RemoteHighestTick   dd 0
NL_RemoteContigTick    dd 0FFFFFFFFh
NL_JitterTicks         dd 2
NL_DesyncDetected      dd 0

; Stats
NL_StatRxPackets       dd 0
NL_StatTxPackets       dd 0
NL_StatDrops           dd 0
NL_StatOutOfOrder      dd 0
NL_StatDuplicates      dd 0

ALIGN 16
NL_RxTick              dd WINDOW_SIZE dup(0)
NL_RxCRC               dq WINDOW_SIZE dup(0)
NL_RxDigest            dw WINDOW_SIZE dup(0)
NL_RxFlags             dw WINDOW_SIZE dup(0)
NL_RxValid             db WINDOW_SIZE dup(0)

.code

; RCX=local port (host order)
; RDX=remote IPv4 (network order)
; R8 =remote port (host order)
; Returns EAX=1 success, 0 failure
NetLockstep_Init PROC FRAME
    sub rsp, 268h
    .allocstack 268h
    .endprolog

    mov qword ptr [rsp + 40h], rcx
    mov qword ptr [rsp + 48h], rdx
    mov qword ptr [rsp + 50h], r8

    mov ecx, 0202h
    lea rdx, [rsp + 60h]
    call WSAStartup
    test eax, eax
    jnz nl_fail

    mov ecx, AF_INET
    mov edx, SOCK_DGRAM
    mov r8d, IPPROTO_UDP
    call socket
    mov qword ptr [NL_Socket], rax
    cmp rax, INVALID_SOCKET
    je nl_fail_cleanup

    mov word ptr [NL_LocalSockAddr + 0], AF_INET
    mov ax, word ptr [rsp + 40h]
    xchg al, ah
    mov word ptr [NL_LocalSockAddr + 2], ax
    mov dword ptr [NL_LocalSockAddr + 4], 0
    mov qword ptr [NL_LocalSockAddr + 8], 0

    mov rcx, qword ptr [NL_Socket]
    lea rdx, NL_LocalSockAddr
    mov r8d, SOCKADDR_IN_SIZE
    call bind
    test eax, eax
    jnz nl_fail_socket

    mov dword ptr [rsp + 38h], 1
    mov rcx, qword ptr [NL_Socket]
    mov edx, FIONBIO
    lea r8, [rsp + 38h]
    call ioctlsocket
    test eax, eax
    jnz nl_fail_socket

    mov rcx, qword ptr [rsp + 48h]
    mov rdx, qword ptr [rsp + 50h]
    call NetLockstep_SetRemote

    mov dword ptr [NL_RemoteSeen], 0
    mov dword ptr [NL_RemoteHighestTick], 0
    mov dword ptr [NL_RemoteContigTick], 0FFFFFFFFh
    mov dword ptr [NL_DesyncDetected], 0

    mov dword ptr [NL_StatRxPackets], 0
    mov dword ptr [NL_StatTxPackets], 0
    mov dword ptr [NL_StatDrops], 0
    mov dword ptr [NL_StatOutOfOrder], 0
    mov dword ptr [NL_StatDuplicates], 0

    lea rdi, NL_RxValid
    mov ecx, WINDOW_SIZE
    xor eax, eax
    rep stosb

    mov eax, 1
    add rsp, 268h
    ret

nl_fail_socket:
    mov rcx, qword ptr [NL_Socket]
    cmp rcx, INVALID_SOCKET
    je nl_fail_cleanup
    call closesocket
    mov qword ptr [NL_Socket], INVALID_SOCKET

nl_fail_cleanup:
    call WSACleanup

nl_fail:
    xor eax, eax
    add rsp, 268h
    ret
NetLockstep_Init ENDP

; RCX=remote IPv4 (network order), RDX=remote port (host order)
; Returns EAX=1
NetLockstep_SetRemote PROC
    mov word ptr [NL_RemoteSockAddr + 0], AF_INET
    mov ax, dx
    xchg al, ah
    mov word ptr [NL_RemoteSockAddr + 2], ax
    mov dword ptr [NL_RemoteSockAddr + 4], ecx
    mov qword ptr [NL_RemoteSockAddr + 8], 0
    mov eax, 1
    ret
NetLockstep_SetRemote ENDP

; RCX=jitter ticks used by stall gate
; Returns EAX=1
NetLockstep_SetJitterTicks PROC
    mov dword ptr [NL_JitterTicks], ecx
    mov eax, 1
    ret
NetLockstep_SetJitterTicks ENDP

; RCX=tick, RDX=crc64, R8D=inputDigest, R9D=flags
; Returns EAX=bytes sent or -1 on socket error
NetLockstep_SendSync PROC FRAME
    sub rsp, 48h
    .allocstack 48h
    .endprolog

    cmp qword ptr [NL_Socket], INVALID_SOCKET
    je tx_fail

    mov dword ptr [NL_TxPacket + 0], ecx
    mov qword ptr [NL_TxPacket + 4], rdx
    mov word ptr [NL_TxPacket + 12], r8w
    mov word ptr [NL_TxPacket + 14], r9w

    mov rcx, qword ptr [NL_Socket]
    lea rdx, NL_TxPacket
    mov r8d, PACKET_BYTES
    xor r9d, r9d
    lea rax, NL_RemoteSockAddr
    mov qword ptr [rsp + 20h], rax
    mov dword ptr [rsp + 28h], SOCKADDR_IN_SIZE
    call sendto

    cmp eax, -1
    je tx_done
    inc dword ptr [NL_StatTxPackets]

tx_done:
    add rsp, 48h
    ret

tx_fail:
    mov eax, -1
    add rsp, 48h
    ret
NetLockstep_SendSync ENDP

; Poll non-blocking recv and push packets into reorder window.
; Returns EAX=packets ingested this call
NetLockstep_PollRecv PROC FRAME
    sub rsp, 68h
    .allocstack 68h
    .endprolog

    xor r11d, r11d
    cmp qword ptr [NL_Socket], INVALID_SOCKET
    je rx_done

rx_loop:
    cmp r11d, 64
    jae rx_done

    mov dword ptr [rsp + 30h], SOCKADDR_IN_SIZE

    mov rcx, qword ptr [NL_Socket]
    lea rdx, NL_RxPacket
    mov r8d, PACKET_BYTES
    xor r9d, r9d
    lea rax, [rsp + 40h]
    mov qword ptr [rsp + 20h], rax
    lea rax, [rsp + 30h]
    mov qword ptr [rsp + 28h], rax
    call recvfrom

    cmp eax, -1
    jne rx_have

    call WSAGetLastError
    cmp eax, WSAEWOULDBLOCK
    je rx_done
    jmp rx_done

rx_have:
    cmp eax, PACKET_BYTES
    jb rx_continue

    mov r10d, dword ptr [NL_RxPacket + 0]
    mov rax, qword ptr [NL_RxPacket + 4]
    movzx edx, word ptr [NL_RxPacket + 12]
    movzx esi, word ptr [NL_RxPacket + 14]

    mov ecx, r10d
    and ecx, WINDOW_MASK

    lea r8, NL_RxTick
    lea r9, NL_RxValid

    cmp byte ptr [r9 + rcx], 0
    je rx_store

    mov edi, dword ptr [r8 + rcx*4]
    cmp edi, r10d
    jne rx_maybe_ooo

    inc dword ptr [NL_StatDuplicates]
    jmp rx_count

rx_maybe_ooo:
    cmp edi, r10d
    jb rx_store
    inc dword ptr [NL_StatOutOfOrder]

rx_store:
    mov dword ptr [r8 + rcx*4], r10d
    lea r8, NL_RxCRC
    mov qword ptr [r8 + rcx*8], rax
    lea r8, NL_RxDigest
    mov word ptr [r8 + rcx*2], dx
    lea r8, NL_RxFlags
    mov word ptr [r8 + rcx*2], si
    mov byte ptr [r9 + rcx], 1

    cmp dword ptr [NL_RemoteSeen], 0
    jne @F
    mov dword ptr [NL_RemoteSeen], 1
    mov dword ptr [NL_RemoteHighestTick], r10d
    mov dword ptr [NL_RemoteContigTick], r10d
    jmp rx_after_contig
@@:
    cmp r10d, dword ptr [NL_RemoteHighestTick]
    jbe rx_after_high

    mov eax, dword ptr [NL_RemoteHighestTick]
    mov edx, r10d
    sub edx, eax
    cmp edx, 1
    jle @F
    dec edx
    add dword ptr [NL_StatDrops], edx
@@:
    mov dword ptr [NL_RemoteHighestTick], r10d

rx_after_high:
    mov eax, dword ptr [NL_RemoteContigTick]

rx_contig_loop:
    mov edx, eax
    inc edx
    mov ecx, edx
    and ecx, WINDOW_MASK

    lea r8, NL_RxValid
    cmp byte ptr [r8 + rcx], 0
    je rx_after_contig

    lea r8, NL_RxTick
    cmp dword ptr [r8 + rcx*4], edx
    jne rx_after_contig

    mov eax, edx
    jmp rx_contig_loop

rx_after_contig:
    mov dword ptr [NL_RemoteContigTick], eax

rx_count:
    inc dword ptr [NL_StatRxPackets]
    inc r11d

rx_continue:
    jmp rx_loop

rx_done:
    mov eax, r11d
    add rsp, 68h
    ret
NetLockstep_PollRecv ENDP

; RCX=tick, RDX=localCRC, R8D=localInputDigest
; Returns EAX: 0=match, 1=mismatch, 2=not yet available
NetLockstep_VerifyTick PROC
    mov eax, ecx
    and eax, WINDOW_MASK

    lea r9, NL_RxValid
    cmp byte ptr [r9 + rax], 0
    je v_not_ready

    lea r9, NL_RxTick
    cmp dword ptr [r9 + rax*4], ecx
    jne v_not_ready

    lea r9, NL_RxCRC
    mov r10, qword ptr [r9 + rax*8]
    cmp r10, rdx
    jne v_mismatch

    lea r9, NL_RxDigest
    movzx r10d, word ptr [r9 + rax*2]
    movzx r8d, r8w
    cmp r10d, r8d
    jne v_mismatch

    xor eax, eax
    ret

v_mismatch:
    mov dword ptr [NL_DesyncDetected], 1
    mov eax, 1
    ret

v_not_ready:
    mov eax, 2
    ret
NetLockstep_VerifyTick ENDP

; RCX = local next tick candidate
; Returns EAX=1 if simulation can step, 0 if should stall
NetLockstep_CanStep PROC
    cmp dword ptr [NL_RemoteSeen], 0
    je cs_allow

    mov eax, dword ptr [NL_RemoteContigTick]
    add eax, dword ptr [NL_JitterTicks]
    cmp ecx, eax
    jbe cs_allow

    xor eax, eax
    ret

cs_allow:
    mov eax, 1
    ret
NetLockstep_CanStep ENDP

NetLockstep_GetRemoteContigTick PROC
    mov eax, dword ptr [NL_RemoteContigTick]
    ret
NetLockstep_GetRemoteContigTick ENDP

NetLockstep_GetRemoteHighestTick PROC
    mov eax, dword ptr [NL_RemoteHighestTick]
    ret
NetLockstep_GetRemoteHighestTick ENDP

; RCX = pointer to output struct of 6 DWORDs:
; [0]=rx, [1]=tx, [2]=drops, [3]=ooo, [4]=dupes, [5]=desyncFlag
; Returns EAX=1
NetLockstep_GetStats PROC
    mov eax, dword ptr [NL_StatRxPackets]
    mov dword ptr [rcx + 0], eax
    mov eax, dword ptr [NL_StatTxPackets]
    mov dword ptr [rcx + 4], eax
    mov eax, dword ptr [NL_StatDrops]
    mov dword ptr [rcx + 8], eax
    mov eax, dword ptr [NL_StatOutOfOrder]
    mov dword ptr [rcx + 12], eax
    mov eax, dword ptr [NL_StatDuplicates]
    mov dword ptr [rcx + 16], eax
    mov eax, dword ptr [NL_DesyncDetected]
    mov dword ptr [rcx + 20], eax
    mov eax, 1
    ret
NetLockstep_GetStats ENDP

NetLockstep_Shutdown PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog

    mov rcx, qword ptr [NL_Socket]
    cmp rcx, INVALID_SOCKET
    je @F
    call closesocket
    mov qword ptr [NL_Socket], INVALID_SOCKET
@@:
    call WSACleanup
    mov eax, 1
    add rsp, 28h
    ret
NetLockstep_Shutdown ENDP

END
