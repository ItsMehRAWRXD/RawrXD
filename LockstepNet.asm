OPTION CASEMAP:NONE

EXTERN WSAStartup   : PROC
EXTERN WSACleanup   : PROC
EXTERN socket       : PROC
EXTERN bind         : PROC
EXTERN sendto       : PROC
EXTERN recvfrom     : PROC
EXTERN closesocket  : PROC
EXTERN ioctlsocket  : PROC
EXTERN WSAGetLastError : PROC

PUBLIC LockstepNet_Init
PUBLIC LockstepNet_Shutdown
PUBLIC LockstepNet_SetRemote
PUBLIC LockstepNet_SendTickCRC
PUBLIC LockstepNet_PollRecv
PUBLIC LockstepNet_TryGetRemoteCRC
PUBLIC LockstepNet_CheckDesync
PUBLIC LockstepNet_CanAdvance
PUBLIC LockstepNet_GetLatestRemoteTick
PUBLIC Net_PreparePacket
PUBLIC Net_VerifySync
PUBLIC Net_AdoptRemoteTick
PUBLIC Net_GetLocalTick
PUBLIC Net_GetLatestRemoteTick
PUBLIC Net_GetLocalCRC
PUBLIC Net_GetPeerCRC

AF_INET             EQU 2
SOCK_DGRAM          EQU 2
IPPROTO_UDP         EQU 17
INVALID_SOCKET      EQU -1

FIONBIO             EQU 8004667Eh
WSAEWOULDBLOCK      EQU 10035

SOCKADDR_IN_SIZE    EQU 16
PACKET_SIZE         EQU 24
RING_SIZE           EQU 256

PKT_MAGIC           EQU 4B50534Ch      ; "LSPK"
PKT_VERSION         EQU 1

.data
ALIGN 16
NetSocket           dq INVALID_SOCKET

; Lockstep heartbeat state
LocalTick           dq 0
RemoteTick          dq 0
PeerCRC             dq 0
LocalCRC            dq 0

LocalSockAddr       db SOCKADDR_IN_SIZE dup(0)
RemoteSockAddr      db SOCKADDR_IN_SIZE dup(0)

TxPacket            db PACKET_SIZE dup(0)
RxPacket            db PACKET_SIZE dup(0)

LocalSequence       dd 0
RemoteLatestTick    dd 0
RemoteSeen          dd 0
DesyncFlag          dd 0

ALIGN 16
RemoteTickRing      dd RING_SIZE dup(0)
RemoteCRCRing       dq RING_SIZE dup(0)
RemoteValidRing     db RING_SIZE dup(0)

.code

; RCX = packet buffer pointer (24 bytes)
; RDX = current tick
; R8  = current CRC64
; R9  = input digest (uint32 in low dword)
; Packet layout:
; +0  QWORD Tick
; +8  QWORD CRC64
; +16 DWORD InputDigest
; +20 DWORD Reserved/Flags
Net_PreparePacket PROC
    mov qword ptr [rcx + 0], rdx
    mov qword ptr [rcx + 8], r8
    mov dword ptr [rcx + 16], r9d
    mov dword ptr [rcx + 20], 0

    mov qword ptr [LocalTick], rdx
    mov qword ptr [LocalCRC], r8

    ret
Net_PreparePacket ENDP

; Returns RAX: 0 = sync OK, 1 = desync detected
Net_VerifySync PROC
    mov rax, qword ptr [LocalCRC]
    cmp rax, qword ptr [PeerCRC]
    je sync_ok

    mov eax, 1
    ret

sync_ok:
    xor eax, eax
    ret
Net_VerifySync ENDP

; Sets LocalTick = RemoteTick after rollback.
; Returns RAX = adopted tick
Net_AdoptRemoteTick PROC
    mov rax, qword ptr [RemoteTick]
    mov qword ptr [LocalTick], rax
    ret
Net_AdoptRemoteTick ENDP

; Returns RAX = local tick
Net_GetLocalTick PROC
    mov rax, qword ptr [LocalTick]
    ret
Net_GetLocalTick ENDP

; Returns RAX = latest remote tick observed
Net_GetLatestRemoteTick PROC
    mov rax, qword ptr [RemoteTick]
    ret
Net_GetLatestRemoteTick ENDP

; Returns RAX = local CRC used by Net_VerifySync
Net_GetLocalCRC PROC
    mov rax, qword ptr [LocalCRC]
    ret
Net_GetLocalCRC ENDP

; Returns RAX = peer CRC used by Net_VerifySync
Net_GetPeerCRC PROC
    mov rax, qword ptr [PeerCRC]
    ret
Net_GetPeerCRC ENDP

; RCX = uint16 host-order port
; RDX = uint32 remote IPv4 in network byte order (e.g., 0x0100007F for 127.0.0.1)
; R8  = uint16 host-order remote port
; Returns EAX=1 success, 0 failure
LockstepNet_Init PROC FRAME
    sub rsp, 268h
    .allocstack 268h
    .endprolog

    mov qword ptr [rsp + 40h], rcx
    mov qword ptr [rsp + 48h], rdx
    mov qword ptr [rsp + 50h], r8

    ; WSAStartup(MAKEWORD(2,2), &wsaData)
    mov ecx, 0202h
    lea rdx, [rsp + 60h]
    call WSAStartup
    test eax, eax
    jnz net_init_fail

    ; socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    mov ecx, AF_INET
    mov edx, SOCK_DGRAM
    mov r8d, IPPROTO_UDP
    call socket
    mov qword ptr [NetSocket], rax
    cmp rax, INVALID_SOCKET
    je net_init_fail_cleanup

    ; local sockaddr_in setup (bind to INADDR_ANY)
    mov word ptr [LocalSockAddr + 0], AF_INET
    mov ax, word ptr [rsp + 40h]
    xchg al, ah
    mov word ptr [LocalSockAddr + 2], ax
    mov dword ptr [LocalSockAddr + 4], 0
    mov qword ptr [LocalSockAddr + 8], 0

    mov rcx, qword ptr [NetSocket]
    lea rdx, LocalSockAddr
    mov r8d, SOCKADDR_IN_SIZE
    call bind
    test eax, eax
    jnz net_init_fail_socket

    ; Set socket nonblocking
    mov dword ptr [rsp + 38h], 1
    mov rcx, qword ptr [NetSocket]
    mov edx, FIONBIO
    lea r8, [rsp + 38h]
    call ioctlsocket
    test eax, eax
    jnz net_init_fail_socket

    ; configure default remote endpoint
    mov rcx, qword ptr [rsp + 48h]
    mov rdx, qword ptr [rsp + 50h]
    call LockstepNet_SetRemote

    mov dword ptr [LocalSequence], 0
    mov dword ptr [RemoteLatestTick], 0
    mov dword ptr [RemoteSeen], 0
    mov dword ptr [DesyncFlag], 0

    mov eax, 1
    add rsp, 268h
    ret

net_init_fail_socket:
    mov rcx, qword ptr [NetSocket]
    cmp rcx, INVALID_SOCKET
    je net_init_fail_cleanup
    call closesocket
    mov qword ptr [NetSocket], INVALID_SOCKET

net_init_fail_cleanup:
    call WSACleanup

net_init_fail:
    xor eax, eax
    add rsp, 268h
    ret
LockstepNet_Init ENDP

; Returns EAX=1 success
LockstepNet_Shutdown PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog

    mov rcx, qword ptr [NetSocket]
    cmp rcx, INVALID_SOCKET
    je @F
    call closesocket
    mov qword ptr [NetSocket], INVALID_SOCKET
@@:
    call WSACleanup
    mov eax, 1
    add rsp, 28h
    ret
LockstepNet_Shutdown ENDP

; RCX = uint32 remote IPv4 network order
; RDX = uint16 host-order remote port
; Returns EAX=1
LockstepNet_SetRemote PROC
    mov word ptr [RemoteSockAddr + 0], AF_INET
    mov ax, dx
    xchg al, ah
    mov word ptr [RemoteSockAddr + 2], ax
    mov dword ptr [RemoteSockAddr + 4], ecx
    mov qword ptr [RemoteSockAddr + 8], 0
    mov eax, 1
    ret
LockstepNet_SetRemote ENDP

; RCX = tick (uint32)
; RDX = crc64
; Returns EAX = bytes sent, or -1 on error
LockstepNet_SendTickCRC PROC FRAME
    sub rsp, 48h
    .allocstack 48h
    .endprolog

    cmp qword ptr [NetSocket], INVALID_SOCKET
    je send_fail

    mov qword ptr [LocalTick], rcx
    mov qword ptr [LocalCRC], rdx

    ; Keep InputDigest defaulted to sequence in the CRC-only send API.
    mov eax, dword ptr [LocalSequence]
    inc eax
    mov dword ptr [LocalSequence], eax

    lea rcx, TxPacket
    mov rdx, qword ptr [LocalTick]
    mov r8, qword ptr [LocalCRC]
    mov r9d, eax
    call Net_PreparePacket

    mov rcx, qword ptr [NetSocket]
    lea rdx, TxPacket
    mov r8d, PACKET_SIZE
    xor r9d, r9d
    lea rax, RemoteSockAddr
    mov qword ptr [rsp + 20h], rax
    mov dword ptr [rsp + 28h], SOCKADDR_IN_SIZE
    call sendto

    add rsp, 48h
    ret

send_fail:
    mov eax, -1
    add rsp, 48h
    ret
LockstepNet_SendTickCRC ENDP

; Polls nonblocking socket and stores packets into ring buffer
; Returns EAX = number of packets ingested this call
LockstepNet_PollRecv PROC FRAME
    sub rsp, 68h
    .allocstack 68h
    .endprolog

    xor r11d, r11d

    cmp qword ptr [NetSocket], INVALID_SOCKET
    je recv_done

recv_loop:
    cmp r11d, 32
    jae recv_done

    mov dword ptr [rsp + 30h], SOCKADDR_IN_SIZE

    mov rcx, qword ptr [NetSocket]
    lea rdx, RxPacket
    mov r8d, PACKET_SIZE
    xor r9d, r9d
    lea rax, [rsp + 40h]
    mov qword ptr [rsp + 20h], rax
    lea rax, [rsp + 30h]
    mov qword ptr [rsp + 28h], rax
    call recvfrom

    cmp eax, -1
    jne recv_have_data

    call WSAGetLastError
    cmp eax, WSAEWOULDBLOCK
    je recv_done
    jmp recv_done

recv_have_data:
    cmp eax, PACKET_SIZE
    jb recv_continue

    mov r10, qword ptr [RxPacket + 0]
    mov rax, qword ptr [RxPacket + 8]

    mov qword ptr [RemoteTick], r10
    mov qword ptr [PeerCRC], rax

    mov r10d, dword ptr [RemoteTick]

    mov ecx, r10d
    and ecx, (RING_SIZE - 1)

    lea r8, RemoteTickRing
    lea r9, RemoteCRCRing
    lea rdx, RemoteValidRing

    mov dword ptr [r8 + rcx*4], r10d
    mov qword ptr [r9 + rcx*8], rax
    mov byte ptr [rdx + rcx], 1

    cmp dword ptr [RemoteSeen], 0
    jne @F
    mov dword ptr [RemoteSeen], 1
    mov dword ptr [RemoteLatestTick], r10d
    jmp recv_count
@@:
    cmp r10d, dword ptr [RemoteLatestTick]
    jb recv_count
    mov dword ptr [RemoteLatestTick], r10d

recv_count:
    inc r11d

recv_continue:
    jmp recv_loop

recv_done:
    mov eax, r11d
    add rsp, 68h
    ret
LockstepNet_PollRecv ENDP

; RCX = tick, RDX = pointer to qword outCRC
; Returns EAX=1 found, 0 not found
LockstepNet_TryGetRemoteCRC PROC
    mov eax, ecx
    and eax, (RING_SIZE - 1)

    lea r8, RemoteValidRing
    lea r9, RemoteTickRing
    lea r10, RemoteCRCRing

    cmp byte ptr [r8 + rax], 0
    je crc_not_found

    mov r11d, dword ptr [r9 + rax*4]
    cmp r11d, ecx
    jne crc_not_found

    mov r11, qword ptr [r10 + rax*8]
    mov qword ptr [rdx], r11
    mov eax, 1
    ret

crc_not_found:
    xor eax, eax
    ret
LockstepNet_TryGetRemoteCRC ENDP

; RCX = tick, RDX = local CRC64
; Returns EAX=1 desync detected, 0 otherwise
LockstepNet_CheckDesync PROC FRAME
    sub rsp, 38h
    .allocstack 38h
    .endprolog

    mov qword ptr [rsp + 28h], rdx

    lea rdx, [rsp + 20h]
    call LockstepNet_TryGetRemoteCRC
    test eax, eax
    jz no_desync

    mov rax, qword ptr [rsp + 20h]
    cmp rax, qword ptr [rsp + 28h]
    je no_desync

    mov dword ptr [DesyncFlag], 1
    mov eax, 1
    add rsp, 38h
    ret

no_desync:
    xor eax, eax
    add rsp, 38h
    ret
LockstepNet_CheckDesync ENDP

; RCX = local tick, EDX = max lead ticks allowed over remote
; Returns EAX=1 if allowed to advance tick, 0 if must stall
LockstepNet_CanAdvance PROC
    cmp dword ptr [RemoteSeen], 0
    je can_advance

    mov eax, dword ptr [RemoteLatestTick]
    add eax, edx
    cmp ecx, eax
    jbe can_advance

    xor eax, eax
    ret

can_advance:
    mov eax, 1
    ret
LockstepNet_CanAdvance ENDP

; Returns EAX = latest remote tick seen
LockstepNet_GetLatestRemoteTick PROC
    mov eax, dword ptr [RemoteLatestTick]
    ret
LockstepNet_GetLatestRemoteTick ENDP

END
