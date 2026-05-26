; Sovereign_SwarmLink.asm — Socket Dispatch
include Sovereign_Common.inc
extern send : proc

.code
PUBLIC SwarmLink_Send
SwarmLink_Send PROC
    ; RCX=Socket, RDX=Buffer, R8=Len
    sub rsp, 40
    xor r9, r9          ; Flags=0
    call send
    add rsp, 40
    ret
SwarmLink_Send ENDP

PUBLIC SwarmLink_SyncConsensus
SwarmLink_SyncConsensus proc
    mov rax, [pSwarm]
    test rax, rax
    jz @fail
    mov eax, [rax]
    cmp eax, 1
    je @success
@fail:
    xor rax, rax
    ret
@success:
    mov rax, 1
    ret
SwarmLink_SyncConsensus endp
end