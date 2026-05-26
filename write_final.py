import os

with open('D:/rawrxd/src/Sovereign_Common.inc', 'w') as f:
    f.write('''ifndef SOVEREIGN_COMMON_INC
SOVEREIGN_COMMON_INC equ 1

; Global External Offsets
extrn pTPS : qword
extrn pGov : qword
extrn pSwarm : qword
extrn pWatchdog : qword

; WinAPI Kernel Procs
extrn OpenFileMappingA : proc
extrn MapViewOfFile : proc
extrn UnmapViewOfFile : proc
extrn ExitProcess : proc
extrn GetTickCount64 : proc
extrn Sleep : proc
extrn GetStdHandle : proc
extrn WriteFile : proc
extrn WriteConsoleA : proc
extrn OutputDebugStringA : proc
extrn CloseHandle : proc
extrn CreateFileA : proc
extrn CreateFileMappingA : proc

include Sovereign_Procs.inc
endif
''')

with open('D:/rawrxd/src/Sovereign_Alpha.asm', 'w') as f:
    f.write('''; Sovereign_Alpha.asm — Production
include Sovereign_Common.inc
.code
PUBLIC Alpha_Execute
Alpha_Execute proc
    mov rcx, [pTPS]
    test rcx, rcx
    jz @no_signal
    ; AVX2 Spread Logic
    vmovupd ymm0, ymmword ptr [rcx]
    vunpckhpd ymm1, ymm0, ymm0
    vsubpd ymm1, ymm1, ymm0
    ; Threshold check 0.05
    mov rax, 03FA999999999999Ah
    vmovq xmm3, rax
    vpbroadcastq ymm3, xmm3
    vcmpltpd ymm4, ymm1, ymm3
    vmovmskpd eax, ymm4
    test eax, eax
    jnz @signal_buy
@no_signal:
    xor rax, rax
    ret
@signal_buy:
    mov rax, 1
    ret
Alpha_Execute endp
end
''')

with open('D:/rawrxd/src/Sovereign_Finisher.asm', 'w') as f:
    f.write('''; Sovereign_Finisher.asm — Production
include Sovereign_Common.inc
.data
msg_online db "SOVEREIGN_ENGINE_ONLINE", 13, 10
len_online equ $ - msg_online
.code
PUBLIC main
main proc
    sub rsp, 40
    call Sovereign_Init
    test rax, rax
    jz @fail
    
    ; Signal Online
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_online]
    mov r8, len_online
    lea r9, [rsp+32]
    mov qword ptr [rsp+32], 0
    call WriteFile

agent_loop:
    call Governor_GetStatus
    cmp eax, 2
    je @fail
    call SwarmLink_SyncConsensus
    test rax, rax
    jz @skip
    call Alpha_Execute
    test rax, rax
    jz @skip
    mov rcx, rax
    call Ticker_EmitOrder
@skip:
    call Watchdog_Pet
    call Monitor_HealthCheck
    test rax, rax
    jz @fail
    mov rcx, 1
    call Sleep
    jmp agent_loop
@fail:
    call Sovereign_Shutdown
main endp
end
''')
