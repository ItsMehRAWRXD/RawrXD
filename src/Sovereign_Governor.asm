; Sovereign_Governor.asm — Production
include Sovereign_Common.inc

.code
PUBLIC Governor_UpdateState
Governor_UpdateState PROC
    ; Logic: Monitor slot saturation
    ; If saturation > 80%, transition to THROTTLE
    mov rax, [pGov]
    mov edx, [rax + GOV_OFFSET_FLAGS]
    
    cmp edx, 80
    jl @set_nominal
    
    ; Transition to THROTTLE
    mov dword ptr [rax + GOV_OFFSET_STATE], GOV_STATE_THROTTLE
    ret
@set_nominal:
    mov dword ptr [rax + GOV_OFFSET_STATE], GOV_STATE_NOMINAL
    ret
Governor_UpdateState ENDP

PUBLIC Governor_GetStatus
Governor_GetStatus proc
    mov rax, [pGov]
    test rax, rax
    jz @fail
    mov eax, [rax]
    ret
@fail:
    xor rax, rax
    ret
Governor_GetStatus endp

PUBLIC Governor_SetState
Governor_SetState proc
    mov rdx, [pGov]
    test rdx, rdx
    jz @done
    mov [rdx], ecx
@done:
    ret
Governor_SetState endp
end