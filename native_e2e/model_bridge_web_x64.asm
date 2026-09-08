; model_bridge_web_x64.asm
option casemap:none
include rawr_native_e2e.inc
EXTERN ModelBridge_GetCapabilities:PROC
EXTERN ModelBridge_GetProfileByName:PROC
.code

RawrNative_ModelBridgeCapabilities proc public
    jmp ModelBridge_GetCapabilities
RawrNative_ModelBridgeCapabilities endp

; RCX=model name, RDX=RawrNativeProfileInfo*
RawrNative_ModelBridgeResolveProfile proc public
    push rbx
    push rsi
    sub rsp, 28h
    mov rbx, rdx
    test rcx, rcx
    jz short RMB_Fail
    test rbx, rbx
    jz short RMB_Fail
    call ModelBridge_GetProfileByName
    test rax, rax
    jz short RMB_Fail
    mov rsi, rax
    mov eax, dword ptr [rsi+MBP_MODEL_ID]
    mov dword ptr [rbx+RNPI_PROFILE_ID], eax
    mov eax, dword ptr [rsi+MBP_ENGINE_MODE]
    mov dword ptr [rbx+RNPI_ENGINE_MODE], eax
    mov eax, dword ptr [rsi+MBP_NUM_LAYERS]
    mov dword ptr [rbx+RNPI_NUM_LAYERS], eax
    mov eax, dword ptr [rsi+MBP_CONTEXT_DEFAULT]
    mov dword ptr [rbx+RNPI_CONTEXT_DEFAULT], eax
    mov eax, dword ptr [rsi+MBP_CONTEXT_MAX]
    mov dword ptr [rbx+RNPI_CONTEXT_MAX], eax
    mov eax, dword ptr [rsi+MBP_MAX_TOKENS]
    mov dword ptr [rbx+RNPI_MAX_TOKENS], eax
    mov eax, dword ptr [rsi+MBP_TIER]
    mov dword ptr [rbx+RNPI_TIER], eax
    mov eax, dword ptr [rsi+MBP_QUANT_TYPE]
    mov dword ptr [rbx+RNPI_QUANT_TYPE], eax
    mov eax, dword ptr [rsi+MBP_RAM_MB]
    mov dword ptr [rbx+RNPI_RAM_MB], eax
    mov eax, dword ptr [rsi+MBP_VRAM_MB]
    mov dword ptr [rbx+RNPI_VRAM_MB], eax
    xor eax, eax
    jmp short RMB_Done
RMB_Fail:
    mov eax, 1
RMB_Done:
    add rsp, 28h
    pop rsi
    pop rbx
    ret
RawrNative_ModelBridgeResolveProfile endp
end
