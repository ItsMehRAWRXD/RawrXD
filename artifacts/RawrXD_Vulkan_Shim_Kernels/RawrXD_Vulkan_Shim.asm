; ============================================================================
; RawrXD_Vulkan_Shim.asm — Sovereign Vulkan Dispatch Shim
; ============================================================================
; Zero-dependency x64 MASM bridge layer.
; Uses function pointers resolved by C++ control plane.
; ============================================================================

        OPTION  CASEMAP:NONE
        OPTION  LANGUAGE:C

        EXTERN  p_vkCmdDispatch:QWORD
        EXTERN  p_vkQueueSubmit:QWORD
        EXTERN  p_vkWaitForFences:QWORD
        EXTERN  p_vkCmdBindPipeline:QWORD
        EXTERN  p_vkCmdBindDescriptorSets:QWORD
        EXTERN  p_vkCmdPushConstants:QWORD
        EXTERN  p_vkCmdDispatchIndirect:QWORD
        EXTERN  p_vkQueueWaitIdle:QWORD
        EXTERN  p_vkResetFences:QWORD
        EXTERN  p_vkGetSemaphoreCounterValue:QWORD

SAFE_CALL_PTR MACRO ptr_sym
LOCAL null_ptr, done_call
        mov     r11, ptr_sym
        test    r11, r11
        jz      null_ptr
        call    r11
        jmp     done_call
null_ptr:
        mov     eax, 1
done_call:
ENDM

        .CODE

; ----------------------------------------------------------------------------
; RawrXD_DispatchMatMul_Asm
; rcx = instance, rdx = desc
; ----------------------------------------------------------------------------
RawrXD_DispatchMatMul_Asm PROC FRAME
        push    rbx
        .pushreg rbx
        sub     rsp, 40
        .allocstack 40
        .endprolog

        mov     rbx, rdx
        test    rbx, rbx
        jz      dispatch_fail

        ; C++ pre-resolves these handles into desc for ASM fast-path.
        ; +0x68 pipeline, +0x70 layout, +0x78 descriptor_set, +0x30 cmd_buffer
        mov     rcx, [rbx + 30h]
        mov     edx, 1
        mov     r8,  [rbx + 68h]
        SAFE_CALL_PTR p_vkCmdBindPipeline
        test    eax, eax
        jnz     dispatch_fail

        mov     rcx, [rbx + 30h]
        mov     edx, 1
        mov     r8,  [rbx + 70h]
        xor     r9,  r9
        mov     dword ptr [rsp + 20h], 1
        lea     rax, [rbx + 78h]
        mov     [rsp + 28h], rax
        xor     eax, eax
        mov     [rsp + 30h], rax
        mov     [rsp + 38h], rax
        SAFE_CALL_PTR p_vkCmdBindDescriptorSets
        test    eax, eax
        jnz     dispatch_fail

        mov     rcx, [rbx + 30h]
        mov     rdx, [rbx + 70h]
        mov     r8d, 20h
        xor     r9,  r9
        mov     dword ptr [rsp + 20h], 14h
        lea     rax, [rbx + 80h]
        mov     [rsp + 28h], rax
        SAFE_CALL_PTR p_vkCmdPushConstants
        test    eax, eax
        jnz     dispatch_fail

        mov     ecx, [rbx + 48h]
        add     ecx, 15
        shr     ecx, 4
        mov     edx, [rbx + 4Ch]
        add     edx, 15
        shr     edx, 4
        mov     r8d, 1
        mov     rax, [rbx + 30h]
        mov     rcx, rax
        SAFE_CALL_PTR p_vkCmdDispatch
        test    eax, eax
        jnz     dispatch_fail

        xor     eax, eax
        jmp     dispatch_exit

dispatch_fail:
        mov     eax, 1

dispatch_exit:
        add     rsp, 40
        pop     rbx
        ret
RawrXD_DispatchMatMul_Asm ENDP

; ----------------------------------------------------------------------------
; RawrXD_DispatchRMSNorm_Asm
; rcx = instance, rdx = args (packed submit args)
; ----------------------------------------------------------------------------
RawrXD_DispatchRMSNorm_Asm PROC FRAME
        push    rbx
        .pushreg rbx
        sub     rsp, 40
        .allocstack 40
        .endprolog

        mov     rbx, rdx
        test    rbx, rbx
        jz      rms_fail

        mov     rcx, [rbx + 10h]            ; queue
        mov     edx, 1                      ; submitCount
        lea     r8,  [rbx + 28h]            ; VkSubmitInfo*
        mov     r9,  [rbx + 08h]            ; fence
        SAFE_CALL_PTR p_vkQueueSubmit
        test    eax, eax
        jnz     rms_fail

        xor     eax, eax
        jmp     rms_exit

rms_fail:
        mov     eax, 1

rms_exit:
        add     rsp, 40
        pop     rbx
        ret
RawrXD_DispatchRMSNorm_Asm ENDP

; ----------------------------------------------------------------------------
; RawrXD_KVAppend_Asm
; rcx = instance, rdx = desc
; ----------------------------------------------------------------------------
RawrXD_KVAppend_Asm PROC FRAME
        push    rbx
        .pushreg rbx
        sub     rsp, 40
        .allocstack 40
        .endprolog

        mov     rbx, rdx
        test    rbx, rbx
        jz      kv_fail

        mov     rcx, [rbx + 30h]
        mov     edx, 1
        mov     r8,  [rbx + 40h]
        SAFE_CALL_PTR p_vkCmdBindPipeline
        test    eax, eax
        jnz     kv_fail

        mov     ecx, [rbx + 30h]
        mov     edx, 1
        mov     r8d, 1
        mov     rcx, [rbx + 30h]
        SAFE_CALL_PTR p_vkCmdDispatch
        test    eax, eax
        jnz     kv_fail

        xor     eax, eax
        jmp     kv_exit

kv_fail:
        mov     eax, 1

kv_exit:
        add     rsp, 40
        pop     rbx
        ret
RawrXD_KVAppend_Asm ENDP

; ----------------------------------------------------------------------------
; RawrXD_SubmitGraph_Asm
; rcx = instance, rdx = SubmitGraphInfo*
; ----------------------------------------------------------------------------
RawrXD_SubmitGraph_Asm PROC FRAME
        push    rbx
        .pushreg rbx
        sub     rsp, 56
        .allocstack 56
        .endprolog

        mov     rbx, rdx
        test    rbx, rbx
        jz      graph_fail

        mov     rcx, [rbx + 20h]            ; queue
        mov     edx, 1                      ; submit count
        lea     r8,  [rbx + 28h]            ; VkSubmitInfo*
        xor     r9,  r9
        SAFE_CALL_PTR p_vkQueueSubmit
        test    eax, eax
        jnz     graph_fail

        xor     eax, eax
        jmp     graph_exit

graph_fail:
        mov     eax, 1

graph_exit:
        add     rsp, 56
        pop     rbx
        ret
RawrXD_SubmitGraph_Asm ENDP

; ----------------------------------------------------------------------------
; RawrXD_Wait_Asm
; rcx = instance, rdx = timeout_ns
; ----------------------------------------------------------------------------
RawrXD_Wait_Asm PROC FRAME
        push    rbx
        .pushreg rbx
        sub     rsp, 40
        .allocstack 40
        .endprolog

        mov     rbx, rdx
        ; Fallback fence wait path
        mov     rcx, [rcx + 20h]            ; device
        mov     edx, 1
        lea     r8,  [rcx + 38h]
        mov     r9d, 1
        mov     [rsp + 20h], rbx
        SAFE_CALL_PTR p_vkWaitForFences
        test    eax, eax
        jnz     wait_fail

        xor     eax, eax
        jmp     wait_exit

wait_fail:
        mov     eax, 1

wait_exit:
        add     rsp, 40
        pop     rbx
        ret
RawrXD_Wait_Asm ENDP

; ----------------------------------------------------------------------------
; RawrXD_QueueWaitIdle_Asm
; rcx = queue handle
; ----------------------------------------------------------------------------
RawrXD_QueueWaitIdle_Asm PROC FRAME
        SAFE_CALL_PTR p_vkQueueWaitIdle
        ret
RawrXD_QueueWaitIdle_Asm ENDP

        .DATA
ALIGN 16
RawrXD_DispatchTable LABEL QWORD
        QWORD RawrXD_DispatchMatMul_Asm
        QWORD RawrXD_KVAppend_Asm
        QWORD RawrXD_DispatchRMSNorm_Asm
        QWORD RawrXD_SubmitGraph_Asm
        QWORD RawrXD_Wait_Asm
        QWORD 0

        END
