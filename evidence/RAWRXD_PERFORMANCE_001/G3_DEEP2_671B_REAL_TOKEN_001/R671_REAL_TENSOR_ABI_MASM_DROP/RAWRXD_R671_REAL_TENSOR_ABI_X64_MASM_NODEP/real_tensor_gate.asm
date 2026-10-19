option casemap:none
include real_tensor_gate.inc

.code
G3Deep2R671RealTokenEvaluate PROC FRAME
    sub rsp,20h
    .allocstack 20h
    .endprolog
    test rcx,rcx
    jz gt_done
    test rdx,rdx
    jz gt_done
    mov qword ptr [rdx].RealTensorGateResult.pass,0

    cmp [rcx].RealTensorGateRaw.real_model,1
    jne gt_done
    cmp [rcx].RealTensorGateRaw.synthetic_tensor,0
    jne gt_done
    cmp [rcx].RealTensorGateRaw.r671_acquire_count,0
    je gt_done
    cmp [rcx].RealTensorGateRaw.r671_failed_acquires,0
    jne gt_done
    cmp [rcx].RealTensorGateRaw.full_tensor_fallback_count,0
    jne gt_done
    cmp [rcx].RealTensorGateRaw.wsc15_pass,1
    jne gt_done
    cmp [rcx].RealTensorGateRaw.working_set_contract_pass,1
    jne gt_done
    cmp [rcx].RealTensorGateRaw.tokencode_authorized,1
    jne gt_done
    cmp [rcx].RealTensorGateRaw.tokensdecoded_authorized,1
    jne gt_done
    cmp [rcx].RealTensorGateRaw.generated_tokens,1
    jne gt_done
    cmp [rcx].RealTensorGateRaw.token_commit_count,1
    jne gt_done
    cmp [rcx].RealTensorGateRaw.decode_commit_count,1
    jne gt_done
    mov rax,[rcx].RealTensorGateRaw.peak_mapped_bytes
    cmp rax,[rcx].RealTensorGateRaw.configured_bound
    ja gt_done
    cmp [rcx].RealTensorGateRaw.newly_mapped_bytes,0
    je gt_done
    cmp [rcx].RealTensorGateRaw.stale_generation_faults,0
    jne gt_done
    cmp [rcx].RealTensorGateRaw.duplicate_commit_count,0
    jne gt_done
    cmp [rcx].RealTensorGateRaw.nonfinite_output_count,0
    jne gt_done

    mov qword ptr [rdx].RealTensorGateResult.pass,1
gt_done:
    xor eax,eax
    add rsp,20h
    ret
G3Deep2R671RealTokenEvaluate ENDP
END
