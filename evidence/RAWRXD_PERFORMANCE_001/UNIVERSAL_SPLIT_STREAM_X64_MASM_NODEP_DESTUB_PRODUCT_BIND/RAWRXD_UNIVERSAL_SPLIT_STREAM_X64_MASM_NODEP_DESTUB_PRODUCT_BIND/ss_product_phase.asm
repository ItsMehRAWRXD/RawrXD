option casemap:none
include usr_universal.inc
include ss_real_provider.inc

VirtualAlloc PROTO :QWORD,:QWORD,:DWORD,:DWORD
VirtualFree  PROTO :QWORD,:QWORD,:DWORD

.code

zero_bytes PROC
    ; rcx=ptr rdx=bytes
    xor eax,eax
zb_loop:
    test rdx,rdx
    jz zb_done
    mov byte ptr [rcx],al
    inc rcx
    dec rdx
    jmp zb_loop
zb_done:
    ret
zero_bytes ENDP

; Product bind phase:
;   real shard -> real GGUF tensor extent -> real FILE read -> WARM
;   -> first-party GPU materializer -> residency HOT commit
;   -> explicit Deep2/Vulkan interop hard failure.
;
; It never initializes the legacy full-model BenchmarkHarness.
ss_product_split_phase PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp,350h
    .allocstack 350h
    .endprolog

    mov r12,rcx                       ; args
    mov r13,rdx                       ; result
    test r12,r12
    jz ssp_bad
    test r13,r13
    jz ssp_bad

    mov rcx,r13
    mov rdx,SIZEOF SSPhaseResult
    call zero_bytes
    mov qword ptr [r13].SSPhaseResult.full_model_init_bypassed,1
    mov qword ptr [r13].SSPhaseResult.deep2_consume_status,SS_DEEP2_CONSUME_NOT_RUN
    mov qword ptr [r13].SSPhaseResult.token_commit_status,SS_TOKEN_COMMIT_NOT_RUN

    mov rax,[r12].SSPhaseArgs.shard1_path
    test rax,rax
    jz ssp_bad_result
    mov rax,[r12].SSPhaseArgs.gpu_backend
    test rax,rax
    jz ssp_backend_fail

    lea r14,[rsp+40h]                 ; SSFileCtx
    mov rcx,[r12].SSPhaseArgs.shard1_path
    mov rdx,r14
    call ss_file_open
    test eax,eax
    jnz ssp_fail_code

    lea r15,[rsp+60h]                 ; SSTensorDesc
    mov rcx,r14
    mov rdx,r15
    call ss_find_anchor_tensor
    test eax,eax
    jnz ssp_close_fail
    mov qword ptr [r13].SSPhaseResult.gguf_anchor_found,1
    mov rax,[r15].SSTensorDesc.which_name
    mov [r13].SSPhaseResult.anchor_which,rax
    mov rax,[r15].SSTensorDesc.absolute_offset
    mov [r13].SSPhaseResult.file_offset,rax
    mov rax,[r15].SSTensorDesc.storage_bytes
    mov [r13].SSPhaseResult.region_bytes,rax

    lea rbx,[rsp+0C0h]                ; USRContext
    mov rcx,rbx
    mov rdx,[r12].SSPhaseArgs.host_budget
    mov r8,[r12].SSPhaseArgs.gpu_budget
    call usr_ctx_init
    test eax,eax
    jnz ssp_close_fail

    mov rcx,rbx
    mov rdx,[r12].SSPhaseArgs.model_id
    mov r8,[r12].SSPhaseArgs.model_generation
    call usr_switch_model
    test eax,eax
    jnz ssp_close_fail

    mov rcx,rbx
    mov rdx,[r12].SSPhaseArgs.op_ticket
    mov r8,[r12].SSPhaseArgs.owner_cookie
    call usr_begin_op
    test eax,eax
    jnz ssp_close_fail

    lea rsi,[rsp+180h]                ; USRRegion
    mov rcx,rsi
    mov rdx,SIZEOF USRRegion
    call zero_bytes
    mov rax,[r12].SSPhaseArgs.model_id
    mov [rsi].USRRegion.model_id,rax
    mov rax,[r12].SSPhaseArgs.model_generation
    mov [rsi].USRRegion.model_generation,rax
    mov rax,[r15].SSTensorDesc.absolute_offset
    mov [rsi].USRRegion.region_id,rax
    mov qword ptr [rsi].USRRegion.provider_id,SS_PROVIDER_FILE
    mov rax,[r15].SSTensorDesc.absolute_offset
    mov [rsi].USRRegion.file_offset,rax
    mov rax,[r15].SSTensorDesc.storage_bytes
    mov [rsi].USRRegion.byte_length,rax
    mov dword ptr [rsi].USRRegion.state,USR_COLD
    mov dword ptr [rsi].USRRegion.request_reason,USR_REQ_CURRENT_STATIC

    mov rcx,rbx
    mov rdx,[rsi].USRRegion.byte_length
    call usr_host_reserve
    test eax,eax
    jnz ssp_endop_fail

    xor ecx,ecx
    mov rdx,[rsi].USRRegion.byte_length
    mov r8d,MEM_COMMIT or MEM_RESERVE
    mov r9d,PAGE_READWRITE
    call VirtualAlloc
    test rax,rax
    jz ssp_host_release_fail
    mov [rsp+2F0h],rax                ; host allocation

    mov rcx,rbx
    mov rdx,rsi
    mov r8,[r12].SSPhaseArgs.op_ticket
    mov r9,[r12].SSPhaseArgs.owner_cookie
    call usr_region_prepare
    cmp eax,USR_PREP_CLAIM_WIN
    jne ssp_free_host_fail

    mov rcx,r14
    mov rdx,[rsi].USRRegion.file_offset
    mov r8,[rsi].USRRegion.byte_length
    mov r9,[rsp+2F0h]
    lea rax,[rsp+2F8h]                ; physical bytes
    mov [rsp+20h],rax
    call ss_file_read_exact
    test eax,eax
    jnz ssp_mg_fail

    mov rcx,rsi
    mov rdx,[rsp+2F0h]
    mov r8,[rsi].USRRegion.byte_length
    mov r9,[rsp+2F8h]
    call usr_commit_warm
    test eax,eax
    jnz ssp_mg_fail
    mov qword ptr [r13].SSPhaseResult.warm_pass,1

    mov rcx,rsi
    call usr_pin
    test eax,eax
    jnz ssp_free_host_fail

    ; First-party GPU backend materializes bytes but cannot define HOT.
    mov rdi,[r12].SSPhaseArgs.gpu_backend
    mov rax,[rdi].SSGpuBackend.promote_fn
    test rax,rax
    jz ssp_unpin_backend
    lea r10,[rsp+300h]                ; SSDeviceMaterialization
    mov rcx,r10
    mov rdx,SIZEOF SSDeviceMaterialization
    call zero_bytes

    mov rax,[rdi].SSGpuBackend.promote_fn
    mov rcx,[rdi].SSGpuBackend.ctx
    mov rdx,[rsp+2F0h]
    mov r8,[rsi].USRRegion.byte_length
    mov r9,[rsi].USRRegion.residency_generation
    lea r10,[rsp+300h]
    mov [rsp+20h],r10
    call rax
    test eax,eax
    jnz ssp_unpin_backend

    cmp qword ptr [rsp+300h].SSDeviceMaterialization.completed,1
    jne ssp_gpu_proof_fail
    cmp qword ptr [rsp+300h].SSDeviceMaterialization.gpu,1
    jne ssp_gpu_proof_fail
    cmp qword ptr [rsp+300h].SSDeviceMaterialization.readback_parity,1
    jne ssp_gpu_proof_fail
    mov rax,[rsp+300h].SSDeviceMaterialization.bytes
    cmp rax,[rsi].USRRegion.byte_length
    jne ssp_gpu_proof_fail
    cmp qword ptr [rsp+300h].SSDeviceMaterialization.device_handle,0
    je ssp_gpu_proof_fail

    ; Only residency commits HOT, after backend completion/parity.
    mov rcx,rsi
    mov rdx,[rsi].USRRegion.residency_generation
    mov r8,[rsp+300h].SSDeviceMaterialization.device_id
    mov r9,[rsp+300h].SSDeviceMaterialization.allocation_generation
    mov rax,[rsp+300h].SSDeviceMaterialization.device_handle
    mov [rsp+20h],rax
    mov rax,[rsp+300h].SSDeviceMaterialization.bytes
    mov [rsp+28h],rax
    call usr_hot_commit
    test eax,eax
    jnz ssp_gpu_proof_fail

    mov qword ptr [r13].SSPhaseResult.hot_pass,1
    mov qword ptr [r13].SSPhaseResult.gpu,1
    mov rax,[rsp+300h].SSDeviceMaterialization.pci_device
    mov [r13].SSPhaseResult.pci_device,rax
    mov qword ptr [r13].SSPhaseResult.readback_parity,1

    ; Second touch must be a HOT hit with no new provider/GPU call.
    mov rcx,rbx
    mov rdx,rsi
    mov r8,[r12].SSPhaseArgs.op_ticket
    mov r9,[r12].SSPhaseArgs.owner_cookie
    call usr_region_prepare
    cmp eax,USR_PREP_HOT_HIT
    jne ssp_gpu_proof_fail

    ; Copy observed counters before cleanup.
    mov rax,[rsi].USRRegion.physical_reads
    mov [r13].SSPhaseResult.physical_reads,rax
    mov rax,[rsi].USRRegion.physical_bytes
    mov [r13].SSPhaseResult.physical_bytes,rax
    mov rax,[rsi].USRRegion.mg_loads
    mov [r13].SSPhaseResult.mg_loads,rax
    mov rax,[rsi].USRRegion.mg_bytes
    mov [r13].SSPhaseResult.mg_bytes,rax
    mov rax,[rsi].USRRegion.hot_hits
    mov [r13].SSPhaseResult.hot_hits,rax

    ; Import+model-op while HOT live. 2=import 3=consume 4=embd model op.
    mov eax,dword ptr [r15].SSTensorDesc.tensor_type
    mov qword ptr [rsp+300h].SSDeviceMaterialization.tensor_type,rax
    mov rax,[r15].SSTensorDesc.dim0
    mov [rsp+300h].SSDeviceMaterialization.dim0,rax
    mov rax,[r15].SSTensorDesc.dim1
    mov [rsp+300h].SSDeviceMaterialization.dim1,rax
    mov rax,[r15].SSTensorDesc.which_name
    mov [rsp+300h].SSDeviceMaterialization.which_name,rax
    mov rax,[r15].SSTensorDesc.element_count
    mov [rsp+300h].SSDeviceMaterialization.element_count,rax
    mov rax,[rdi].SSGpuBackend.consume_fn
    test rax,rax
    jz ssp_no_consume
    mov rcx,[rdi].SSGpuBackend.ctx
    lea rdx,[rsp+300h]
    call rax
    cmp eax,SS_DEEP2_MODEL_OP
    je ssp_model_ok
    cmp eax,SS_DEEP2_CONSUMED
    je ssp_consume_ok
    cmp eax,SS_DEEP2_IMPORTED
    jne ssp_no_consume
    mov qword ptr [r13].SSPhaseResult.deep2_consume_status,SS_DEEP2_IMPORTED
    jmp ssp_after_consume
ssp_model_ok:
    mov qword ptr [r13].SSPhaseResult.deep2_consume_status,SS_DEEP2_MODEL_OP
    jmp ssp_after_consume
ssp_consume_ok:
    mov qword ptr [r13].SSPhaseResult.deep2_consume_status,SS_DEEP2_CONSUMED
    jmp ssp_after_consume
ssp_no_consume:
    mov qword ptr [r13].SSPhaseResult.deep2_consume_status,SS_DEEP2_CONSUME_NOT_RUN
ssp_after_consume:

    ; Cleanly invalidate HOT and free backend allocation.
    mov rcx,rsi
    mov rdx,[rsp+300h].SSDeviceMaterialization.allocation_generation
    call usr_hot_reset

    mov rax,[rdi].SSGpuBackend.release_fn
    test rax,rax
    jz ssp_after_gpu_release
    mov rcx,[rdi].SSGpuBackend.ctx
    mov rdx,[rsp+300h].SSDeviceMaterialization.device_handle
    mov r8,[rsp+300h].SSDeviceMaterialization.allocation_generation
    call rax
ssp_after_gpu_release:
    mov rcx,rsi
    call usr_unpin

    ; Logits/token remain unreachable even after imported model op.
    mov qword ptr [r13].SSPhaseResult.token_commit_status,SS_TOKEN_COMMIT_NOT_RUN
    mov eax,SS_E_DEEP2_INTEROP
    cmp qword ptr [r13].SSPhaseResult.deep2_consume_status,SS_DEEP2_MODEL_OP
    jne ssp_check_consumed
    mov eax,SS_E_LMHEAD_HOLD
    jmp ssp_set_phase_rc
ssp_check_consumed:
    cmp qword ptr [r13].SSPhaseResult.deep2_consume_status,SS_DEEP2_CONSUMED
    jne ssp_check_imported
    mov eax,SS_E_LOGITS_HOLD
    jmp ssp_set_phase_rc
ssp_check_imported:
    cmp qword ptr [r13].SSPhaseResult.deep2_consume_status,SS_DEEP2_IMPORTED
    jne ssp_set_phase_rc
    mov eax,SS_E_PRIMITIVE_HOLD
ssp_set_phase_rc:
    mov [r13].SSPhaseResult.phase_rc,rax

    mov rcx,rbx
    mov rdx,[r12].SSPhaseArgs.op_ticket
    mov r8,[r12].SSPhaseArgs.owner_cookie
    call usr_end_op

    mov rcx,[rsp+2F0h]
    xor edx,edx
    mov r8d,MEM_RELEASE
    call VirtualFree

    mov rcx,rbx
    mov rdx,[rsi].USRRegion.byte_length
    call usr_host_release

    mov rcx,r14
    call ss_file_close

    mov eax,dword ptr [r13].SSPhaseResult.phase_rc
    jmp ssp_done

ssp_gpu_proof_fail:
    mov eax,SS_E_GPU_PROOF
    jmp ssp_unpin_fail_code
ssp_unpin_backend:
    mov eax,SS_E_BACKEND
ssp_unpin_fail_code:
    mov [rsp+2E8h],rax
    mov rcx,rsi
    call usr_unpin
    mov eax,dword ptr [rsp+2E8h]
    jmp ssp_free_host_fail

ssp_mg_fail:
    mov [rsp+2E8h],rax
    mov rcx,rsi
    call usr_fail_mg
    mov eax,dword ptr [rsp+2E8h]
    jmp ssp_free_host_fail

ssp_free_host_fail:
    mov [rsp+2E8h],rax
    mov rcx,[rsp+2F0h]
    test rcx,rcx
    jz ssp_host_release_fail_code
    xor edx,edx
    mov r8d,MEM_RELEASE
    call VirtualFree
ssp_host_release_fail_code:
    mov eax,dword ptr [rsp+2E8h]
ssp_host_release_fail:
    mov [rsp+2E8h],rax
    mov rcx,rbx
    mov rdx,[rsi].USRRegion.byte_length
    call usr_host_release
    mov eax,dword ptr [rsp+2E8h]

ssp_endop_fail:
    mov [rsp+2E8h],rax
    mov rcx,rbx
    mov rdx,[r12].SSPhaseArgs.op_ticket
    mov r8,[r12].SSPhaseArgs.owner_cookie
    call usr_end_op
    mov eax,dword ptr [rsp+2E8h]
    jmp ssp_close_fail

ssp_backend_fail:
    mov eax,SS_E_BACKEND
    jmp ssp_fail_code

ssp_close_fail:
    mov [rsp+2E8h],rax
    mov rcx,r14
    call ss_file_close
    mov eax,dword ptr [rsp+2E8h]
ssp_fail_code:
    mov [r13].SSPhaseResult.phase_rc,rax
    jmp ssp_done

ssp_bad_result:
    mov eax,SS_E_INVALID
    mov [r13].SSPhaseResult.phase_rc,rax
    jmp ssp_done
ssp_bad:
    mov eax,SS_E_INVALID

ssp_done:
    add rsp,350h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
ss_product_split_phase ENDP

END
