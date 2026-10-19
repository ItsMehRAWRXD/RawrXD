option casemap:none
include r671_bytes15.inc

.code

R671BytesEvaluate PROC FRAME
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
    sub rsp,20h
    .allocstack 20h
    .endprolog

    mov rsi,rcx
    mov rdi,rdx

    ; Clear result.
    xor eax,eax
    mov rcx,SIZEOF R671BytesResult
    mov rdx,rdi
rb_zero:
    test rcx,rcx
    jz rb_zero_done
    mov byte ptr [rdx],al
    inc rdx
    dec rcx
    jmp rb_zero
rb_zero_done:

    test rsi,rsi
    jz rb_done
    test rdi,rdi
    jz rb_done

    ; All witnesses begin NOT_RUN.
    xor ebx,ebx
rb_init:
    cmp ebx,RB_WITNESS_COUNT
    jae rb_eval
    mov qword ptr [rdi].R671BytesResult.witness_state[rbx*8],RB_NOT_RUN
    inc ebx
    jmp rb_init

rb_eval:
    cmp [rsi].R671BytesRaw.run_observed,0
    je rb_count

    mov r12,[rsi].R671BytesRaw.generation_id
    mov r13,[rsi].R671BytesRaw.requested_bytes

; RB01 same-generation lease.
    test r12,r12
    jz rb01_fail
    cmp [rsi].R671BytesRaw.lease_generation_id,r12
    jne rb01_fail
    mov qword ptr [rdi].R671BytesResult.witness_state[RB01_GENERATION_BOUND*8],RB_PASS
    jmp rb02
rb01_fail:
    mov qword ptr [rdi].R671BytesResult.witness_state[RB01_GENERATION_BOUND*8],RB_FAIL

; RB02 offset+bytes must not overflow and must be inside file.
rb02:
    mov rax,[rsi].R671BytesRaw.file_offset
    add rax,r13
    jc rb02_fail
    cmp rax,[rsi].R671BytesRaw.file_bytes
    ja rb02_fail
    mov qword ptr [rdi].R671BytesResult.witness_state[RB02_FILE_RANGE_VALID*8],RB_PASS
    jmp rb03
rb02_fail:
    mov qword ptr [rdi].R671BytesResult.witness_state[RB02_FILE_RANGE_VALID*8],RB_FAIL

; RB03 requested byte length nonzero.
rb03:
    test r13,r13
    jz rb03_fail
    mov qword ptr [rdi].R671BytesResult.witness_state[RB03_BYTE_LENGTH_NONZERO*8],RB_PASS
    jmp rb04
rb03_fail:
    mov qword ptr [rdi].R671BytesResult.witness_state[RB03_BYTE_LENGTH_NONZERO*8],RB_FAIL

; RB04 lease active.
rb04:
    cmp [rsi].R671BytesRaw.lease_active,1
    jne rb04_fail
    mov qword ptr [rdi].R671BytesResult.witness_state[RB04_LEASE_ACTIVE*8],RB_PASS
    jmp rb05
rb04_fail:
    mov qword ptr [rdi].R671BytesResult.witness_state[RB04_LEASE_ACTIVE*8],RB_FAIL

; RB05 lease offset must equal requested offset.
rb05:
    mov rax,[rsi].R671BytesRaw.file_offset
    cmp [rsi].R671BytesRaw.lease_request_offset,rax
    jne rb05_fail
    mov qword ptr [rdi].R671BytesResult.witness_state[RB05_LEASE_OFFSET_MATCH*8],RB_PASS
    jmp rb06
rb05_fail:
    mov qword ptr [rdi].R671BytesResult.witness_state[RB05_LEASE_OFFSET_MATCH*8],RB_FAIL

; RB06 lease covers requested bytes.
rb06:
    mov rax,[rsi].R671BytesRaw.lease_bytes
    cmp rax,r13
    jb rb06_fail
    mov qword ptr [rdi].R671BytesResult.witness_state[RB06_LEASE_BYTE_COVERAGE*8],RB_PASS
    jmp rb07
rb06_fail:
    mov qword ptr [rdi].R671BytesResult.witness_state[RB06_LEASE_BYTE_COVERAGE*8],RB_FAIL

; RB07 ptr must be exactly view_base + delta, with overflow checked.
rb07:
    mov rax,[rsi].R671BytesRaw.lease_view_base
    test rax,rax
    jz rb07_fail
    add rax,[rsi].R671BytesRaw.lease_delta
    jc rb07_fail
    cmp rax,[rsi].R671BytesRaw.lease_ptr
    jne rb07_fail
    test rax,rax
    jz rb07_fail
    mov qword ptr [rdi].R671BytesResult.witness_state[RB07_POINTER_PROVENANCE*8],RB_PASS
    jmp rb08
rb07_fail:
    mov qword ptr [rdi].R671BytesResult.witness_state[RB07_POINTER_PROVENANCE*8],RB_FAIL

; RB08 live mapped bytes and lease view must stay within configured bound.
rb08:
    mov rax,[rsi].R671BytesRaw.configured_mapped_bound
    test rax,rax
    jz rb08_fail
    cmp [rsi].R671BytesRaw.mapped_bytes_live,rax
    ja rb08_fail
    cmp [rsi].R671BytesRaw.lease_view_bytes,rax
    ja rb08_fail
    mov qword ptr [rdi].R671BytesResult.witness_state[RB08_MAPPING_BOUND*8],RB_PASS
    jmp rb09
rb08_fail:
    mov qword ptr [rdi].R671BytesResult.witness_state[RB08_MAPPING_BOUND*8],RB_FAIL

; RB09 primitive consumed exactly the requested tensor bytes.
rb09:
    mov rax,[rsi].R671BytesRaw.primitive_bytes_consumed
    cmp rax,r13
    jne rb09_fail
    test r13,r13
    jz rb09_fail
    mov qword ptr [rdi].R671BytesResult.witness_state[RB09_EXACT_BYTE_CONSUMPTION*8],RB_PASS
    jmp rb10
rb09_fail:
    mov qword ptr [rdi].R671BytesResult.witness_state[RB09_EXACT_BYTE_CONSUMPTION*8],RB_FAIL

; RB10 at least one acquire and zero failed acquires.
rb10:
    cmp [rsi].R671BytesRaw.acquire_count,0
    je rb10_fail
    cmp [rsi].R671BytesRaw.failed_acquires,0
    jne rb10_fail
    mov qword ptr [rdi].R671BytesResult.witness_state[RB10_NO_FAILED_ACQUIRE*8],RB_PASS
    jmp rb11
rb10_fail:
    mov qword ptr [rdi].R671BytesResult.witness_state[RB10_NO_FAILED_ACQUIRE*8],RB_FAIL

; RB11 no full tensor fallback.
rb11:
    cmp [rsi].R671BytesRaw.full_tensor_fallback_count,0
    jne rb11_fail
    mov qword ptr [rdi].R671BytesResult.witness_state[RB11_NO_FULL_TENSOR_FALLBACK*8],RB_PASS
    jmp rb12
rb11_fail:
    mov qword ptr [rdi].R671BytesResult.witness_state[RB11_NO_FULL_TENSOR_FALLBACK*8],RB_FAIL

; RB12 checksum was produced from the consumed bytes.
rb12:
    cmp [rsi].R671BytesRaw.checksum_observed,1
    jne rb12_fail
    ; checksum value itself may legally be zero; observation bit is authority.
    mov qword ptr [rdi].R671BytesResult.witness_state[RB12_CHECKSUM_OBSERVED*8],RB_PASS
    jmp rb13
rb12_fail:
    mov qword ptr [rdi].R671BytesResult.witness_state[RB12_CHECKSUM_OBSERVED*8],RB_FAIL

; RB13 no nonfinite primitive output/input observation.
rb13:
    cmp [rsi].R671BytesRaw.nonfinite_count,0
    jne rb13_fail
    mov qword ptr [rdi].R671BytesResult.witness_state[RB13_NONFINITE_FREE*8],RB_PASS
    jmp rb14
rb13_fail:
    mov qword ptr [rdi].R671BytesResult.witness_state[RB13_NONFINITE_FREE*8],RB_FAIL

; RB14 release closure: one release per acquire; no live lease remains.
rb14:
    mov rax,[rsi].R671BytesRaw.acquire_count
    cmp [rsi].R671BytesRaw.release_count,rax
    jne rb14_fail
    cmp [rsi].R671BytesRaw.live_leases_after_release,0
    jne rb14_fail
    mov qword ptr [rdi].R671BytesResult.witness_state[RB14_RELEASE_CLOSURE*8],RB_PASS
    jmp rb_count
rb14_fail:
    mov qword ptr [rdi].R671BytesResult.witness_state[RB14_RELEASE_CLOSURE*8],RB_FAIL

; RB15 conjunction only.
rb_count:
    xor r12d,r12d
    xor r13d,r13d
    xor r14d,r14d
    xor ebx,ebx
rb_loop:
    cmp ebx,14
    jae rb_summary
    mov rax,[rdi].R671BytesResult.witness_state[rbx*8]
    cmp rax,RB_PASS
    je rb_pass
    cmp rax,RB_FAIL
    je rb_fail
    inc r14
    jmp rb_next
rb_pass:
    inc r12
    jmp rb_next
rb_fail:
    inc r13
rb_next:
    inc ebx
    jmp rb_loop

rb_summary:
    mov [rdi].R671BytesResult.pass_count,r12
    mov [rdi].R671BytesResult.fail_count,r13
    mov [rdi].R671BytesResult.notrun_count,r14

    cmp r12,14
    jne rb_auth_fail
    test r13,r13
    jnz rb_auth_fail
    test r14,r14
    jnz rb_auth_fail

    mov qword ptr [rdi].R671BytesResult.witness_state[RB15_AUTH_DERIVATION*8],RB_PASS
    mov qword ptr [rdi].R671BytesResult.bytes_authorized,1
    jmp rb_done

rb_auth_fail:
    mov qword ptr [rdi].R671BytesResult.witness_state[RB15_AUTH_DERIVATION*8],RB_FAIL
    mov qword ptr [rdi].R671BytesResult.bytes_authorized,0

rb_done:
    add rsp,20h
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
R671BytesEvaluate ENDP

END
