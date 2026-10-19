option casemap:none
include r671_abi.inc

CreateFileA PROTO
GetFileSizeEx PROTO
CreateFileMappingA PROTO
MapViewOfFile PROTO
UnmapViewOfFile PROTO
CloseHandle PROTO
GetSystemInfo PROTO
GetLastError PROTO

.data?
sysinfo_buf BYTE 64 DUP(?)

.code

zero_ctx PROC
    xor eax,eax
    mov r8, SIZEOF R671Context
zc_loop:
    test r8,r8
    jz zc_done
    mov byte ptr [rdx],al
    inc rdx
    dec r8
    jmp zc_loop
zc_done:
    ret
zero_ctx ENDP

zero_lease PROC
    xor eax,eax
    mov r8, SIZEOF R671Lease
zl_loop:
    test r8,r8
    jz zl_done
    mov byte ptr [rdx],al
    inc rdx
    dec r8
    jmp zl_loop
zl_done:
    ret
zero_lease ENDP

r671_open PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp,40h
    .allocstack 40h
    .endprolog

    mov rsi,rcx
    mov rdi,rdx
    test rsi,rsi
    jz ro_invalid
    test rdi,rdi
    jz ro_invalid

    mov rdx,rdi
    call zero_ctx

    mov rcx,rsi
    mov edx,GENERIC_READ
    mov r8d,FILE_SHARE_READ
    xor r9d,r9d
    mov qword ptr [rsp+20h],OPEN_EXISTING
    mov qword ptr [rsp+28h],FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+30h],0
    call CreateFileA
    cmp rax,INVALID_HANDLE_VALUE
    je ro_open_fail
    mov [rdi].R671Context.file_handle,rax
    mov rbx,rax

    lea rdx,[rsp+38h]
    mov rcx,rbx
    call GetFileSizeEx
    test eax,eax
    jz ro_size_fail
    mov rax,[rsp+38h]
    test rax,rax
    jz ro_size_fail
    mov [rdi].R671Context.file_bytes,rax

    mov rcx,rbx
    xor rdx,rdx
    mov r8d,PAGE_READONLY
    xor r9d,r9d
    mov qword ptr [rsp+20h],0
    mov qword ptr [rsp+28h],0
    call CreateFileMappingA
    test rax,rax
    jz ro_mapping_fail
    mov [rdi].R671Context.mapping_handle,rax

    lea rcx,sysinfo_buf
    call GetSystemInfo
    mov eax,dword ptr [sysinfo_buf+28h] ; dwAllocationGranularity
    test eax,eax
    jz ro_gran_default
    mov [rdi].R671Context.allocation_gran,rax
    xor eax,eax
    jmp ro_done

ro_gran_default:
    mov qword ptr [rdi].R671Context.allocation_gran,10000h
    xor eax,eax
    jmp ro_done

ro_mapping_fail:
    call GetLastError
    test eax,eax
    jnz ro_map_err
    mov eax,R671_E_MAPPING
    jmp ro_cleanup_file
ro_map_err:
    jmp ro_cleanup_file
ro_size_fail:
    mov eax,R671_E_SIZE
ro_cleanup_file:
    mov ebx,eax
    mov rcx,[rdi].R671Context.file_handle
    test rcx,rcx
    jz ro_cleanup_done
    call CloseHandle
ro_cleanup_done:
    mov rdx,rdi
    call zero_ctx
    mov eax,ebx
    jmp ro_done
ro_open_fail:
    call GetLastError
    test eax,eax
    jnz ro_done
    mov eax,R671_E_OPEN
    jmp ro_done
ro_invalid:
    mov eax,R671_E_INVALID
ro_done:
    add rsp,40h
    pop rdi
    pop rsi
    pop rbx
    ret
r671_open ENDP

r671_tensor_acquire PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    sub rsp,50h
    .allocstack 50h
    .endprolog

    mov rsi,rcx        ; ctx
    mov rbx,rdx        ; offset
    mov r12,r8         ; bytes
    mov r10,r9         ; generation
    mov rdi,[rsp+98h]  ; fifth arg after pushes+alloc

    test rsi,rsi
    jz ra_invalid
    test rdi,rdi
    jz ra_invalid
    mov rdx,rdi
    call zero_lease

    test r12,r12
    jz ra_fail_range
    mov rax,rbx
    add rax,r12
    jc ra_fail_range
    cmp rax,[rsi].R671Context.file_bytes
    ja ra_fail_range
    cmp [rsi].R671Context.mapping_handle,0
    je ra_fail_state

    mov r11,[rsi].R671Context.allocation_gran
    test r11,r11
    jz ra_fail_state

    ; aligned_offset = offset - (offset % granularity)
    mov rax,rbx
    xor rdx,rdx
    div r11
    mov r9,rdx         ; delta
    mov rax,rbx
    sub rax,r9         ; aligned offset
    mov [rdi].R671Lease.aligned_offset,rax
    mov [rdi].R671Lease.delta,r9
    mov [rdi].R671Lease.request_offset,rbx
    mov [rdi].R671Lease.bytes,r12
    mov [rdi].R671Lease.generation_id,r10

    mov rcx,r12
    add rcx,r9
    jc ra_fail_range
    mov [rdi].R671Lease.view_bytes,rcx

    ; MapViewOfFile(handle, FILE_MAP_READ, off_hi, off_lo, view_bytes)
    mov rax,[rdi].R671Lease.aligned_offset
    mov r8,rax
    shr r8,32
    mov r9d,eax
    mov rcx,[rsi].R671Context.mapping_handle
    mov edx,FILE_MAP_READ
    mov rax,[rdi].R671Lease.view_bytes
    mov [rsp+20h],rax
    call MapViewOfFile
    test rax,rax
    jz ra_fail_view

    mov [rdi].R671Lease.view_base,rax
    mov rcx,[rdi].R671Lease.delta
    add rax,rcx
    mov [rdi].R671Lease.data_ptr,rax
    mov qword ptr [rdi].R671Lease.active,1

    inc qword ptr [rsi].R671Context.acquire_count
    inc qword ptr [rsi].R671Context.live_leases
    mov rax,[rdi].R671Lease.view_bytes
    add [rsi].R671Context.mapped_bytes_live,rax
    add [rsi].R671Context.newly_mapped_bytes,rax
    mov rcx,[rsi].R671Context.mapped_bytes_live
    cmp rcx,[rsi].R671Context.mapped_bytes_peak
    jbe ra_ok
    mov [rsi].R671Context.mapped_bytes_peak,rcx
ra_ok:
    xor eax,eax
    jmp ra_done

ra_fail_view:
    inc qword ptr [rsi].R671Context.failed_acquires
    mov eax,R671_E_VIEW
    jmp ra_done
ra_fail_range:
    test rsi,rsi
    jz ra_range_noctx
    inc qword ptr [rsi].R671Context.failed_acquires
ra_range_noctx:
    mov eax,R671_E_RANGE
    jmp ra_done
ra_fail_state:
    inc qword ptr [rsi].R671Context.failed_acquires
    mov eax,R671_E_STATE
    jmp ra_done
ra_invalid:
    mov eax,R671_E_INVALID
ra_done:
    add rsp,50h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
r671_tensor_acquire ENDP

r671_release PROC FRAME
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp,20h
    .allocstack 20h
    .endprolog
    mov rsi,rcx
    mov rdi,rdx
    test rsi,rsi
    jz rr_invalid
    test rdi,rdi
    jz rr_invalid
    cmp [rdi].R671Lease.active,1
    jne rr_state

    mov rcx,[rdi].R671Lease.view_base
    call UnmapViewOfFile
    test eax,eax
    jz rr_state

    mov rax,[rdi].R671Lease.view_bytes
    cmp [rsi].R671Context.mapped_bytes_live,rax
    jb rr_zero_live
    sub [rsi].R671Context.mapped_bytes_live,rax
    jmp rr_dec
rr_zero_live:
    mov qword ptr [rsi].R671Context.mapped_bytes_live,0
rr_dec:
    cmp [rsi].R671Context.live_leases,0
    je rr_count
    dec qword ptr [rsi].R671Context.live_leases
rr_count:
    inc qword ptr [rsi].R671Context.release_count
    mov rdx,rdi
    call zero_lease
    xor eax,eax
    jmp rr_done
rr_state:
    mov eax,R671_E_STATE
    jmp rr_done
rr_invalid:
    mov eax,R671_E_INVALID
rr_done:
    add rsp,20h
    pop rdi
    pop rsi
    ret
r671_release ENDP

r671_close PROC FRAME
    push rsi
    .pushreg rsi
    sub rsp,20h
    .allocstack 20h
    .endprolog
    mov rsi,rcx
    test rsi,rsi
    jz rc_invalid
    cmp [rsi].R671Context.live_leases,0
    jne rc_state

    mov rcx,[rsi].R671Context.mapping_handle
    test rcx,rcx
    jz rc_file
    call CloseHandle
rc_file:
    mov rcx,[rsi].R671Context.file_handle
    test rcx,rcx
    jz rc_zero
    call CloseHandle
rc_zero:
    mov rdx,rsi
    call zero_ctx
    xor eax,eax
    jmp rc_done
rc_state:
    mov eax,R671_E_STATE
    jmp rc_done
rc_invalid:
    mov eax,R671_E_INVALID
rc_done:
    add rsp,20h
    pop rsi
    ret
r671_close ENDP

END
