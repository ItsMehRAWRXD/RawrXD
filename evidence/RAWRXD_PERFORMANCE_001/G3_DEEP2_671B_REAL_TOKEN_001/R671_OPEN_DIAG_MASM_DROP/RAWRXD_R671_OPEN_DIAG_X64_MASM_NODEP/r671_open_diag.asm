option casemap:none
include r671_open_diag.inc

CreateFileA        PROTO
GetFileSizeEx      PROTO
CreateFileMappingA PROTO
CloseHandle        PROTO
GetSystemInfo      PROTO
GetLastError       PROTO

; Local frame offsets after:
;   push rbx,rsi,rdi = 18h
;   sub rsp,50h      = 50h
;
; 20h..37h = outbound stack arguments
; 38h..3fh = named LARGE_INTEGER scratch
; 40h..4fh = spare diagnostics/local scratch
R671_LOCAL_FILESIZE equ 38h

.data?
sysinfo_buf BYTE 64 DUP(?)

.code

zero_diag_ctx PROC
    xor eax,eax
    mov r8,SIZEOF R671ContextDiag
zd_loop:
    test r8,r8
    jz zd_done
    mov byte ptr [rdx],al
    inc rdx
    dec r8
    jmp zd_loop
zd_done:
    ret
zero_diag_ctx ENDP


capture_error PROC
    ; rcx = ctx, edx = stage, r8d = r671 rc
    ; Preserve inputs across GetLastError using nonvolatile-free stack locals.
    sub rsp,38h
    mov [rsp+20h],rcx
    mov [rsp+28h],edx
    mov [rsp+30h],r8d
    call GetLastError
    mov rcx,[rsp+20h]
    mov edx,[rsp+28h]
    mov r8d,[rsp+30h]
    mov [rcx].R671ContextDiag.open_stage,edx
    mov [rcx].R671ContextDiag.open_rc,r8d
    mov [rcx].R671ContextDiag.win32_last_error,eax
    mov eax,r8d
    add rsp,38h
    ret
capture_error ENDP


r671_open_diag PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp,50h
    .allocstack 50h
    .endprolog

    mov rsi,rcx
    mov rdi,rdx
    test rsi,rsi
    jz ro_invalid
    test rdi,rdi
    jz ro_invalid

    mov rdx,rdi
    call zero_diag_ctx

; ---------------------------------------------------------------------------
; Stage 1: CreateFileA
; ---------------------------------------------------------------------------
    mov dword ptr [rdi].R671ContextDiag.open_stage,R671_STAGE_CREATEFILE

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
    mov [rdi].R671ContextDiag.file_handle,rax
    mov rbx,rax

; ---------------------------------------------------------------------------
; Stage 2: GetFileSizeEx
; ---------------------------------------------------------------------------
    mov dword ptr [rdi].R671ContextDiag.open_stage,R671_STAGE_GETFILESIZE

    mov qword ptr [rsp+R671_LOCAL_FILESIZE],0
    mov rcx,rbx
    lea rdx,[rsp+R671_LOCAL_FILESIZE]
    call GetFileSizeEx
    test eax,eax
    jz ro_size_fail

    mov rax,[rsp+R671_LOCAL_FILESIZE]
    test rax,rax
    jz ro_zero_size
    mov [rdi].R671ContextDiag.file_bytes,rax

; ---------------------------------------------------------------------------
; Stage 3: CreateFileMappingA
; ---------------------------------------------------------------------------
    mov dword ptr [rdi].R671ContextDiag.open_stage,R671_STAGE_MAPPING

    mov rcx,rbx
    xor rdx,rdx
    mov r8d,PAGE_READONLY
    xor r9d,r9d
    mov qword ptr [rsp+20h],0
    mov qword ptr [rsp+28h],0
    call CreateFileMappingA
    test rax,rax
    jz ro_mapping_fail
    mov [rdi].R671ContextDiag.mapping_handle,rax

; ---------------------------------------------------------------------------
; Stage 4: GetSystemInfo cannot fail; record ready after granularity capture.
; ---------------------------------------------------------------------------
    mov dword ptr [rdi].R671ContextDiag.open_stage,R671_STAGE_SYSINFO
    lea rcx,sysinfo_buf
    call GetSystemInfo
    mov eax,dword ptr [sysinfo_buf+28h]
    test eax,eax
    jnz ro_gran_ok
    mov eax,10000h
ro_gran_ok:
    mov [rdi].R671ContextDiag.allocation_gran,rax

    mov dword ptr [rdi].R671ContextDiag.open_stage,R671_STAGE_READY
    mov dword ptr [rdi].R671ContextDiag.open_rc,R671_OK
    mov dword ptr [rdi].R671ContextDiag.win32_last_error,0
    xor eax,eax
    jmp ro_done

; Capture GetLastError immediately at each failing Win32 call.
ro_open_fail:
    mov rcx,rdi
    mov edx,R671_STAGE_CREATEFILE
    mov r8d,R671_E_OPEN
    call capture_error
    jmp ro_done

ro_size_fail:
    mov rcx,rdi
    mov edx,R671_STAGE_GETFILESIZE
    mov r8d,R671_E_SIZE
    call capture_error
    mov ebx,eax
    jmp ro_cleanup_file_keepdiag

; Zero-length is a semantic size failure; GetLastError is not authoritative.
ro_zero_size:
    mov dword ptr [rdi].R671ContextDiag.open_stage,R671_STAGE_GETFILESIZE
    mov dword ptr [rdi].R671ContextDiag.open_rc,R671_E_SIZE
    mov dword ptr [rdi].R671ContextDiag.win32_last_error,0
    mov ebx,R671_E_SIZE
    jmp ro_cleanup_file_keepdiag

ro_mapping_fail:
    mov rcx,rdi
    mov edx,R671_STAGE_MAPPING
    mov r8d,R671_E_MAPPING
    call capture_error
    mov ebx,eax

ro_cleanup_file_keepdiag:
    mov rcx,[rdi].R671ContextDiag.file_handle
    test rcx,rcx
    jz ro_cleanup_file_done
    call CloseHandle
ro_cleanup_file_done:
    mov qword ptr [rdi].R671ContextDiag.file_handle,0
    mov eax,ebx
    jmp ro_done

ro_invalid:
    mov eax,R671_E_INVALID

ro_done:
    add rsp,50h
    pop rdi
    pop rsi
    pop rbx
    ret
r671_open_diag ENDP

END
