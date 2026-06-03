option casemap:none

EXTERN rawrxd_harness_alloc_engine:PROC
EXTERN rawrxd_harness_ctor_engine:PROC
EXTERN rawrxd_harness_init_model:PROC
EXTERN rawrxd_harness_run_cycle:PROC
EXTERN rawrxd_harness_dtor_engine:PROC
EXTERN rawrxd_harness_free_engine:PROC
EXTERN rawrxd_harness_last_error:PROC
EXTERN rawrxd_probe_empty_size:PROC
EXTERN rawrxd_probe_virtual_size:PROC
EXTERN rawrxd_probe_stl_size:PROC
EXTERN rawrxd_probe_alloc:PROC
EXTERN rawrxd_probe_free:PROC
EXTERN rawrxd_probe_empty_ctor:PROC
EXTERN rawrxd_probe_empty_dtor:PROC
EXTERN rawrxd_probe_virtual_ctor:PROC
EXTERN rawrxd_probe_virtual_dtor:PROC
EXTERN rawrxd_probe_stl_ctor:PROC
EXTERN rawrxd_probe_stl_dtor:PROC
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN ExitProcess:PROC

STD_OUTPUT_HANDLE EQU -11

.data
model_path      db "d:\phi3mini.gguf", 0
prompt_text     db "Telemetry forward path test", 0
boot_msg        db "[MASM Harness] boot", 13, 10
boot_msg_len    EQU ($ - boot_msg)
stage_probe_empty db "[MASM Harness] probe-empty", 13, 10
stage_probe_empty_len EQU ($ - stage_probe_empty)
stage_probe_virtual db "[MASM Harness] probe-virtual", 13, 10
stage_probe_virtual_len EQU ($ - stage_probe_virtual)
stage_probe_stl db "[MASM Harness] probe-stl", 13, 10
stage_probe_stl_len EQU ($ - stage_probe_stl)
stage_alloc     db "[MASM Harness] alloc", 13, 10
stage_alloc_len EQU ($ - stage_alloc)
stage_ctor      db "[MASM Harness] ctor", 13, 10
stage_ctor_len  EQU ($ - stage_ctor)
stage_init      db "[MASM Harness] init", 13, 10
stage_init_len  EQU ($ - stage_init)
stage_run       db "[MASM Harness] run", 13, 10
stage_run_len   EQU ($ - stage_run)
ok_msg          db "[MASM Harness] run_cycle succeeded", 13, 10
ok_msg_len      EQU ($ - ok_msg)
fail_msg        db "[MASM Harness] failure: ", 0
newline_msg     db 13, 10

.code

harness_write proc
    ; RCX = pointer, RDX = length
    sub rsp, 28h
    mov r10, rcx
    mov r11, rdx

    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle

    mov rcx, rax
    mov rdx, r10
    mov r8,  r11
    lea r9, [rsp+18h]
    mov qword ptr [rsp+20h], 0
    call WriteFile
    add rsp, 28h
    ret
harness_write endp

harness_entry proc
    ; 16-byte alignment + 32-byte shadow space
    sub rsp, 28h
    xor ebx, ebx
    xor r12d, r12d
    xor r13, r13

    lea rcx, boot_msg
    mov rdx, boot_msg_len
    call harness_write

    ; probe 1: empty constructor
    lea rcx, stage_probe_empty
    mov rdx, stage_probe_empty_len
    call harness_write

    call rawrxd_probe_empty_size
    mov rcx, rax
    call rawrxd_probe_alloc
    test rax, rax
    jz harness_fail
    mov r13, rax

    mov rcx, r13
    call rawrxd_probe_empty_ctor
    test eax, eax
    jnz harness_fail_probe

    mov rcx, r13
    call rawrxd_probe_empty_dtor
    test eax, eax
    jnz harness_fail_probe

    mov rcx, r13
    call rawrxd_probe_free
    test eax, eax
    jnz harness_fail
    xor r13, r13

    ; probe 2: virtual constructor
    lea rcx, stage_probe_virtual
    mov rdx, stage_probe_virtual_len
    call harness_write

    call rawrxd_probe_virtual_size
    mov rcx, rax
    call rawrxd_probe_alloc
    test rax, rax
    jz harness_fail
    mov r13, rax

    mov rcx, r13
    call rawrxd_probe_virtual_ctor
    test eax, eax
    jnz harness_fail_probe

    mov rcx, r13
    call rawrxd_probe_virtual_dtor
    test eax, eax
    jnz harness_fail_probe

    mov rcx, r13
    call rawrxd_probe_free
    test eax, eax
    jnz harness_fail
    xor r13, r13

    ; probe 3: STL constructor
    lea rcx, stage_probe_stl
    mov rdx, stage_probe_stl_len
    call harness_write

    call rawrxd_probe_stl_size
    mov rcx, rax
    call rawrxd_probe_alloc
    test rax, rax
    jz harness_fail
    mov r13, rax

    mov rcx, r13
    call rawrxd_probe_stl_ctor
    test eax, eax
    jnz harness_fail_probe

    mov rcx, r13
    call rawrxd_probe_stl_dtor
    test eax, eax
    jnz harness_fail_probe

    mov rcx, r13
    call rawrxd_probe_free
    test eax, eax
    jnz harness_fail
    xor r13, r13

    lea rcx, stage_alloc
    mov rdx, stage_alloc_len
    call harness_write

    ; alloc engine memory
    call rawrxd_harness_alloc_engine
    test rax, rax
    jz harness_fail
    mov rbx, rax
    or r12d, 1

    lea rcx, stage_ctor
    mov rdx, stage_ctor_len
    call harness_write

    ; run constructor in-place
    mov rcx, rbx
    call rawrxd_harness_ctor_engine
    test eax, eax
    jnz harness_fail
    or r12d, 2

    lea rcx, stage_init
    mov rdx, stage_init_len
    call harness_write

    ; initialize model
    mov rcx, rbx
    lea rdx, model_path
    call rawrxd_harness_init_model
    test eax, eax
    jnz harness_fail

    lea rcx, stage_run
    mov rdx, stage_run_len
    call harness_write

    ; run one inference cycle
    mov rcx, rbx
    lea rdx, prompt_text
    mov r8d, 32
    call rawrxd_harness_run_cycle
    test eax, eax
    jnz harness_fail

    ; success message
    lea rcx, ok_msg
    mov rdx, ok_msg_len
    call harness_write

    ; cleanup + exit(0)
    test r12d, 2
    jz skip_dtor_success
    mov rcx, rbx
    call rawrxd_harness_dtor_engine
skip_dtor_success:
    test r12d, 1
    jz skip_free_success
    mov rcx, rbx
    call rawrxd_harness_free_engine
skip_free_success:
    xor ecx, ecx
    call ExitProcess

harness_fail:
    test r13, r13
    jz skip_probe_free_fail
    mov rcx, r13
    call rawrxd_probe_free
    xor r13, r13
skip_probe_free_fail:

    ; cleanup depending on completed stages
    test r12d, 2
    jz skip_dtor_fail
    mov rcx, rbx
    call rawrxd_harness_dtor_engine
skip_dtor_fail:
    test r12d, 1
    jz skip_free_fail
    mov rcx, rbx
    call rawrxd_harness_free_engine
skip_free_fail:

    ; print prefix
    lea rcx, fail_msg
    mov rdx, 24
    call harness_write

    ; print C-string error
    call rawrxd_harness_last_error
    mov rcx, rax
    xor rdx, rdx
count_len:
    cmp byte ptr [rcx+rdx], 0
    je have_len
    inc rdx
    jmp count_len
have_len:
    call harness_write

    lea rcx, newline_msg
    mov rdx, 2
    call harness_write

    mov ecx, 1
    call ExitProcess
harness_fail_probe:
    test r13, r13
    jz harness_fail
    mov rcx, r13
    call rawrxd_probe_free
    xor r13, r13
    jmp harness_fail
harness_entry endp

END
