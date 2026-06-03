option casemap:none

EXTERN rawrxd_harness_create_engine:PROC
EXTERN rawrxd_harness_run_cycle:PROC
EXTERN rawrxd_harness_destroy_engine:PROC
EXTERN rawrxd_harness_last_error:PROC
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN ExitProcess:PROC

STD_OUTPUT_HANDLE EQU -11

.data
model_path      db "d:\phi3mini.gguf", 0
prompt_text     db "Telemetry forward path test", 0
boot_msg        db "[MASM Harness] boot", 13, 10
boot_msg_len    EQU ($ - boot_msg)
stage_create    db "[MASM Harness] create", 13, 10
stage_create_len EQU ($ - stage_create)
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

    lea rcx, boot_msg
    mov rdx, boot_msg_len
    call harness_write

    lea rcx, stage_create
    mov rdx, stage_create_len
    call harness_write

    ; create engine
    lea rcx, model_path
    call rawrxd_harness_create_engine
    test rax, rax
    jz harness_fail
    mov rbx, rax

    lea rcx, stage_run
    mov rdx, stage_run_len
    call harness_write

    ; run one inference cycle
    mov rcx, rbx
    lea rdx, prompt_text
    mov r8d, 32
    call rawrxd_harness_run_cycle
    test eax, eax
    jz harness_fail_with_engine

    ; success message
    lea rcx, ok_msg
    mov rdx, ok_msg_len
    call harness_write

    ; destroy + exit(0)
    mov rcx, rbx
    call rawrxd_harness_destroy_engine
    xor ecx, ecx
    call ExitProcess

harness_fail_with_engine:
    mov rcx, rbx
    call rawrxd_harness_destroy_engine

harness_fail:
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
harness_entry endp

END
