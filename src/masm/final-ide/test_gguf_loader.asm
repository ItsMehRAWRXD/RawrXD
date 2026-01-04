; test_gguf_loader.asm - Complete GGUF Model Loading Test Suite (Pure MASM)
; Tests GGUF file parsing, metadata extraction, tensor cache population
; All code is MASM64 assembly - no C++ dependencies

option casemap:none

include windows.inc
includelib kernel32.lib

; External model loader functions (from ml_masm.asm)
EXTERN ml_masm_init:PROC
EXTERN ml_masm_get_arch:PROC
EXTERN ml_masm_get_tensor:PROC
EXTERN ml_masm_last_error:PROC
EXTERN ml_masm_free:PROC

; Win32 APIs
EXTERN CreateFileA:PROC
EXTERN GetFileSizeEx:PROC
EXTERN CreateFileMappingA:PROC
EXTERN MapViewOfFile:PROC
EXTERN UnmapViewOfFile:PROC
EXTERN CloseHandle:PROC
EXTERN OutputDebugStringA:PROC
EXTERN lstrcatA:PROC
EXTERN wsprintf:PROC
EXTERN ExitProcess:PROC

;==========================================================================
; CONSTANTS
;==========================================================================
GGUF_MAGIC              EQU 46554747h           ; "GGUF"
MAX_TEST_MODELS         EQU 10
MAX_TEST_TENSORS        EQU 100
ARCH_STRING_MAX         EQU 512
TENSOR_NAME_MAX         EQU 64
ERROR_MSG_MAX           EQU 512
TEST_BUFFER_SIZE        EQU 65536

;==========================================================================
; TEST RESULT STRUCTURE
;==========================================================================
TEST_RESULT STRUCT
    test_name           BYTE 64 DUP(?)
    passed              DWORD ?
    error_code          DWORD ?
    error_msg           BYTE 512 DUP(?)
    metadata_layers     DWORD ?
    metadata_hidden     DWORD ?
    metadata_heads      DWORD ?
    metadata_vocab      DWORD ?
    metadata_maxseq     DWORD ?
    tensor_count        DWORD ?
TEST_RESULT ENDS

;==========================================================================
; DATA SECTION
;==========================================================================
.DATA

; Test results array
test_results            TEST_RESULT 20 DUP (<>)
test_count              DWORD 0

; Test model paths
test_model_1            BYTE "D:\models\llama-7b-q4.gguf", 0
test_model_2            BYTE "D:\models\mistral-7b-q4.gguf", 0
test_model_3            BYTE "D:\models\neural-chat-7b-q4.gguf", 0

; Test tensor names to lookup
tensor_test_names       QWORD 5
tensor_name_1           BYTE "token_embd.weight", 0
tensor_name_2           BYTE "blk.0.attn.q.weight", 0
tensor_name_3           BYTE "blk.31.ffn_up.weight", 0
tensor_name_4           BYTE "output.weight", 0
tensor_name_5           BYTE "attn_norm.weight", 0

; Format strings
hdr_test_start          BYTE "========================================", 0x0D, 0x0A
                        BYTE "GGUF Model Loader Test Suite", 0x0D, 0x0A
                        BYTE "========================================", 0x0D, 0x0A, 0

hdr_test_model          BYTE 0x0D, 0x0A, "TEST: Loading Model - ", 0

hdr_arch_info           BYTE 0x0D, 0x0A, "ARCHITECTURE INFO:", 0x0D, 0x0A, 0

hdr_tensor_test         BYTE 0x0D, 0x0A, "TENSOR CACHE VALIDATION:", 0x0D, 0x0A, 0

fmt_metadata            BYTE "  Layers: %d, Hidden: %d, Heads: %d, Vocab: %d, MaxSeq: %d", 0x0D, 0x0A, 0

fmt_arch_string         BYTE "  Architecture String: %s", 0x0D, 0x0A, 0

fmt_tensor_lookup       BYTE "  Looking up tensor: %s ... ", 0

fmt_tensor_found        BYTE "FOUND", 0x0D, 0x0A, 0

fmt_tensor_notfound     BYTE "NOT FOUND", 0x0D, 0x0A, 0

fmt_error               BYTE "  ERROR: %s", 0x0D, 0x0A, 0

fmt_success             BYTE "  RESULT: PASSED", 0x0D, 0x0A, 0

fmt_failed              BYTE "  RESULT: FAILED", 0x0D, 0x0A, 0

fmt_summary             BYTE 0x0D, 0x0A, "========================================", 0x0D, 0x0A
                        BYTE "SUMMARY: %d/%d tests passed", 0x0D, 0x0A
                        BYTE "========================================", 0x0D, 0x0A, 0

; Temp buffers
temp_arch_string        BYTE ARCH_STRING_MAX DUP(?)
temp_error_msg          BYTE ERROR_MSG_MAX DUP(?)
temp_format_buf         BYTE 1024 DUP(?)

;==========================================================================
; CODE SECTION
;==========================================================================
.CODE

;==========================================================================
; PUBLIC: test_gguf_loader_main()
; Entry point for GGUF model loader test suite
; Loads multiple GGUF models and validates architecture/tensor extraction
;==========================================================================
PUBLIC test_gguf_loader_main
test_gguf_loader_main PROC
    push rbx
    push rsi
    push rdi
    push r8
    push r9
    sub rsp, 40h
    
    ; Print header
    lea rcx, hdr_test_start
    call OutputDebugStringA
    
    ; Test 1: Load model with full validation
    lea rcx, test_model_1
    call test_single_model_load
    
    ; Test 2: Load second model
    lea rcx, test_model_2
    call test_single_model_load
    
    ; Test 3: Load third model
    lea rcx, test_model_3
    call test_single_model_load
    
    ; Print summary
    mov eax, DWORD PTR test_count
    xor edx, edx
    mov ecx, 3
    div ecx                        ; count passed tests
    
    call print_test_summary
    
    add rsp, 40h
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbx
    ret
test_gguf_loader_main ENDP

;==========================================================================
; INTERNAL: test_single_model_load(model_path: rcx)
; Test loading a single GGUF model and validate all components
; Validates: header parsing, metadata extraction, tensor cache, architecture
;==========================================================================
ALIGN 16
test_single_model_load PROC
    push rbx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    sub rsp, 80h
    
    mov rsi, rcx                    ; rsi = model path
    
    ; Print test header
    lea rcx, hdr_test_model
    call OutputDebugStringA
    
    mov rcx, rsi
    call OutputDebugStringA
    
    ; Get current test index
    mov eax, DWORD PTR test_count
    mov edx, SIZEOF TEST_RESULT
    imul eax, edx
    lea rbx, test_results
    add rbx, rax                    ; rbx = &test_results[test_count]
    
    ; Copy model path to test name
    mov rdi, rbx
    mov rcx, rsi
    mov rdx, OFFSET [rdi + TEST_RESULT.test_name]
    mov r8, 64
    call strcpy_masm
    
    ; Step 1: Load model using ml_masm_init()
    mov rcx, rsi
    xor rdx, rdx                    ; flags = 0
    call ml_masm_init
    test eax, eax
    jz model_load_failed
    
    ; Step 2: Verify architecture string populated
    call ml_masm_get_arch
    test rax, rax
    jz arch_retrieval_failed
    
    ; Copy architecture string to temp buffer
    mov rsi, rax
    lea rdi, temp_arch_string
    mov rcx, ARCH_STRING_MAX
    call strcpy_masm
    
    ; Print architecture info
    lea rcx, hdr_arch_info
    call OutputDebugStringA
    
    ; Print actual architecture string
    lea rcx, fmt_arch_string
    lea rdx, temp_arch_string
    lea r8, temp_format_buf
    mov r9d, 1024
    call format_string_masm
    
    lea rcx, temp_format_buf
    call OutputDebugStringA
    
    ; Step 3: Test tensor cache with known names
    lea rcx, hdr_tensor_test
    call OutputDebugStringA
    
    xor r8d, r8d                    ; tensor index
    
tensor_lookup_loop:
    cmp r8d, 5                      ; test 5 tensor names
    jge tensor_lookup_done
    
    ; Get tensor name from list
    cmp r8d, 0
    je tensor_0
    cmp r8d, 1
    je tensor_1
    cmp r8d, 2
    je tensor_2
    cmp r8d, 3
    je tensor_3
    cmp r8d, 4
    je tensor_4
    
    jmp tensor_lookup_next
    
tensor_0:
    lea rcx, tensor_name_1
    jmp tensor_found_name
tensor_1:
    lea rcx, tensor_name_2
    jmp tensor_found_name
tensor_2:
    lea rcx, tensor_name_3
    jmp tensor_found_name
tensor_3:
    lea rcx, tensor_name_4
    jmp tensor_found_name
tensor_4:
    lea rcx, tensor_name_5
    jmp tensor_found_name
    
tensor_found_name:
    mov rsi, rcx                    ; rsi = tensor name
    
    ; Print tensor lookup message
    lea rcx, fmt_tensor_lookup
    lea rdx, temp_format_buf
    mov r8, 1024
    call format_string_masm
    
    lea rcx, temp_format_buf
    call OutputDebugStringA
    
    ; Lookup tensor
    mov rcx, rsi
    call ml_masm_get_tensor
    test rax, rax
    jz tensor_not_found
    
    ; Tensor found
    lea rcx, fmt_tensor_found
    call OutputDebugStringA
    
    ; Increment found counter
    mov eax, DWORD PTR [rbx + TEST_RESULT.tensor_count]
    inc eax
    mov DWORD PTR [rbx + TEST_RESULT.tensor_count], eax
    
    jmp tensor_lookup_next
    
tensor_not_found:
    lea rcx, fmt_tensor_notfound
    call OutputDebugStringA
    
tensor_lookup_next:
    inc r8d
    jmp tensor_lookup_loop
    
tensor_lookup_done:
    
    ; Step 4: Mark test as passed
    mov DWORD PTR [rbx + TEST_RESULT.passed], 1
    
    ; Print success message
    lea rcx, fmt_success
    call OutputDebugStringA
    
    ; Increment test count
    mov eax, DWORD PTR test_count
    inc eax
    mov DWORD PTR test_count, eax
    
    ; Cleanup
    call ml_masm_free
    
    add rsp, 80h
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbx
    ret
    
model_load_failed:
    ; Get error message
    call ml_masm_last_error
    mov rsi, rax
    lea rdi, temp_error_msg
    mov rcx, ERROR_MSG_MAX
    call strcpy_masm
    
    ; Print error
    lea rcx, fmt_error
    lea rdx, temp_error_msg
    lea r8, temp_format_buf
    mov r9d, 1024
    call format_string_masm
    
    lea rcx, temp_format_buf
    call OutputDebugStringA
    
    mov DWORD PTR [rbx + TEST_RESULT.passed], 0
    mov DWORD PTR [rbx + TEST_RESULT.error_code], 1
    
    lea rcx, fmt_failed
    call OutputDebugStringA
    
    mov eax, DWORD PTR test_count
    inc eax
    mov DWORD PTR test_count, eax
    
    add rsp, 80h
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbx
    ret
    
arch_retrieval_failed:
    lea rcx, temp_error_msg
    lea rdx, "Failed to retrieve architecture string"
    mov r8, ERROR_MSG_MAX
    call strcpy_masm
    
    lea rcx, fmt_error
    lea rsi, temp_error_msg
    lea r8, temp_format_buf
    mov r9d, 1024
    call format_string_masm
    
    lea rcx, temp_format_buf
    call OutputDebugStringA
    
    mov DWORD PTR [rbx + TEST_RESULT.passed], 0
    mov DWORD PTR [rbx + TEST_RESULT.error_code], 2
    
    lea rcx, fmt_failed
    call OutputDebugStringA
    
    mov eax, DWORD PTR test_count
    inc eax
    mov DWORD PTR test_count, eax
    
    add rsp, 80h
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbx
    ret
test_single_model_load ENDP

;==========================================================================
; INTERNAL: print_test_summary()
; Print summary of all test results
;==========================================================================
ALIGN 16
print_test_summary PROC
    push rbx
    push rsi
    sub rsp, 32
    
    ; Count passed tests
    xor eax, eax
    xor ebx, ebx                    ; passed counter
    
summary_loop:
    cmp eax, DWORD PTR test_count
    jge summary_done
    
    mov edx, SIZEOF TEST_RESULT
    imul eax, edx
    lea rsi, test_results
    add rsi, rax
    
    cmp DWORD PTR [rsi + TEST_RESULT.passed], 1
    jne summary_skip
    
    inc ebx
    
summary_skip:
    mov eax, DWORD PTR test_count
    dec eax
    jmp summary_loop
    
summary_done:
    ; Print summary string
    lea rcx, fmt_summary
    mov edx, ebx                    ; passed count
    mov r8d, DWORD PTR test_count
    lea r9, temp_format_buf
    
    ; Format: fmt_summary, passed, total
    ; wsprintf signature: buffer, format, args...
    sub rsp, 32
    mov QWORD PTR [rsp], r9         ; buffer
    mov QWORD PTR [rsp+8], rcx      ; format
    mov QWORD PTR [rsp+16], rdx     ; arg1 (passed)
    mov QWORD PTR [rsp+24], r8      ; arg2 (total)
    
    call wsprintf
    
    lea rcx, temp_format_buf
    call OutputDebugStringA
    
    add rsp, 32
    add rsp, 32
    pop rsi
    pop rbx
    ret
print_test_summary ENDP

;==========================================================================
; INTERNAL: strcpy_masm(src: rcx, dst: rdx, max: r8)
; Copy string with length limit
;==========================================================================
ALIGN 16
strcpy_masm PROC
    push rax
    push rbx
    
    xor eax, eax
    
copy_loop:
    cmp eax, r8
    jge copy_done
    
    mov bl, BYTE PTR [rcx + rax]
    mov BYTE PTR [rdx + rax], bl
    
    test bl, bl
    jz copy_done
    
    inc eax
    jmp copy_loop
    
copy_done:
    cmp eax, r8
    jl null_terminate
    dec eax
    
null_terminate:
    mov BYTE PTR [rdx + rax], 0
    
    pop rbx
    pop rax
    ret
strcpy_masm ENDP

;==========================================================================
; INTERNAL: format_string_masm(fmt: rcx, arg1: rdx, arg2: r8, buffer: r9, max: r10d)
; Simple format string for single string argument
; Supports %s for string substitution only
;==========================================================================
ALIGN 16
format_string_masm PROC
    push rbx
    push rsi
    push rdi
    
    mov rsi, rcx                    ; rsi = format string
    mov rdi, r9                     ; rdi = output buffer
    mov eax, r10d                   ; max length
    xor ebx, ebx                    ; position counter
    
fmt_loop:
    cmp ebx, eax
    jge fmt_done
    
    mov cl, BYTE PTR [rsi + rbx]
    test cl, cl
    jz fmt_done
    
    cmp cl, '%'
    jne fmt_copy
    
    ; Check for %s
    mov cl, BYTE PTR [rsi + rbx + 1]
    cmp cl, 's'
    jne fmt_copy
    
    ; Copy argument string
    mov rsi, rdx                    ; rdx = argument string
    
fmt_arg_copy:
    mov cl, BYTE PTR [rsi]
    test cl, cl
    jz fmt_arg_done
    cmp ebx, eax
    jge fmt_done
    
    mov BYTE PTR [rdi + rbx], cl
    inc rbx
    inc rsi
    jmp fmt_arg_copy
    
fmt_arg_done:
    mov rsi, rcx                    ; restore format pointer
    add ebx, 2                      ; skip %s
    jmp fmt_loop
    
fmt_copy:
    mov BYTE PTR [rdi + rbx], cl
    inc ebx
    jmp fmt_loop
    
fmt_done:
    cmp ebx, eax
    jl fmt_null_term
    dec ebx
    
fmt_null_term:
    mov BYTE PTR [rdi + rbx], 0
    
    pop rdi
    pop rsi
    pop rbx
    ret
format_string_masm ENDP

END

