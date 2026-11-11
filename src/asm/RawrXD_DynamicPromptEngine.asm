OPTION CASEMAP:NONE
.code

; =============================================================================
; RawrXD Dynamic Prompt Engine - x64 MASM Implementation
; Exports for RawrXD_DynamicPromptEngine.def
; =============================================================================

; Function prototypes matching the .def exports
PUBLIC PromptGen_AnalyzeContext
PUBLIC PromptGen_BuildCritic
PUBLIC PromptGen_BuildAuditor
PUBLIC PromptGen_Interpolate
PUBLIC PromptGen_GetTemplate
PUBLIC PromptGen_ForceMode

; Mode IDs (must match C++ enum)
CTX_MODE_GENERIC    EQU 0
CTX_MODE_CODE       EQU 1
CTX_MODE_SECURITY   EQU 2
CTX_MODE_SHELL      EQU 3
CTX_MODE_CASUAL     EQU 4
CTX_MODE_ENTERPRISE EQU 5
CTX_MODE_MAX        EQU 6

; Error codes
ERROR_SUCCESS               EQU 0
ERROR_INVALID_PARAMETER     EQU 80000001h

; =============================================================================
; Data Section - Read/Write data for the DLL
; =============================================================================
.data
ALIGN 8

; Global state
g_ForceMode     DWORD -1    ; -1 = no forced mode

; Simple keyword detection strings (null-terminated, double-null to end list)
; Code keywords
KwCode1     BYTE "function", 0
KwCode2     BYTE "class", 0
KwCode3     BYTE "def ", 0
KwCode4     BYTE "import", 0
KwCode5     BYTE "#include", 0
KwCode6     BYTE "const", 0
KwCode7     BYTE "let ", 0
KwCode8     BYTE "var ", 0
KwCode9     BYTE "async", 0
KwCode10    BYTE "await", 0
KwCodeEnd   BYTE 0, 0

; Security keywords
KwSec1      BYTE "password", 0
KwSec2      BYTE "token", 0
KwSec3      BYTE "secret", 0
KwSec4      BYTE "key", 0
KwSec5      BYTE "auth", 0
KwSec6      BYTE "encrypt", 0
KwSec7      BYTE "hash", 0
KwSec8      BYTE "vulnerability", 0
KwSecEnd    BYTE 0, 0

; Shell keywords
KwShell1    BYTE "rm -", 0
KwShell2    BYTE "sudo", 0
KwShell3    BYTE "chmod", 0
KwShell4    BYTE "curl", 0
KwShell5    BYTE "wget", 0
KwShell6    BYTE "bash", 0
KwShell7    BYTE "powershell", 0
KwShell8    BYTE "apt ", 0
KwShell9    BYTE "yum ", 0
KwShell10   BYTE "docker", 0
KwShellEnd  BYTE 0, 0

; Code block markers
CodeFence1  BYTE "```", 0
CodeFence2  BYTE "    ", 0

; Template strings (simplified)
TemplateCritic      BYTE "Analyze the following for issues: ", 0
TemplateAuditor     BYTE "Audit the following for compliance: ", 0
TemplateGeneric     BYTE "Process the following: ", 0

; =============================================================================
; PromptGen_AnalyzeContext - Classify input text, return mode ID
; Entry:  rcx = context string pointer
;         rdx = output mode ID pointer
; Exit:   rax = 0 (success) or error code
; =============================================================================
PromptGen_AnalyzeContext PROC FRAME
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
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov rsi, rcx            ; rsi = input text
    mov rdi, rdx            ; rdi = output pointer

    ; Validate inputs
    test rsi, rsi
    jz analyze_null_input
    test rdi, rdi
    jz analyze_null_output

    ; Check for forced mode first
    mov eax, [g_ForceMode]
    cmp eax, -1
    je analyze_auto_detect
    cmp eax, CTX_MODE_MAX
    jae analyze_auto_detect
    ; Valid forced mode
    mov [rdi], eax
    xor eax, eax
    jmp analyze_done

analyze_auto_detect:
    ; Simple heuristic classification
    ; Score each mode based on keyword presence
    xor r12, r12            ; r12 = code score
    xor r13, r13            ; r13 = security score
    xor rbx, rbx            ; rbx = shell score

    ; Scan for code keywords
    mov rcx, rsi
    lea rdx, KwCode1
    call CountKeywordMatchesSimple
    add r12, rax

    ; Scan for security keywords  
    mov rcx, rsi
    lea rdx, KwSec1
    call CountKeywordMatchesSimple
    add r13, rax

    ; Scan for shell keywords
    mov rcx, rsi
    lea rdx, KwShell1
    call CountKeywordMatchesSimple
    add rbx, rax

    ; Check for code fences (strong signal)
    mov rcx, rsi
    lea rdx, CodeFence1
    call CountKeywordMatchesSimple
    shl rax, 2              ; Multiply by 4 (strong weight)
    add r12, rax

    ; Determine winner
    mov eax, CTX_MODE_GENERIC   ; default
    mov rcx, r12                ; rcx = best score
    mov r8d, CTX_MODE_CODE      ; r8d = best mode

    cmp r13, rcx                ; security > code?
    jbe check_shell
    mov rcx, r13
    mov r8d, CTX_MODE_SECURITY

check_shell:
    cmp rbx, rcx                ; shell > current?
    jbe check_threshold
    mov rcx, rbx
    mov r8d, CTX_MODE_SHELL

check_threshold:
    ; Must have at least 1 hit to be non-generic
    test rcx, rcx
    jz analyze_store_result
    mov eax, r8d

analyze_store_result:
    mov [rdi], eax
    xor eax, eax            ; Return success

analyze_done:
    add rsp, 40
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

analyze_null_input:
    mov eax, ERROR_INVALID_PARAMETER
    jmp analyze_done

analyze_null_output:
    mov eax, ERROR_INVALID_PARAMETER
    jmp analyze_done
PromptGen_AnalyzeContext ENDP

; =============================================================================
; CountKeywordMatchesSimple - Count occurrences of keywords in text
; Entry:  rcx = text pointer
;         rdx = keyword array pointer (null-terminated strings, double-null end)
; Exit:   rax = match count
; =============================================================================
CountKeywordMatchesSimple PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov rsi, rcx            ; rsi = text
    mov rdi, rdx            ; rdi = keyword array
    xor r12, r12            ; r12 = match count

keyword_outer_loop:
    ; Check if we've reached end of keyword array (double null)
    mov al, [rdi]
    test al, al
    jnz keyword_process
    mov al, [rdi+1]
    test al, al
    jz keyword_done         ; Double null = end of array

keyword_process:
    ; Count occurrences of current keyword in text
    mov rcx, rsi
    mov rdx, rdi
    call CountSingleKeyword
    add r12, rax

    ; Advance to next keyword
    mov rcx, rdi
    call StringLength
    add rdi, rax
    inc rdi                 ; Skip null terminator
    jmp keyword_outer_loop

keyword_done:
    mov rax, r12
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
CountKeywordMatchesSimple ENDP

; =============================================================================
; CountSingleKeyword - Count occurrences of single keyword in text
; Entry:  rcx = text pointer
;         rdx = keyword pointer
; Exit:   rax = match count
; =============================================================================
CountSingleKeyword PROC FRAME
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
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov rsi, rcx            ; rsi = text
    mov rdi, rdx            ; rdi = keyword
    xor r12, r12            ; r12 = count
    mov r13, rdi            ; r13 = saved keyword start

    ; Get keyword length
    mov rcx, rdi
    call StringLength
    test rax, rax
    jz count_single_done    ; Empty keyword
    mov rbx, rax            ; rbx = keyword length

count_single_loop:
    ; Search for keyword at current position
    mov rcx, rsi
    mov rdx, rdi
    call StringStartsWith
    test rax, rax
    jz count_single_next
    ; Found match
    inc r12
    add rsi, rbx            ; Skip past this keyword
    jmp count_single_loop

count_single_next:
    ; Move to next character in text
    mov al, [rsi]
    test al, al
    jz count_single_done    ; End of text
    inc rsi
    jmp count_single_loop

count_single_done:
    mov rax, r12
    add rsp, 40
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
CountSingleKeyword ENDP

; =============================================================================
; StringStartsWith - Check if text starts with keyword
; Entry:  rcx = text pointer
;         rdx = keyword pointer
; Exit:   rax = 1 if starts with, 0 otherwise
; =============================================================================
StringStartsWith PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov rsi, rcx
    mov rdi, rdx

startswith_loop:
    mov al, [rdi]
    test al, al
    jz startswith_yes       ; Reached end of keyword = match

    mov bl, [rsi]
    cmp al, bl
    jne startswith_no       ; Mismatch

    inc rsi
    inc rdi
    jmp startswith_loop

startswith_yes:
    mov rax, 1
    jmp startswith_done

startswith_no:
    xor rax, rax

startswith_done:
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    ret
StringStartsWith ENDP

; =============================================================================
; StringLength - Calculate length of null-terminated string
; Entry:  rcx = string pointer
; Exit:   rax = length
; =============================================================================
StringLength PROC FRAME
    push rdi
    .pushreg rdi
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov rdi, rcx
    xor rax, rax            ; rax = length

strlen_loop:
    mov dl, [rdi + rax]
    test dl, dl
    jz strlen_done
    inc rax
    jmp strlen_loop

strlen_done:
    add rsp, 40
    pop rdi
    ret
StringLength ENDP

; =============================================================================
; PromptGen_BuildCritic - Generate critic prompt for mode+context
; Entry:  rcx = mode ID
;         rdx = context string pointer
;         r8  = output buffer pointer
;         r9  = output buffer size
; Exit:   rax = 0 (success) or error code
; =============================================================================
PromptGen_BuildCritic PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov ebx, ecx            ; ebx = mode
    mov rsi, rdx            ; rsi = context
    mov rdi, r8             ; rdi = output buffer
    mov r12, r9             ; r12 = buffer size

    ; Validate inputs
    test rdi, rdi
    jz critic_null_buffer
    test r12, r12
    jz critic_null_buffer

    ; Copy template prefix
    lea rcx, TemplateCritic
    mov rdx, rdi
    mov r8, r12
    call CopyStringLimited

    ; Append context if present
    test rsi, rsi
    jz critic_done
    mov rcx, rsi
    call StringLength
    mov r8, rax             ; r8 = context length

    ; Calculate remaining space
    mov rcx, rdi
    call StringLength
    mov r9, r12
    sub r9, rax             ; r9 = remaining space
    sub r9, 1               ; Leave room for null

    cmp r9, r8
    cmova r9, r8            ; r9 = min(remaining, context_len)

    ; Append context
    mov rcx, rdi
    call StringLength
    add rdi, rax            ; rdi = end of current string
    mov rcx, rsi            ; rcx = context
    mov rdx, rdi            ; rdx = destination
    mov r8, r9              ; r8 = count
    call CopyMemory

    ; Null terminate
    mov byte ptr [rdi + r9], 0

critic_done:
    xor eax, eax
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

critic_null_buffer:
    mov eax, ERROR_INVALID_PARAMETER
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
PromptGen_BuildCritic ENDP

; =============================================================================
; CopyStringLimited - Copy string with length limit
; Entry:  rcx = source
;         rdx = dest
;         r8  = max bytes (including null)
; Exit:   rax = bytes copied (excluding null)
; =============================================================================
CopyStringLimited PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov rsi, rcx
    mov rdi, rdx
    mov rbx, r8
    dec rbx                 ; Leave room for null terminator
    xor rax, rax            ; rax = count

copy_limited_loop:
    test rbx, rbx
    jz copy_limited_done
    mov dl, [rsi + rax]
    mov [rdi + rax], dl
    test dl, dl
    jz copy_limited_done
    inc rax
    dec rbx
    jmp copy_limited_loop

copy_limited_done:
    ; Ensure null termination
    mov byte ptr [rdi + rax], 0
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    ret
CopyStringLimited ENDP

; =============================================================================
; CopyMemory - Copy memory block
; Entry:  rcx = source
;         rdx = dest
;         r8  = count
; =============================================================================
CopyMemory PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov rsi, rcx
    mov rdi, rdx
    mov rbx, r8
    xor rax, rax

copy_mem_loop:
    cmp rax, rbx
    jae copy_mem_done
    mov dl, [rsi + rax]
    mov [rdi + rax], dl
    inc rax
    jmp copy_mem_loop

copy_mem_done:
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    ret
CopyMemory ENDP

; =============================================================================
; PromptGen_BuildAuditor - Generate auditor prompt for mode+context
; Entry:  rcx = mode ID
;         rdx = context string pointer
;         r8  = output buffer pointer
;         r9  = output buffer size
; Exit:   rax = 0 (success) or error code
; =============================================================================
PromptGen_BuildAuditor PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov ebx, ecx
    mov rsi, rdx
    mov rdi, r8
    mov r12, r9

    test rdi, rdi
    jz auditor_null_buffer
    test r12, r12
    jz auditor_null_buffer

    ; Copy template prefix
    lea rcx, TemplateAuditor
    mov rdx, rdi
    mov r8, r12
    call CopyStringLimited

    ; Append context if present
    test rsi, rsi
    jz auditor_done
    mov rcx, rsi
    call StringLength
    mov r8, rax

    mov rcx, rdi
    call StringLength
    mov r9, r12
    sub r9, rax
    sub r9, 1
    cmp r9, r8
    cmova r9, r8

    mov rcx, rdi
    call StringLength
    add rdi, rax
    mov rcx, rsi
    mov rdx, rdi
    mov r8, r9
    call CopyMemory
    mov byte ptr [rdi + r9], 0

auditor_done:
    xor eax, eax
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

auditor_null_buffer:
    mov eax, ERROR_INVALID_PARAMETER
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
PromptGen_BuildAuditor ENDP

; =============================================================================
; PromptGen_Interpolate - Inject context vars into template
; Entry:  rcx = template string pointer
;         rdx = context JSON pointer
;         r8  = output buffer pointer
;         r9  = output buffer size
; Exit:   rax = 0 (success) or error code
; =============================================================================
PromptGen_Interpolate PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov rsi, rcx            ; rsi = template
    mov rdi, r8             ; rdi = output buffer
    mov r12, r9             ; r12 = buffer size

    ; Validate inputs
    test rsi, rsi
    jz interpolate_null_template
    test rdi, rdi
    jz interpolate_null_output
    test r12, r12
    jz interpolate_null_output

    ; For stub: just copy template to output
    mov rcx, rsi
    mov rdx, rdi
    mov r8, r12
    call CopyStringLimited

interpolate_done:
    xor eax, eax
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

interpolate_null_template:
    mov eax, ERROR_INVALID_PARAMETER
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

interpolate_null_output:
    mov eax, ERROR_INVALID_PARAMETER
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
PromptGen_Interpolate ENDP

; =============================================================================
; PromptGen_GetTemplate - Retrieve raw template by ID
; Entry:  rcx = template ID
;         rdx = output buffer pointer
;         r8  = output buffer size
; Exit:   rax = 0 (success) or error code
; =============================================================================
PromptGen_GetTemplate PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov ebx, ecx            ; ebx = template ID
    mov rdi, rdx            ; rdi = output buffer
    mov r12, r8             ; r12 = buffer size

    test rdi, rdi
    jz gettemplate_null
    test r12, r12
    jz gettemplate_null

    ; Select template based on ID
    lea rcx, TemplateGeneric    ; default
    cmp ebx, 0
    je gettemplate_copy
    lea rcx, TemplateCritic
    cmp ebx, 1
    je gettemplate_copy
    lea rcx, TemplateAuditor
    cmp ebx, 2
    je gettemplate_copy
    lea rcx, TemplateGeneric

gettemplate_copy:
    mov rdx, rdi
    mov r8, r12
    call CopyStringLimited

    xor eax, eax
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

gettemplate_null:
    mov eax, ERROR_INVALID_PARAMETER
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
PromptGen_GetTemplate ENDP

; =============================================================================
; PromptGen_ForceMode - Override auto-classification
; Entry:  rcx = mode ID to force (-1 to clear)
; Exit:   rax = 0 (success) or error code
; =============================================================================
PromptGen_ForceMode PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov ebx, ecx
    mov [g_ForceMode], ebx
    xor eax, eax

    add rsp, 40
    pop rbx
    ret
PromptGen_ForceMode ENDP

; Legacy stub for backward compatibility
PUBLIC rawrxd_recovery_stub_rawrxd_dynamicpromptengine
rawrxd_recovery_stub_rawrxd_dynamicpromptengine PROC
    xor eax, eax
    ret
rawrxd_recovery_stub_rawrxd_dynamicpromptengine ENDP

END
