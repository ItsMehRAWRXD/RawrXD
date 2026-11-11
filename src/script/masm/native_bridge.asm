; RawrXD-Script Native Bridge (MASM)
; Phase 4: IDE Integration
; Provides low-level native function dispatch

include \masm64\include64\masm64rt.inc

; External imports from interpreter
extern JsValue_FromInt:PROC
extern JsValue_ToInt:PROC
extern JsValue_IsString:PROC
extern JsValue_IsInt32:PROC
extern JsValue_IsObject:PROC
extern JsValue_IsFunction:PROC

; Native function table
.data
align 8

; Native function dispatch table (256 entries)
NativeDispatchTable LABEL QWORD
    QWORD Native_Noop           ; 0
    QWORD Native_ConsoleLog     ; 1
    QWORD Native_ConsoleError   ; 2
    QWORD Native_ConsoleWarn    ; 3
    QWORD Native_ConsoleInfo    ; 4
    QWORD Native_ConsoleDebug   ; 5
    QWORD Native_WorkspaceOpen  ; 6
    QWORD Native_WorkspaceSave  ; 7
    QWORD Native_EditorGetText  ; 8
    QWORD Native_EditorSetText  ; 9
    QWORD Native_FSReadFile     ; 10
    QWORD Native_FSWriteFile    ; 11
    QWORD Native_FSExists       ; 12
    QWORD Native_FSMkdir        ; 13
    QWORD Native_ProcessExec    ; 14
    QWORD Native_ProcessExit    ; 15
    QWORD Native_WindowAlert    ; 16
    QWORD Native_WindowConfirm  ; 17
    QWORD Native_WindowPrompt   ; 18
    ; ... remaining entries are 0 (unimplemented)
    REPEAT 237
        QWORD 0
    ENDM

; Native function names (for lookup)
NativeFunctionNames LABEL BYTE
    db "noop", 0
    db "console.log", 0
    db "console.error", 0
    db "console.warn", 0
    db "console.info", 0
    db "console.debug", 0
    db "workspace.openTextDocument", 0
    db "workspace.saveAll", 0
    db "editor.getText", 0
    db "editor.setText", 0
    db "fs.readFile", 0
    db "fs.writeFile", 0
    db "fs.exists", 0
    db "fs.mkdir", 0
    db "process.exec", 0
    db "process.exit", 0
    db "window.showInformationMessage", 0
    db "window.showErrorMessage", 0
    db "window.showInputBox", 0

; Native function count
NativeFunctionCount DWORD 19

; Console output buffer
ConsoleBuffer BYTE 4096 DUP(0)
ConsoleBufferPos DWORD 0

; File I/O buffer
FileBuffer BYTE 65536 DUP(0)

.code

; ============================================================================
; Native Function Dispatcher
; ============================================================================

; NativeBridge_Dispatch
;   rcx = native function index
;   rdx = argument count
;   r8  = pointer to argument array (JsValue*)
;   r9  = this value (JsValue)
; Returns:
;   rax = result (JsValue)
NativeBridge_Dispatch PROC FRAME
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .pushreg r12
    .pushreg r13
    .pushreg r14
    .pushreg r15
    .endprolog
    
    ; Validate index
    cmp ecx, 256
    jae invalid_index
    
    ; Load dispatch table
    lea rax, NativeDispatchTable
    mov rax, [rax + rcx * 8]
    
    ; Check if implemented
    test rax, rax
    jz unimplemented
    
    ; Call native function
    ; rcx = arg count, rdx = args, r8 = this
    mov rcx, rdx        ; arg count
    mov rdx, r8         ; args pointer
    mov r8, r9          ; this value
    call rax
    
    jmp done
    
invalid_index:
    ; Return undefined
    mov rax, 0x7FF8000000000001h  ; JS_UNDEFINED
    jmp done
    
unimplemented:
    ; Return undefined
    mov rax, 0x7FF8000000000001h  ; JS_UNDEFINED
    
done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
NativeBridge_Dispatch ENDP

; ============================================================================
; Native Function Implementations
; ============================================================================

; Native_Noop - Does nothing, returns undefined
;   rcx = arg count
;   rdx = args
;   r8  = this
Native_Noop PROC
    mov rax, 0x7FF8000000000001h  ; JS_UNDEFINED
    ret
Native_Noop ENDP

; Native_ConsoleLog - Output to console
;   rcx = arg count
;   rdx = args (JsValue array)
;   r8  = this
Native_ConsoleLog PROC FRAME
    push rbx
    push rsi
    push rdi
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .endprolog
    
    ; Reset buffer
    mov dword ptr [ConsoleBufferPos], 0
    
    ; Iterate through arguments
    mov rsi, rdx        ; args pointer
    mov rbx, rcx        ; arg count
    xor rdi, rdi        ; arg index
    
arg_loop:
    cmp rdi, rbx
    jge print_output
    
    ; Add space separator if not first
    test rdi, rdi
    jz first_arg
    
    mov eax, [ConsoleBufferPos]
    mov byte ptr [ConsoleBuffer + rax], ' '
    inc dword ptr [ConsoleBufferPos]
    
first_arg:
    ; Get argument value
    mov rax, [rsi + rdi * 8]    ; Load JsValue
    
    ; Convert to string and append to buffer
    ; For now, just handle integers
    call JsValue_ToInt
    
    ; Convert int to string
    lea rcx, ConsoleBuffer
    mov edx, [ConsoleBufferPos]
    add rcx, rdx
    mov edx, eax
    call IntToString
    add [ConsoleBufferPos], eax
    
    inc rdi
    jmp arg_loop
    
print_output:
    ; Add newline
    mov eax, [ConsoleBufferPos]
    mov byte ptr [ConsoleBuffer + rax], 0
    
    ; Output to console
    lea rcx, ConsoleBuffer
    call OutputDebugStringA
    
    ; Also to stdout
    lea rcx, ConsoleBuffer
    call printf
    
    ; Return undefined
    mov rax, 0x7FF8000000000001h
    
    pop rdi
    pop rsi
    pop rbx
    ret
Native_ConsoleLog ENDP

; Native_ConsoleError - Output error to console
;   rcx = arg count
;   rdx = args
;   r8  = this
Native_ConsoleError PROC FRAME
    push rbx
    push rsi
    push rdi
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .endprolog
    
    ; Prefix with "ERROR: "
    lea rcx, ErrorPrefix
    call printf
    
    ; Then do normal log
    mov rsi, rdx
    mov rbx, rcx
    call Native_ConsoleLog
    
    pop rdi
    pop rsi
    pop rbx
    ret
ErrorPrefix db "ERROR: ", 0
Native_ConsoleError ENDP

; Native_ConsoleWarn - Output warning to console
Native_ConsoleWarn PROC FRAME
    push rbx
    push rsi
    push rdi
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .endprolog
    
    lea rcx, WarnPrefix
    call printf
    
    mov rsi, rdx
    mov rbx, rcx
    call Native_ConsoleLog
    
    pop rdi
    pop rsi
    pop rbx
    ret
WarnPrefix db "WARNING: ", 0
Native_ConsoleWarn ENDP

; Native_ConsoleInfo - Output info to console
Native_ConsoleInfo PROC FRAME
    push rbx
    push rsi
    push rdi
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .endprolog
    
    lea rcx, InfoPrefix
    call printf
    
    mov rsi, rdx
    mov rbx, rcx
    call Native_ConsoleLog
    
    pop rdi
    pop rsi
    pop rbx
    ret
InfoPrefix db "INFO: ", 0
Native_ConsoleInfo ENDP

; Native_ConsoleDebug - Output debug to console
Native_ConsoleDebug PROC FRAME
    push rbx
    push rsi
    push rdi
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .endprolog
    
    lea rcx, DebugPrefix
    call printf
    
    mov rsi, rdx
    mov rbx, rcx
    call Native_ConsoleLog
    
    pop rdi
    pop rsi
    pop rbx
    ret
DebugPrefix db "DEBUG: ", 0
Native_ConsoleDebug ENDP

; ============================================================================
; Workspace API
; ============================================================================

; Native_WorkspaceOpen - Open a text document
;   rcx = arg count
;   rdx = args[0] = file path (string)
; Returns: document object or null
Native_WorkspaceOpen PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    
    ; For now, just log and return null
    lea rcx, OpenMsg
    call OutputDebugStringA
    
    mov rax, 0x7FF8000000000002h  ; JS_NULL
    
    pop rbx
    ret
OpenMsg db "[Native] Opening document", 0
Native_WorkspaceOpen ENDP

; Native_WorkspaceSave - Save all documents
Native_WorkspaceSave PROC FRAME
    lea rcx, SaveMsg
    call OutputDebugStringA
    
    mov rax, 0x7FF8000000000001h  ; JS_UNDEFINED
    ret
SaveMsg db "[Native] Saving all documents", 0
Native_WorkspaceSave ENDP

; ============================================================================
; Editor API
; ============================================================================

; Native_EditorGetText - Get editor text
; Returns: string
Native_EditorGetText PROC FRAME
    ; Return placeholder string
    ; In real implementation, would get from IDE
    mov rax, 0x7FF8000000000002h  ; JS_NULL (placeholder)
    ret
Native_EditorGetText ENDP

; Native_EditorSetText - Set editor text
;   rcx = arg count
;   rdx = args[0] = text (string)
Native_EditorSetText PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    
    lea rcx, SetTextMsg
    call OutputDebugStringA
    
    mov rax, 0x7FF8000000000001h  ; JS_UNDEFINED
    
    pop rbx
    ret
SetTextMsg db "[Native] Setting editor text", 0
Native_EditorSetText ENDP

; ============================================================================
; File System API
; ============================================================================

; Native_FSReadFile - Read file contents
;   rcx = arg count
;   rdx = args[0] = path (string)
; Returns: string contents or null
Native_FSReadFile PROC FRAME
    push rbx
    push rsi
    push rdi
    push r12
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .pushreg r12
    .endprolog
    
    ; Get path from first argument
    mov rsi, rdx        ; args
    mov rbx, [rsi]      ; first arg (JsValue)
    
    ; Check if string
    ; For now, assume it is and extract pointer
    ; Real implementation would validate
    
    ; Open file
    ; rcx = filename, rdx = mode
    ; Returns: FILE* in rax
    
    ; For now, return empty string
    mov rax, 0x7FF8000000000002h  ; JS_NULL
    
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Native_FSReadFile ENDP

; Native_FSWriteFile - Write file contents
;   rcx = arg count
;   rdx = args[0] = path, args[1] = content
; Returns: boolean success
Native_FSWriteFile PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    
    lea rcx, WriteFileMsg
    call OutputDebugStringA
    
    ; Return true
    mov rax, 0x7FF8000000000006h  ; JS_TRUE
    
    pop rbx
    ret
WriteFileMsg db "[Native] Writing file", 0
Native_FSWriteFile ENDP

; Native_FSExists - Check if file exists
;   rcx = arg count
;   rdx = args[0] = path
; Returns: boolean
Native_FSExists PROC FRAME
    ; For now, always return false
    mov rax, 0x7FF8000000000007h  ; JS_FALSE
    ret
Native_FSExists ENDP

; Native_FSMkdir - Create directory
;   rcx = arg count
;   rdx = args[0] = path
; Returns: boolean success
Native_FSMkdir PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    
    lea rcx, MkdirMsg
    call OutputDebugStringA
    
    mov rax, 0x7FF8000000000006h  ; JS_TRUE
    
    pop rbx
    ret
MkdirMsg db "[Native] Creating directory", 0
Native_FSMkdir ENDP

; ============================================================================
; Process API
; ============================================================================

; Native_ProcessExec - Execute command
;   rcx = arg count
;   rdx = args[0] = command string
; Returns: output string
Native_ProcessExec PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    
    lea rcx, ExecMsg
    call OutputDebugStringA
    
    ; Return empty string
    mov rax, 0x7FF8000000000002h  ; JS_NULL
    
    pop rbx
    ret
ExecMsg db "[Native] Executing process", 0
Native_ProcessExec ENDP

; Native_ProcessExit - Exit process
;   rcx = arg count
;   rdx = args[0] = exit code
Native_ProcessExit PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    
    ; Get exit code
    mov rsi, rdx
    mov rbx, [rsi]      ; first arg
    
    ; Convert to int
    call JsValue_ToInt
    mov ecx, eax
    
    ; Exit
    call ExitProcess
    
    ; Never reached
    xor rax, rax
    pop rbx
    ret
Native_ProcessExit ENDP

; ============================================================================
; Window API
; ============================================================================

; Native_WindowAlert - Show alert message
;   rcx = arg count
;   rdx = args[0] = message
Native_WindowAlert PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    
    lea rcx, AlertMsg
    call OutputDebugStringA
    
    mov rax, 0x7FF8000000000001h  ; JS_UNDEFINED
    
    pop rbx
    ret
AlertMsg db "[Native] Window alert", 0
Native_WindowAlert ENDP

; Native_WindowConfirm - Show confirm dialog
;   rcx = arg count
;   rdx = args[0] = message
; Returns: boolean
Native_WindowConfirm PROC FRAME
    ; For now, always return true
    mov rax, 0x7FF8000000000006h  ; JS_TRUE
    ret
Native_WindowConfirm ENDP

; Native_WindowPrompt - Show prompt dialog
;   rcx = arg count
;   rdx = args[0] = message, args[1] = default
; Returns: string or null
Native_WindowPrompt PROC FRAME
    ; Return null (cancelled)
    mov rax, 0x7FF8000000000002h  ; JS_NULL
    ret
Native_WindowPrompt ENDP

; ============================================================================
; Helper Functions
; ============================================================================

; IntToString - Convert integer to string
;   rcx = buffer
;   edx = value
; Returns:
;   eax = string length
IntToString PROC FRAME
    push rbx
    push rsi
    push rdi
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .endprolog
    
    mov rdi, rcx        ; buffer
    mov eax, edx        ; value
    mov ebx, 10         ; divisor
    xor ecx, ecx        ; digit count
    
    ; Handle negative
    test eax, eax
    jns positive
    neg eax
    mov byte ptr [rdi], '-'
    inc rdi
    inc ecx
    
positive:
    ; Convert to digits (reverse order)
    mov rsi, rdi        ; save start
    
digit_loop:
    xor edx, edx
    div ebx
    add dl, '0'
    mov [rdi], dl
    inc rdi
    inc ecx
    test eax, eax
    jnz digit_loop
    
    ; Null terminate
    mov byte ptr [rdi], 0
    
    ; Reverse the string
    mov rdx, rdi
    dec rdx             ; last char
    mov rdi, rsi        ; first char
    
    ; Check if we had negative sign
    cmp byte ptr [rdi], '-'
    jne reverse_loop
    inc rdi
    
reverse_loop:
    cmp rdi, rdx
    jge done_reverse
    mov al, [rdi]
    mov bl, [rdx]
    mov [rdi], bl
    mov [rdx], al
    inc rdi
    dec rdx
    jmp reverse_loop
    
done_reverse:
    mov eax, ecx        ; return length
    
    pop rdi
    pop rsi
    pop rbx
    ret
IntToString ENDP

; ============================================================================
; Export table
; ============================================================================

PUBLIC NativeBridge_Dispatch
PUBLIC NativeDispatchTable
PUBLIC NativeFunctionNames
PUBLIC NativeFunctionCount

END
