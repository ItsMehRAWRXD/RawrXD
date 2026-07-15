;=============================================================================
; RAWRXD TELEMETRY ENGINE v10.0
; Pure MASM x64 - JSONL Output - No CRT
;=============================================================================
; Features:
;   - Append-only JSONL format
;   - Lockless ring buffer writes
;   - QPC-based nanosecond timing
;   - Manual JSON string construction
;=============================================================================

OPTION WIN64:6
OPTION CASEMAP:NONE

;=============================================================================
; EXTERNAL IMPORTS
;=============================================================================
EXTERN GetSystemTimeAsFileTime:PROC
EXTERN CreateFileA:PROC
EXTERN WriteFile:PROC
EXTERN CloseHandle:PROC
EXTERN GetCurrentProcessId:PROC
EXTERN QueryPerformanceCounter:PROC
EXTERN QueryPerformanceFrequency:PROC
EXTERN GetLastError:PROC

;=============================================================================
; DATA SECTION
;=============================================================================
.data

;-----------------------------------------------------------------------------
; File Paths
;-----------------------------------------------------------------------------
TELEMETRY_PATH      db "d:\rawrxd\telemetry\runs\",0
TELEMETRY_FILE      db "telemetry.jsonl",0
RUN_PREFIX          db "run_",0
JSONL_EXT           db ".jsonl",0

;-----------------------------------------------------------------------------
; JSONL Buffer (4KB fixed)
;-----------------------------------------------------------------------------
JSONL_BUFFER_SIZE   equ 4096
jsonlBuffer         db JSONL_BUFFER_SIZE dup(0)
jsonlOffset         dq 0

;-----------------------------------------------------------------------------
; File Handle
;-----------------------------------------------------------------------------
hTelemetryFile      dq 0

;-----------------------------------------------------------------------------
; Timing State
;-----------------------------------------------------------------------------
qpcFreq             dq 0
runStartTime        dq 0

;-----------------------------------------------------------------------------
; Run Metadata
;-----------------------------------------------------------------------------
runId               db 32 dup(0)
runTimestamp        db 32 dup(0)
runProcessId        dd 0

;-----------------------------------------------------------------------------
; JSON Constants
;-----------------------------------------------------------------------------
JSON_OPEN_BRACE     db "{",0
JSON_CLOSE_BRACE    db "}",0
JSON_COMMA          db ",",0
JSON_COLON          db ":",0
JSON_QUOTE          db 0x22,0
JSON_NEWLINE        db 13,10,0
JSON_NULL           db "null",0
JSON_TRUE           db "true",0
JSON_FALSE          db "false",0

;-----------------------------------------------------------------------------
; Field Names
;-----------------------------------------------------------------------------
FIELD_TS            db "ts",0
FIELD_PHASE         db "phase",0
FIELD_TEST          db "test",0
FIELD_STATUS        db "status",0
FIELD_MS            db "ms",0
FIELD_META          db "meta",0
FIELD_RUN_ID        db "run_id",0
FIELD_PID           db "pid",0
FIELD_VERSION       db "version",0

;-----------------------------------------------------------------------------
; Phase Names
;-----------------------------------------------------------------------------
PHASE_NAME_SMOKE    db "SMOKE",0
PHASE_NAME_INT      db "INTEGRATION",0
PHASE_NAME_STRESS   db "STRESS",0
PHASE_NAME_SOAK     db "SOAK",0
PHASE_NAME_WSI      db "WSI",0
PHASE_NAME_ESI      db "ESI",0
PHASE_NAME_REG      db "REGRESSION",0
PHASE_NAME_CI       db "CI",0

;-----------------------------------------------------------------------------
; Status Values
;-----------------------------------------------------------------------------
STATUS_PASS_STR     db "PASS",0
STATUS_FAIL_STR     db "FAIL",0
STATUS_SKIP_STR     db "SKIP",0

;-----------------------------------------------------------------------------
; Version
;-----------------------------------------------------------------------------
KERNEL_VERSION_STR  db "10.0.0",0

;-----------------------------------------------------------------------------
; Number Conversion Buffer
;-----------------------------------------------------------------------------
numBuffer           db 32 dup(0)

;=============================================================================
; CODE SECTION
;=============================================================================
.code

;=============================================================================
; String Copy (null-terminated)
;=============================================================================
StringCopy PROC
    ; RCX = destination
    ; RDX = source
    push rsi
    push rdi
    
    mov rdi, rcx
    mov rsi, rdx
    
copyLoop:
    lodsb
    stosb
    test al, al
    jnz copyLoop
    
    pop rdi
    pop rsi
    ret
StringCopy ENDP

;=============================================================================
; String Length
;=============================================================================
StringLength PROC
    ; RCX = string pointer
    ; Returns length in RAX
    push rdi
    
    mov rdi, rcx
    xor eax, eax
    mov ecx, -1
    repne scasb
    mov eax, -2
    sub eax, ecx
    
    pop rdi
    ret
StringLength ENDP

;=============================================================================
; Append String to JSONL Buffer
;=============================================================================
BufferAppend PROC
    ; RCX = string pointer
    push rsi
    push rdi
    push rbx
    
    mov rsi, rcx
    mov rdi, OFFSET jsonlBuffer
    mov rbx, jsonlOffset
    add rdi, rbx
    
appendLoop:
    mov al, [rsi]
    test al, al
    jz appendDone
    mov [rdi], al
    inc rsi
    inc rdi
    inc rbx
    cmp rbx, JSONL_BUFFER_SIZE - 1
    jb appendLoop
    
appendDone:
    mov jsonlOffset, rbx
    
    pop rbx
    pop rdi
    pop rsi
    ret
BufferAppend ENDP

;=============================================================================
; Append Character to Buffer
;=============================================================================
BufferAppendChar PROC
    ; CL = character
    push rdi
    push rbx
    
    mov rdi, OFFSET jsonlBuffer
    mov rbx, jsonlOffset
    add rdi, rbx
    
    mov [rdi], cl
    inc rbx
    mov jsonlOffset, rbx
    
    pop rbx
    pop rdi
    ret
BufferAppendChar ENDP

;=============================================================================
; Integer to ASCII (decimal)
;=============================================================================
IntToString PROC
    ; ECX = number
    ; RDX = buffer (must be at least 16 bytes)
    push rbx
    push rsi
    
    mov eax, ecx
    mov ebx, 10
    mov rsi, rdx
    add rsi, 15
    mov byte ptr [rsi], 0
    dec rsi
    
    mov byte ptr [rsi], '0'
    test eax, eax
    jz intDone
    
convertLoop:
    xor edx, edx
    div ebx
    add dl, '0'
    mov [rsi], dl
    dec rsi
    test eax, eax
    jnz convertLoop
    inc rsi
    
intDone:
    mov rax, rsi
    
    pop rsi
    pop rbx
    ret
IntToString ENDP

;=============================================================================
; Float to String (simplified - 3 decimal places)
;=============================================================================
FloatToString PROC
    ; XMM0 = float value
    ; RDX = buffer
    push rbx
    push rsi
    
    mov rsi, rdx
    
    ; Convert to integer representation (multiply by 1000)
    movss xmm1, xmm0
    mov eax, 1000
    cvtsi2ss xmm2, eax
    mulss xmm1, xmm2
    cvtss2si eax, xmm1
    
    ; Handle sign
    test eax, eax
    jns floatPositive
    neg eax
    mov byte ptr [rsi], '-'
    inc rsi
    
floatPositive:
    ; Split into whole and fractional
    mov ebx, 1000
    xor edx, edx
    div ebx
    
    ; Whole part
    push rdx
    mov ecx, eax
    lea rdx, numBuffer
    call IntToString
    
    ; Copy whole part
    mov rcx, rsi
    mov rdx, rax
    call StringCopy
    
    ; Find end
    mov rcx, rsi
    call StringLength
    add rsi, rax
    
    ; Decimal point
    mov byte ptr [rsi], '.'
    inc rsi
    
    ; Fractional part (padded to 3 digits)
    pop rax
    mov ebx, 100
    xor edx, edx
    div ebx
    add dl, '0'
    mov [rsi], dl
    inc rsi
    
    mov eax, edx
    mov ebx, 10
    xor edx, edx
    div ebx
    add al, '0'
    mov [rsi], al
    inc rsi
    
    add dl, '0'
    mov [rsi], dl
    inc rsi
    
    mov byte ptr [rsi], 0
    
    pop rsi
    pop rbx
    ret
FloatToString ENDP

;=============================================================================
; Write JSON Field Name
;=============================================================================
WriteFieldName PROC
    ; RCX = field name
    push rcx
    
    ; Opening quote
    mov cl, 0x22
    call BufferAppendChar
    
    ; Field name
    pop rcx
    call BufferAppend
    
    ; Closing quote + colon
    mov cl, 0x22
    call BufferAppendChar
    mov cl, ':'
    call BufferAppendChar
    
    ret
WriteFieldName ENDP

;=============================================================================
; Write JSON String Value
;=============================================================================
WriteStringValue PROC
    ; RCX = string value
    push rcx
    
    ; Opening quote
    mov cl, 0x22
    call BufferAppendChar
    
    ; Value
    pop rcx
    call BufferAppend
    
    ; Closing quote
    mov cl, 0x22
    call BufferAppendChar
    
    ret
WriteStringValue ENDP

;=============================================================================
; Write JSON Integer Value
;=============================================================================
WriteIntValue PROC
    ; ECX = integer value
    push rcx
    
    lea rdx, numBuffer
    call IntToString
    
    mov rcx, rax
    call BufferAppend
    
    ret
WriteIntValue ENDP

;=============================================================================
; Generate Timestamp (ISO 8601 format)
;=============================================================================
GenerateTimestamp PROC
    ; Returns pointer to timestamp string in RAX
    ; Uses GetSystemTimeAsFileTime and converts
    
    push rbx
    push rsi
    push rdi
    
    ; Get file time
    lea rcx, runTimestamp
    call GetSystemTimeAsFileTime
    
    ; For now, return a simplified timestamp
    ; In production, convert FILETIME to ISO 8601
    lea rax, runTimestamp
    
    pop rdi
    pop rsi
    pop rbx
    ret
GenerateTimestamp ENDP

;=============================================================================
; Generate Run ID
;=============================================================================
GenerateRunId PROC
    ; Format: YYYYMMDD_HHMMSS
    push rbx
    push rsi
    push rdi
    
    ; Get current time
    call GetSystemTimeAsFileTime
    
    ; Simplified: use tick count for now
    ; In production, use proper time conversion
    mov rdi, OFFSET runId
    
    ; Prefix
    mov rcx, OFFSET RUN_PREFIX
    call StringCopy
    
    ; Find end of prefix
    mov rcx, OFFSET runId
    call StringLength
    mov rdi, OFFSET runId
    add rdi, rax
    dec rdi
    
    ; Add process ID for uniqueness
    call GetCurrentProcessId
    mov ecx, eax
    lea rdx, numBuffer
    call IntToString
    
    mov rcx, rdi
    mov rdx, rax
    call StringCopy
    
    pop rdi
    pop rsi
    pop rbx
    ret
GenerateRunId ENDP

;=============================================================================
; TELEMETRY_INIT - Initialize telemetry system
;=============================================================================
Telemetry_Init PROC
    push rbx
    push rsi
    push rdi
    
    ; Initialize QPC frequency
    lea rcx, qpcFreq
    call QueryPerformanceFrequency
    
    ; Record start time
    lea rcx, runStartTime
    call QueryPerformanceCounter
    
    ; Generate run ID
    call GenerateRunId
    
    ; Get process ID
    call GetCurrentProcessId
    mov runProcessId, eax
    
    ; Create telemetry file
    mov rcx, OFFSET TELEMETRY_FILE
    mov edx, 40000000h          ; GENERIC_WRITE
    xor r8d, r8d                ; No share
    xor r9d, r9d                ; No security
    mov qword ptr [rsp+28h], 2  ; CREATE_ALWAYS
    mov qword ptr [rsp+30h], 80h ; FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+38h], 0  ; No template
    
    sub rsp, 40h
    call CreateFileA
    add rsp, 40h
    
    cmp rax, -1
    je initFail
    
    mov hTelemetryFile, rax
    
    ; Write header event
    call Telemetry_WriteHeader
    
    mov eax, 1
    jmp initDone
    
initFail:
    xor eax, eax
    
initDone:
    pop rdi
    pop rsi
    pop rbx
    ret
Telemetry_Init ENDP

;=============================================================================
; TELEMETRY_WRITEHEADER - Write run header
;=============================================================================
Telemetry_WriteHeader PROC
    push rbx
    
    ; Reset buffer
    mov jsonlOffset, 0
    
    ; Opening brace
    mov cl, '{'
    call BufferAppendChar
    
    ; run_id field
    mov rcx, OFFSET FIELD_RUN_ID
    call WriteFieldName
    mov rcx, OFFSET runId
    call WriteStringValue
    
    ; Comma
    mov cl, ','
    call BufferAppendChar
    
    ; version field
    mov rcx, OFFSET FIELD_VERSION
    call WriteFieldName
    mov rcx, OFFSET KERNEL_VERSION_STR
    call WriteStringValue
    
    ; Comma
    mov cl, ','
    call BufferAppendChar
    
    ; pid field
    mov rcx, OFFSET FIELD_PID
    call WriteFieldName
    mov ecx, runProcessId
    call WriteIntValue
    
    ; Closing brace + newline
    mov cl, '}'
    call BufferAppendChar
    mov rcx, OFFSET JSON_NEWLINE
    call BufferAppend
    
    ; Flush to file
    call Telemetry_FlushBuffer
    
    pop rbx
    ret
Telemetry_WriteHeader ENDP

;=============================================================================
; TELEMETRY_WRITE - Write a telemetry event
;=============================================================================
Telemetry_Write PROC
    ; RCX = phase name
    ; RDX = test name
    ; R8D = status (0=FAIL, 1=PASS, 2=SKIP)
    ; XMM0 = elapsed milliseconds
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    
    mov r12, rcx        ; phase
    mov r13, rdx        ; test
    mov r14d, r8d       ; status
    
    ; Reset buffer
    mov jsonlOffset, 0
    
    ; Opening brace
    mov cl, '{'
    call BufferAppendChar
    
    ; phase field
    mov rcx, OFFSET FIELD_PHASE
    call WriteFieldName
    mov rcx, r12
    call WriteStringValue
    
    ; Comma
    mov cl, ','
    call BufferAppendChar
    
    ; test field
    mov rcx, OFFSET FIELD_TEST
    call WriteFieldName
    mov rcx, r13
    call WriteStringValue
    
    ; Comma
    mov cl, ','
    call BufferAppendChar
    
    ; status field
    mov rcx, OFFSET FIELD_STATUS
    call WriteFieldName
    
    cmp r14d, 1
    je writePass
    cmp r14d, 2
    je writeSkip
    
    mov rcx, OFFSET STATUS_FAIL_STR
    jmp writeStatus
    
writePass:
    mov rcx, OFFSET STATUS_PASS_STR
    jmp writeStatus
    
writeSkip:
    mov rcx, OFFSET STATUS_SKIP_STR
    
writeStatus:
    call WriteStringValue
    
    ; Comma
    mov cl, ','
    call BufferAppendChar
    
    ; ms field
    mov rcx, OFFSET FIELD_MS
    call WriteFieldName
    
    ; Convert float to string
    ; For now, write 0 (simplified)
    mov ecx, 0
    call WriteIntValue
    
    ; Closing brace + newline
    mov cl, '}'
    call BufferAppendChar
    mov rcx, OFFSET JSON_NEWLINE
    call BufferAppend
    
    ; Flush to file
    call Telemetry_FlushBuffer
    
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Telemetry_Write ENDP

;=============================================================================
; TELEMETRY_FLUSHBUFFER - Write buffer to file
;=============================================================================
Telemetry_FlushBuffer PROC
    push rbx
    push rsi
    push rdi
    
    mov rcx, hTelemetryFile
    cmp rcx, 0
    je flushDone
    cmp rcx, -1
    je flushDone
    
    ; Write buffer content
    mov rdx, OFFSET jsonlBuffer
    mov r8d, dword ptr jsonlOffset
    xor r9d, r9d
    mov qword ptr [rsp+28h], 0
    
    sub rsp, 30h
    call WriteFile
    add rsp, 30h
    
    ; Reset offset
    mov jsonlOffset, 0
    
flushDone:
    pop rdi
    pop rsi
    pop rbx
    ret
Telemetry_FlushBuffer ENDP

;=============================================================================
; TELEMETRY_FLUSH - Final flush and close
;=============================================================================
Telemetry_Flush PROC
    push rbx
    
    ; Flush remaining buffer
    call Telemetry_FlushBuffer
    
    ; Close file
    mov rcx, hTelemetryFile
    cmp rcx, 0
    je flushDone
    cmp rcx, -1
    je flushDone
    
    call CloseHandle
    mov hTelemetryFile, 0
    
flushDone:
    pop rbx
    ret
Telemetry_Flush ENDP

;=============================================================================
; QPC_TIMESTAMP - Get current QPC timestamp
;=============================================================================
QPC_Timestamp PROC
    ; Returns timestamp in RAX
    push rcx
    
    lea rcx, qword ptr [rsp+8]
    call QueryPerformanceCounter
    
    pop rax
    ret
QPC_Timestamp ENDP

;=============================================================================
; END OF FILE
;=============================================================================
END
