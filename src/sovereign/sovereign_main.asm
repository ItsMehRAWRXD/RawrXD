; =============================================================================
; sovereign_main.asm - Sovereign Engine CLI Entry Point
; =============================================================================
; Command-line interface for the RawrXD inference engine.
; Built entirely with the native toolchain (no external dependencies).
;
; Commands:
;   sovereign load <model.gguf>     - Load and validate model
;   sovereign infer "<prompt>"      - Run inference
;   sovereign benchmark               - Performance benchmark
;   sovereign serve [--port <n>]    - HTTP server mode
;
; Build: rawrxd_native_assembler.exe /c sovereign_main.asm sovereign_main.obj
; Link:  rawrxd_native_linker.exe sovereign_main.obj /out:sovereign.exe
; =============================================================================

INCLUDE ..\asm\RawrXD_Common.inc

option casemap:none

; =============================================================================
; CONSTANTS
; =============================================================================

; Exit codes
EXIT_SUCCESS            EQU     0
EXIT_ERROR_ARGS         EQU     1
EXIT_ERROR_FILE         EQU     2
EXIT_ERROR_MEMORY       EQU     3
EXIT_ERROR_MODEL        EQU     4

; Buffer sizes
MAX_PATH_LEN            EQU     260
MAX_CMD_LEN             EQU     4096
MAX_PROMPT_LEN          EQU     32768
DEFAULT_PORT            EQU     8080

; Console handles
STD_INPUT_HANDLE        EQU     -10
STD_OUTPUT_HANDLE       EQU     -11
STD_ERROR_HANDLE        EQU     -12

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Command strings
cmd_load                DB      "load", 0
cmd_infer               DB      "infer", 0
cmd_benchmark           DB      "benchmark", 0
cmd_serve               DB      "serve", 0
cmd_help                DB      "help", 0
cmd_version             DB      "version", 0

; Error messages
err_usage               DB      "Usage: sovereign <command> [args]", 13, 10
                        DB      "Commands:", 13, 10
                        DB      "  load <model.gguf>     Load model file", 13, 10
                        DB      "  infer <prompt>        Run inference", 13, 10
                        DB      "  benchmark             Performance test", 13, 10
                        DB      "  serve [--port <n>]    HTTP server", 13, 10
                        DB      "  version               Show version", 13, 10
                        DB      "  help                  Show this help", 13, 10, 0

err_unknown_cmd         DB      "Error: Unknown command '", 0
err_cmd_suffix          DB      "'", 13, 10, 0
err_no_model            DB      "Error: No model file specified", 13, 10, 0
err_model_not_found     DB      "Error: Model file not found: ", 0
err_load_failed         DB      "Error: Failed to load model", 13, 10, 0

; Success messages
msg_version             DB      "Sovereign Engine v1.0.0 (Native Toolchain Build)", 13, 10
                        DB      "Architecture: x64", 13, 10
                        DB      "Build: ", __DATE__, " ", __TIME__, 13, 10, 0
msg_loading             DB      "Loading model: ", 0
msg_load_success        DB      "Model loaded successfully", 13, 10, 0
msg_inference_start     DB      "Running inference...", 13, 10, 0
msg_benchmark_start     DB      "Running benchmark...", 13, 10, 0
msg_server_start        DB      "Server starting on port ", 0

; Format strings
fmt_newline             DB      13, 10, 0
fmt_percent             DB      "%", 0

; Buffers
cmd_buffer              DB      MAX_CMD_LEN DUP(0)
path_buffer             DB      MAX_PATH_LEN DUP(0)
arg_buffer              DB      MAX_PROMPT_LEN DUP(0)

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; External functions (from kernel libraries)
EXTERNDEF Sovereign_Init:PROC
EXTERNDEF Sovereign_LoadModel:PROC
EXTERNDEF Sovereign_RunInference:PROC
EXTERNDEF Sovereign_RunBenchmark:PROC
EXTERNDEF Sovereign_StartServer:PROC
EXTERNDEF Sovereign_Shutdown:PROC

; Windows API imports
EXTERNDEF GetStdHandle:PROC
EXTERNDEF WriteFile:PROC
EXTERNDEF ExitProcess:PROC
EXTERNDEF lstrlenA:PROC

; =============================================================================
; ENTRY POINT
; =============================================================================

; _start - Entry point for the linker
PUBLIC _start
_start PROC
    ; Get argc and argv from the stack (Windows x64 calling convention)
    mov     rcx, [rsp+8]          ; argc
    mov     rdx, [rsp+16]         ; argv
    call    SovereignMain
    ; Exit with return code
    mov     rcx, rax              ; exit code
    call    ExitProcess
    ; Should never reach here
_start ENDP

SovereignMain PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Save argc, argv
    mov     [rbp+16], rcx         ; argc
    mov     [rbp+24], rdx         ; argv
    
    ; Check argc
    cmp     rcx, 1
    jle     ShowUsage
    
    ; Get command (argv[1])
    mov     rax, [rdx+8]          ; argv[1]
    mov     [rbp+32], rax         ; save command pointer
    
    ; Parse command
    mov     rcx, rax
    call    ParseCommand
    
    ; Jump to handler based on command ID
    cmp     eax, CMD_LOAD
    je      HandleLoad
    cmp     eax, CMD_INFER
    je      HandleInfer
    cmp     eax, CMD_BENCHMARK
    je      HandleBenchmark
    cmp     eax, CMD_SERVE
    je      HandleServe
    cmp     eax, CMD_VERSION
    je      HandleVersion
    cmp     eax, CMD_HELP
    je      ShowUsage
    
    ; Unknown command
    jmp     HandleUnknown

ShowUsage:
    lea     rcx, err_usage
    call    PrintString
    mov     eax, EXIT_SUCCESS
    jmp     Exit

HandleUnknown:
    lea     rcx, err_unknown_cmd
    call    PrintString
    mov     rcx, [rbp+32]
    call    PrintString
    lea     rcx, err_cmd_suffix
    call    PrintString
    mov     eax, EXIT_ERROR_ARGS
    jmp     Exit

HandleVersion:
    lea     rcx, msg_version
    call    PrintString
    mov     eax, EXIT_SUCCESS
    jmp     Exit

HandleLoad:
    ; Check for model file argument
    mov     rax, [rbp+16]         ; argc
    cmp     rax, 2
    jle     LoadNoModel
    
    ; Get model path (argv[2])
    mov     rax, [rbp+24]         ; argv
    mov     rcx, [rax+16]         ; argv[2]
    mov     [rbp+40], rcx         ; save model path
    
    ; Print loading message
    lea     rcx, msg_loading
    call    PrintString
    mov     rcx, [rbp+40]
    call    PrintString
    lea     rcx, fmt_newline
    call    PrintString
    
    ; Call Sovereign_LoadModel
    mov     rcx, [rbp+40]
    call    Sovereign_LoadModel
    test    eax, eax
    jz      LoadFailed
    
    ; Success
    lea     rcx, msg_load_success
    call    PrintString
    mov     eax, EXIT_SUCCESS
    jmp     Exit

LoadNoModel:
    lea     rcx, err_no_model
    call    PrintString
    mov     eax, EXIT_ERROR_ARGS
    jmp     Exit

LoadFailed:
    lea     rcx, err_load_failed
    call    PrintString
    mov     eax, EXIT_ERROR_MODEL
    jmp     Exit

HandleInfer:
    ; Check for prompt argument
    mov     rax, [rbp+16]
    cmp     rax, 2
    jle     InferNoPrompt
    
    ; TODO: Implement inference
    lea     rcx, msg_inference_start
    call    PrintString
    mov     eax, EXIT_SUCCESS
    jmp     Exit

InferNoPrompt:
    lea     rcx, err_no_model
    call    PrintString
    mov     eax, EXIT_ERROR_ARGS
    jmp     Exit

HandleBenchmark:
    lea     rcx, msg_benchmark_start
    call    PrintString
    call    Sovereign_RunBenchmark
    mov     eax, EXIT_SUCCESS
    jmp     Exit

HandleServe:
    ; Default port
    mov     dword ptr [rbp+48], DEFAULT_PORT
    
    ; Check for --port argument
    mov     rax, [rbp+16]
    cmp     rax, 4
    jl      ServeDefaultPort
    
    ; TODO: Parse --port argument
    
ServeDefaultPort:
    lea     rcx, msg_server_start
    call    PrintString
    mov     edx, [rbp+48]
    call    PrintInt
    lea     rcx, fmt_newline
    call    PrintString
    
    mov     ecx, [rbp+48]
    call    Sovereign_StartServer
    mov     eax, EXIT_SUCCESS
    jmp     Exit

Exit:
    add     rsp, 64
    pop     rbp
    ret

SovereignMain ENDP

; =============================================================================
; COMMAND PARSING
; =============================================================================

; Command IDs
CMD_UNKNOWN     EQU     0
CMD_LOAD        EQU     1
CMD_INFER       EQU     2
CMD_BENCHMARK   EQU     3
CMD_SERVE       EQU     4
CMD_VERSION     EQU     5
CMD_HELP        EQU     6

ParseCommand PROC
    push    rbp
    mov     rbp, rsp
    
    ; Compare with "load"
    lea     rdx, cmd_load
    call    StringCompare
    test    eax, eax
    jz      @F
    mov     eax, CMD_LOAD
    jmp     ParseDone
@@:
    ; Compare with "infer"
    lea     rdx, cmd_infer
    call    StringCompare
    test    eax, eax
    jz      @F
    mov     eax, CMD_INFER
    jmp     ParseDone
@@:
    ; Compare with "benchmark"
    lea     rdx, cmd_benchmark
    call    StringCompare
    test    eax, eax
    jz      @F
    mov     eax, CMD_BENCHMARK
    jmp     ParseDone
@@:
    ; Compare with "serve"
    lea     rdx, cmd_serve
    call    StringCompare
    test    eax, eax
    jz      @F
    mov     eax, CMD_SERVE
    jmp     ParseDone
@@:
    ; Compare with "version"
    lea     rdx, cmd_version
    call    StringCompare
    test    eax, eax
    jz      @F
    mov     eax, CMD_VERSION
    jmp     ParseDone
@@:
    ; Compare with "help"
    lea     rdx, cmd_help
    call    StringCompare
    test    eax, eax
    jz      @F
    mov     eax, CMD_HELP
    jmp     ParseDone
@@:
    ; Unknown command
    mov     eax, CMD_UNKNOWN

ParseDone:
    pop     rbp
    ret

ParseCommand ENDP

; =============================================================================
; UTILITY FUNCTIONS
; =============================================================================

; StringCompare(rcx=str1, rdx=str2) -> eax=1 if equal, 0 if not
StringCompare PROC
    push    rsi
    push    rdi
    mov     rsi, rcx
    mov     rdi, rdx

CompareLoop:
    mov     al, [rsi]
    mov     bl, [rdi]
    cmp     al, bl
    jne     NotEqual
    test    al, al
    jz      Equal
    inc     rsi
    inc     rdi
    jmp     CompareLoop

NotEqual:
    xor     eax, eax
    pop     rdi
    pop     rsi
    ret

Equal:
    mov     eax, 1
    pop     rdi
    pop     rsi
    ret

StringCompare ENDP

; PrintString(rcx=string) - Output string to console using Windows API
PrintString PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 40
    
    mov     rsi, rcx                    ; RSI = string pointer
    
    ; Get string length
    mov     rcx, rsi
    call    lstrlenA
    mov     rdi, rax                    ; RDI = length
    
    ; Get stdout handle
    mov     rcx, -11                    ; STD_OUTPUT_HANDLE
    call    GetStdHandle
    mov     rbx, rax                    ; RBX = handle
    
    ; Write to console
    mov     rcx, rbx                    ; hConsoleOutput
    mov     rdx, rsi                    ; lpBuffer
    mov     r8, rdi                     ; nNumberOfCharsToWrite
    xor     r9, r9                      ; lpNumberOfCharsWritten (optional)
    mov     qword ptr [rsp+32], 0       ; lpReserved
    call    WriteFile
    
    add     rsp, 40
    pop     rdi
    pop     rsi
    pop     rbx
    ret
PrintString ENDP

; PrintInt(edx=value) - Output integer to console (simplified)
PrintInt PROC
    push    rbx
    sub     rsp, 40
    
    ; Simple implementation: just return for now
    ; Full implementation would convert int to string
    
    add     rsp, 40
    pop     rbx
    ret
PrintInt ENDP

; =============================================================================
; END
; =============================================================================

END
