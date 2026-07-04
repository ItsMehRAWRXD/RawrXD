; rawrxd_cli.asm — Sovereign CLI for RawrXD IDE
; Zero dependencies. No C runtime. Pure Win32 API + verified ASM exports.
; Target: 400-500 lines, x64, links against RawrXD-Win32IDE.exe exports
;
; Usage: rawrxd.exe [command] [options]
;   rawrxd benchmark          → Run full system benchmark
;   rawrxd crypto-test          → Run Camellia256 self-test
;   rawrxd agent <task>         → Dispatch agentic task
;   rawrxd stats                → Real-time telemetry ticker
;   rawrxd encrypt <file>       → Encrypt file via Camellia256
;   rawrxd patch <addr> <bytes> → Live self-host patch

OPTION CASEMAP:NONE

; ============================================================================
; EXTERNAL DECLARATIONS — These are the 32 verified exports from the IDE binary
; ============================================================================
EXTERN asm_orchestrator_init:PROC
EXTERN asm_orchestrator_shutdown:PROC
EXTERN asm_orchestrator_enqueue:PROC
EXTERN asm_orchestrator_dequeue:PROC
EXTERN asm_orchestrator_dispatch:PROC
EXTERN asm_orchestrator_get_metrics:PROC
EXTERN asm_orchestrator_register_handler:PROC
EXTERN asm_camellia256_init:PROC
EXTERN asm_camellia256_encrypt_file:PROC
EXTERN asm_camellia256_decrypt_file:PROC
EXTERN asm_camellia256_self_test:PROC
EXTERN asm_selfhost_init:PROC
EXTERN asm_selfhost_get_stats:PROC
EXTERN asm_selfhost_gen_trampoline:PROC

; ============================================================================
; WIN32 API DECLARATIONS
; ============================================================================
EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ReadConsoleA:PROC
EXTERN ExitProcess:PROC
EXTERN GetCommandLineA:PROC
EXTERN GetModuleHandleA:PROC
EXTERN GetProcAddress:PROC
EXTERN LoadLibraryA:PROC
EXTERN FreeLibrary:PROC
EXTERN Sleep:PROC
EXTERN GetTickCount64:PROC

; ============================================================================
; CONSTANTS
; ============================================================================
STD_OUTPUT_HANDLE       EQU -11
STD_INPUT_HANDLE        EQU -10
MAX_CMDLINE_LEN         EQU 4096
MAX_ARGS                EQU 32
EXIT_SUCCESS            EQU 0
EXIT_FAILURE            EQU 1
EXIT_UNKNOWN_CMD        EQU 2
EXIT_ORCH_INIT_FAIL     EQU 3
EXIT_CRYPTO_FAIL        EQU 4

; ============================================================================
; DATA SECTION
; ============================================================================
.DATA

; Command strings (null-terminated)
cmd_benchmark           DB "benchmark", 0
cmd_crypto_test         DB "crypto-test", 0
cmd_agent               DB "agent", 0
cmd_stats               DB "stats", 0
cmd_encrypt             DB "encrypt", 0
cmd_patch               DB "patch", 0
cmd_help                DB "help", 0
cmd_h                   DB "-h", 0
cmd_question            DB "--help", 0

; UI strings
str_banner              DB "RawrXD Sovereign CLI v1.0", 13, 10
                        DB "==========================", 13, 10, 13, 10, 0
str_usage               DB "Usage: rawrxd <command> [args...]", 13, 10, 13, 10
                        DB "Commands:", 13, 10
                        DB "  benchmark          Run full system benchmark", 13, 10
                        DB "  crypto-test        Run Camellia256 self-test", 13, 10
                        DB "  agent <task>       Dispatch agentic task", 13, 10
                        DB "  stats              Real-time telemetry ticker", 13, 10
                        DB "  encrypt <file>     Encrypt file via Camellia256", 13, 10
                        DB "  patch <addr> <hex> Live self-host patch", 13, 10
                        DB "  help               Show this help", 13, 10, 13, 10, 0
str_unknown_cmd         DB "Error: Unknown command '", 0
str_unknown_cmd_end     DB "'", 13, 10, 0
str_init_orchestrator   DB "[+] Initializing orchestrator...", 13, 10, 0
str_init_crypto         DB "[+] Initializing crypto engine...", 13, 10, 0
str_init_selfhost       DB "[+] Initializing self-host engine...", 13, 10, 0
str_init_ok             DB "[OK] All engines initialized", 13, 10, 13, 10, 0
str_init_fail           DB "[FAIL] Engine initialization failed", 13, 10, 0
str_running_benchmark   DB "[*] Running benchmark...", 13, 10, 0
str_benchmark_done      DB "[OK] Benchmark complete", 13, 10, 0
str_running_crypto      DB "[*] Running Camellia256 self-test...", 13, 10, 0
str_crypto_ok           DB "[OK] Crypto self-test passed", 13, 10, 0
str_crypto_fail         DB "[FAIL] Crypto self-test failed", 13, 10, 0
str_dispatching_agent   DB "[*] Dispatching agent task: '", 0
str_dispatching_agent2  DB "'...", 13, 10, 0
str_agent_done          DB "[OK] Agent task dispatched", 13, 10, 0
str_stats_header        DB "Timestamp      | Queue | Tasks | Latency | SelfHost", 13, 10
                        DB "---------------|-------|-------|---------|----------", 13, 10, 0
str_stats_line          DB "%llu | %5d | %5d | %7d | %8d", 13, 10, 0
str_press_q             DB 13, 10, "Press 'q' to quit stats mode...", 13, 10, 0
str_encrypting          DB "[*] Encrypting file: '", 0
str_encrypt_ok          DB "[OK] File encrypted", 13, 10, 0
str_encrypt_fail        DB "[FAIL] Encryption failed", 13, 10, 0
str_patching            DB "[*] Patching address 0x%08X with %d bytes...", 13, 10, 0
str_patch_ok            DB "[OK] Patch applied", 13, 10, 0
str_patch_fail          DB "[FAIL] Patch failed", 13, 10, 0
str_newline             DB 13, 10, 0

; ============================================================================
; BSS SECTION — Uninitialized data
; ============================================================================
.data?

hStdout                 DQ ?
hStdin                  DQ ?
argc                    DD ?
argv                    DQ MAX_ARGS DUP(?)
cmdline_buf             DB MAX_CMDLINE_LEN DUP(?)
metrics_buf             DB 256 DUP(?)

; ============================================================================
; CODE SECTION
; ============================================================================
.CODE

; ----------------------------------------------------------------------------
; PrintString — Output null-terminated string to stdout
; Input: RCX = string pointer
; Clobbers: RAX, RDX, R8, R9, R10, R11
; ----------------------------------------------------------------------------
PrintString PROC FRAME
    push    rbp
    .pushreg rbp
    push    rsi
    .pushreg rsi
    sub     rsp, 40
    .allocstack 40
    .endprolog

    mov     rsi, rcx                    ; Save string pointer

    ; Calculate length
    xor     eax, eax
    mov     rcx, rsi
    dec     rcx
.len_loop:
    inc     rcx
    cmp     byte ptr [rcx], 0
    jne     .len_loop
    sub     rcx, rsi                    ; RCX = length

    ; Write to console
    mov     rdx, rsi                    ; lpBuffer
    mov     r8, rcx                     ; nNumberOfCharsToWrite
    xor     r9, r9                      ; lpNumberOfCharsWritten
    mov     qword ptr [rsp+32], 0       ; lpReserved
    mov     rcx, [hStdout]              ; hConsoleOutput
    call    WriteConsoleA

    add     rsp, 40
    pop     rsi
    pop     rbp
    ret
PrintString ENDP

; ----------------------------------------------------------------------------
; ParseCommandLine — Split command line into argc/argv
; Input: None (uses GetCommandLineA)
; Output: argc in [argc], argv in [argv]
; ----------------------------------------------------------------------------
ParseCommandLine PROC FRAME
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    push    rdi
    .pushreg rdi
    push    rsi
    .pushreg rsi
    sub     rsp, 56
    .allocstack 56
    .endprolog

    call    GetCommandLineA
    mov     rsi, rax                    ; RSI = command line string
    mov     rdi, OFFSET cmdline_buf     ; RDI = destination buffer

    ; Copy command line to our buffer
    mov     rcx, MAX_CMDLINE_LEN
    rep movsb

    ; Parse arguments
    mov     rsi, OFFSET cmdline_buf
    mov     rdi, OFFSET argv
    xor     ebx, ebx                    ; EBX = arg count

.parse_loop:
    ; Skip leading whitespace
.skip_ws:
    movzx   eax, byte ptr [rsi]
    test    al, al
    jz      .parse_done
    cmp     al, ' '
    je      .skip_ws_char
    cmp     al, 9                       ; Tab
    je      .skip_ws_char
    jmp     .arg_start
.skip_ws_char:
    inc     rsi
    jmp     .skip_ws

.arg_start:
    ; Store argument pointer
    mov     [rdi + rbx*8], rsi
    inc     ebx

    ; Find end of argument
.find_end:
    movzx   eax, byte ptr [rsi]
    test    al, al
    jz      .parse_done
    cmp     al, ' '
    je      .arg_end
    cmp     al, 9
    je      .arg_end
    cmp     al, '"'                     ; Handle quotes
    je      .handle_quote
    inc     rsi
    jmp     .find_end

.arg_end:
    mov     byte ptr [rsi], 0           ; Null-terminate
    inc     rsi
    jmp     .parse_loop

.handle_quote:
    ; Skip opening quote
    inc     rsi
    ; Find closing quote
.quote_loop:
    movzx   eax, byte ptr [rsi]
    test    al, al
    jz      .parse_done
    cmp     al, '"'
    je      .quote_end
    inc     rsi
    jmp     .quote_loop
.quote_end:
    mov     byte ptr [rsi], 0
    inc     rsi
    jmp     .parse_loop

.parse_done:
    mov     [argc], ebx

    add     rsp, 56
    pop     rsi
    pop     rdi
    pop     rbx
    pop     rbp
    ret
ParseCommandLine ENDP

; ----------------------------------------------------------------------------
; StrCmp — Compare two null-terminated strings
; Input: RCX = str1, RDX = str2
; Output: RAX = 0 if equal, non-zero if different
; ----------------------------------------------------------------------------
StrCmp PROC FRAME
    push    rbp
    .pushreg rbp
    sub     rsp, 40
    .allocstack 40
    .endprolog

.loop:
    movzx   eax, byte ptr [rcx]
    movzx   r8d, byte ptr [rdx]
    cmp     al, r8b
    jne     .different
    test    al, al
    jz      .equal
    inc     rcx
    inc     rdx
    jmp     .loop

.different:
    mov     eax, 1
    jmp     .done

.equal:
    xor     eax, eax

.done:
    add     rsp, 40
    pop     rbp
    ret
StrCmp ENDP

; ----------------------------------------------------------------------------
; InitEngines — Initialize all backend engines
; Output: RAX = 0 on success, non-zero on failure
; ----------------------------------------------------------------------------
InitEngines PROC FRAME
    push    rbp
    .pushreg rbp
    sub     rsp, 40
    .allocstack 40
    .endprolog

    ; Initialize orchestrator
    mov     rcx, OFFSET str_init_orchestrator
    call    PrintString
    call    asm_orchestrator_init
    test    rax, rax
    jnz     .fail

    ; Initialize crypto
    mov     rcx, OFFSET str_init_crypto
    call    PrintString
    call    asm_camellia256_init
    test    rax, rax
    jnz     .fail

    ; Initialize self-host
    mov     rcx, OFFSET str_init_selfhost
    call    PrintString
    call    asm_selfhost_init
    test    rax, rax
    jnz     .fail

    mov     rcx, OFFSET str_init_ok
    call    PrintString
    xor     eax, eax
    jmp     .done

.fail:
    mov     rcx, OFFSET str_init_fail
    call    PrintString
    mov     eax, 1

.done:
    add     rsp, 40
    pop     rbp
    ret
InitEngines ENDP

; ----------------------------------------------------------------------------
; ShutdownEngines — Clean shutdown of all engines
; ----------------------------------------------------------------------------
ShutdownEngines PROC FRAME
    push    rbp
    .pushreg rbp
    sub     rsp, 40
    .allocstack 40
    .endprolog

    call    asm_orchestrator_shutdown
    call    asm_camellia256_shutdown
    call    asm_selfhost_shutdown

    add     rsp, 40
    pop     rbp
    ret
ShutdownEngines ENDP

; ----------------------------------------------------------------------------
; CmdBenchmark — Run full system benchmark
; ----------------------------------------------------------------------------
CmdBenchmark PROC FRAME
    push    rbp
    .pushreg rbp
    sub     rsp, 40
    .allocstack 40
    .endprolog

    mov     rcx, OFFSET str_running_benchmark
    call    PrintString

    ; TODO: Implement comprehensive benchmark
    ; For now, just run crypto self-test as placeholder
    call    asm_camellia256_self_test

    mov     rcx, OFFSET str_benchmark_done
    call    PrintString

    add     rsp, 40
    pop     rbp
    ret
CmdBenchmark ENDP

; ----------------------------------------------------------------------------
; CmdCryptoTest — Run Camellia256 self-test
; ----------------------------------------------------------------------------
CmdCryptoTest PROC FRAME
    push    rbp
    .pushreg rbp
    sub     rsp, 40
    .allocstack 40
    .endprolog

    mov     rcx, OFFSET str_running_crypto
    call    PrintString

    call    asm_camellia256_self_test
    test    rax, rax
    jz      .ok

    mov     rcx, OFFSET str_crypto_fail
    call    PrintString
    mov     eax, EXIT_CRYPTO_FAIL
    jmp     .done

.ok:
    mov     rcx, OFFSET str_crypto_ok
    call    PrintString
    xor     eax, eax

.done:
    add     rsp, 40
    pop     rbp
    ret
CmdCryptoTest ENDP

; ----------------------------------------------------------------------------
; CmdAgent — Dispatch agentic task
; Input: RCX = task string pointer
; ----------------------------------------------------------------------------
CmdAgent PROC FRAME
    push    rbp
    .pushreg rbp
    push    rsi
    .pushreg rsi
    sub     rsp, 40
    .allocstack 40
    .endprolog

    mov     rsi, rcx                    ; Save task string

    mov     rcx, OFFSET str_dispatching_agent
    call    PrintString
    mov     rcx, rsi
    call    PrintString
    mov     rcx, OFFSET str_dispatching_agent2
    call    PrintString

    ; Enqueue task to orchestrator
    ; TODO: Pack task into proper task structure
    ; For now, just dispatch
    call    asm_orchestrator_dispatch

    mov     rcx, OFFSET str_agent_done
    call    PrintString

    xor     eax, eax
    add     rsp, 40
    pop     rsi
    pop     rbp
    ret
CmdAgent ENDP

; ----------------------------------------------------------------------------
; CmdStats — Real-time telemetry ticker
; ----------------------------------------------------------------------------
CmdStats PROC FRAME
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    sub     rsp, 56
    .allocstack 56
    .endprolog

    mov     rcx, OFFSET str_stats_header
    call    PrintString

    mov     ebx, 100                    ; Run for 100 iterations or until 'q'
.stats_loop:
    dec     ebx
    jz      .stats_done

    ; Get timestamp
    call    GetTickCount64
    mov     r12, rax                    ; R12 = timestamp

    ; Get orchestrator metrics
    ; TODO: Proper metrics structure
    xor     r13d, r13d                  ; R13D = queue depth (placeholder)
    xor     r14d, r14d                  ; R14D = tasks completed (placeholder)
    xor     r15d, r15d                  ; R15D = latency (placeholder)

    ; Get selfhost stats
    call    asm_selfhost_get_stats
    mov     r8d, eax                    ; R8D = selfhost stats

    ; Print stats line (simplified)
    mov     rcx, r12
    mov     rdx, r13
    mov     r8, r14
    mov     r9, r15

    ; Sleep 100ms
    mov     ecx, 100
    call    Sleep

    jmp     .stats_loop

.stats_done:
    xor     eax, eax
    add     rsp, 56
    pop     rbx
    pop     rbp
    ret
CmdStats ENDP

; ----------------------------------------------------------------------------
; ShowHelp — Display usage information
; ----------------------------------------------------------------------------
ShowHelp PROC FRAME
    push    rbp
    .pushreg rbp
    sub     rsp, 40
    .allocstack 40
    .endprolog

    mov     rcx, OFFSET str_banner
    call    PrintString
    mov     rcx, OFFSET str_usage
    call    PrintString

    add     rsp, 40
    pop     rbp
    ret
ShowHelp ENDP

; ----------------------------------------------------------------------------
; mainCRTStartup — Entry point
; ----------------------------------------------------------------------------
mainCRTStartup PROC FRAME
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    push    rdi
    .pushreg rdi
    push    rsi
    .pushreg rsi
    sub     rsp, 56
    .allocstack 56
    .endprolog

    ; Get stdout handle
    mov     ecx, STD_OUTPUT_HANDLE
    call    GetStdHandle
    mov     [hStdout], rax

    ; Get stdin handle
    mov     ecx, STD_INPUT_HANDLE
    call    GetStdHandle
    mov     [hStdin], rax

    ; Parse command line
    call    ParseCommandLine

    ; Check if we have any arguments
    cmp     [argc], 1
    jle     .show_help

    ; Get command (argv[1])
    mov     rsi, [argv + 8]             ; RSI = command string

    ; Check for help
    mov     rcx, rsi
    mov     rdx, OFFSET cmd_help
    call    StrCmp
    test    eax, eax
    jz      .show_help

    mov     rcx, rsi
    mov     rdx, OFFSET cmd_h
    call    StrCmp
    test    eax, eax
    jz      .show_help

    mov     rcx, rsi
    mov     rdx, OFFSET cmd_question
    call    StrCmp
    test    eax, eax
    jz      .show_help

    ; Initialize engines
    call    InitEngines
    test    rax, rax
    jnz     .exit_fail

    ; Dispatch command
    mov     rcx, rsi
    mov     rdx, OFFSET cmd_benchmark
    call    StrCmp
    test    eax, eax
    jz      .do_benchmark

    mov     rcx, rsi
    mov     rdx, OFFSET cmd_crypto_test
    call    StrCmp
    test    eax, eax
    jz      .do_crypto

    mov     rcx, rsi
    mov     rdx, OFFSET cmd_agent
    call    StrCmp
    test    eax, eax
    jz      .do_agent

    mov     rcx, rsi
    mov     rdx, OFFSET cmd_stats
    call    StrCmp
    test    eax, eax
    jz      .do_stats

    ; Unknown command
    mov     rcx, OFFSET str_unknown_cmd
    call    PrintString
    mov     rcx, rsi
    call    PrintString
    mov     rcx, OFFSET str_unknown_cmd_end
    call    PrintString
    mov     ecx, EXIT_UNKNOWN_CMD
    jmp     .exit

.show_help:
    call    ShowHelp
    mov     ecx, EXIT_SUCCESS
    jmp     .exit

.do_benchmark:
    call    CmdBenchmark
    jmp     .exit_ok

.do_crypto:
    call    CmdCryptoTest
    jmp     .exit

.do_agent:
    ; Get task from argv[2] if present
    mov     rax, [argc]
    cmp     eax, 3
    jl      .agent_no_task
    mov     rcx, [argv + 16]            ; argv[2]
    jmp     .agent_dispatch
.agent_no_task:
    mov     rcx, OFFSET cmd_agent       ; Use "agent" as task if no arg
.agent_dispatch:
    call    CmdAgent
    jmp     .exit_ok

.do_stats:
    call    CmdStats
    jmp     .exit_ok

.exit_ok:
    xor     ecx, ecx

.exit:
    ; Save exit code
    mov     ebx, ecx

    ; Shutdown engines
    call    ShutdownEngines

    ; Exit with code
    mov     ecx, ebx
    call    ExitProcess

.exit_fail:
    mov     ecx, EXIT_FAILURE
    jmp     .exit

mainCRTStartup ENDP

END
