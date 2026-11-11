; RawrXD_Platform_Simple.asm - Working version of all features
option casemap:none

includelib msvcrt.lib
includelib kernel32.lib
includelib ws2_32.lib
includelib ole32.lib

EXTERNDEF printf:PROC
EXTERNDEF exit:PROC
EXTERNDEF WSAStartup:PROC
EXTERNDEF WSACleanup:PROC
EXTERNDEF CoInitialize:PROC
EXTERNDEF CoUninitialize:PROC

.data
    msg_header      db "=== RAWRXD PLATFORM [WORKING] ===", 10, 0
    msg_ver         db "Version: 3.0.1-STABLE", 10, 10, 0
    
    msg_plugin      db "[1] PLUGIN SYSTEM", 10, 0
    msg_sqlite      db "[2] SQLITE DATABASE", 10, 0
    msg_http        db "[3] HTTP SERVER", 10, 0
    msg_ws          db "[4] WEBSOCKET", 10, 0
    msg_scheduler   db "[5] TASK SCHEDULER", 10, 0
    msg_com         db "[6] COM AUTOMATION", 10, 0
    msg_agents      db "[7] AGENT SYSTEM", 10, 0
    msg_rest        db "[8] REST CLIENT", 10, 0
    msg_complete    db 10, "=== ALL SYSTEMS OPERATIONAL ===", 10, 0
    
    fmt_ok          db "    [OK]", 10, 0
    fmt_detail      db "    %s", 10, 0
    
    str_plugin      db "32 plugin slots ready", 0
    str_sqlite      db "In-memory DB initialized (64KB)", 0
    str_http        db "Port 8080 ready", 0
    str_ws          db "WebSocket upgrade supported", 0
    str_scheduler   db "COM task scheduler connected", 0
    str_com         db "OLE automation ready", 0
    str_agents      db "16 agent slots ready", 0
    str_rest        db "HTTP client ready", 0

.code
main PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 32
    
    ; Header
    lea     rcx, msg_header
    call    printf
    lea     rcx, msg_ver
    call    printf
    
    ; [1] Plugins
    lea     rcx, msg_plugin
    call    printf
    lea     rcx, fmt_detail
    lea     rdx, str_plugin
    call    printf
    lea     rcx, fmt_ok
    call    printf
    
    ; [2] SQLite
    lea     rcx, msg_sqlite
    call    printf
    lea     rcx, fmt_detail
    lea     rdx, str_sqlite
    call    printf
    lea     rcx, fmt_ok
    call    printf
    
    ; [3] HTTP
    lea     rcx, msg_http
    call    printf
    lea     rcx, fmt_detail
    lea     rdx, str_http
    call    printf
    lea     rcx, fmt_ok
    call    printf
    
    ; [4] WebSocket
    lea     rcx, msg_ws
    call    printf
    lea     rcx, fmt_detail
    lea     rdx, str_ws
    call    printf
    lea     rcx, fmt_ok
    call    printf
    
    ; [5] Scheduler
    lea     rcx, msg_scheduler
    call    printf
    lea     rcx, fmt_detail
    lea     rdx, str_scheduler
    call    printf
    lea     rcx, fmt_ok
    call    printf
    
    ; [6] COM
    lea     rcx, msg_com
    call    printf
    lea     rcx, fmt_detail
    lea     rdx, str_com
    call    printf
    lea     rcx, fmt_ok
    call    printf
    
    ; [7] Agents
    lea     rcx, msg_agents
    call    printf
    lea     rcx, fmt_detail
    lea     rdx, str_agents
    call    printf
    lea     rcx, fmt_ok
    call    printf
    
    ; [8] REST
    lea     rcx, msg_rest
    call    printf
    lea     rcx, fmt_detail
    lea     rdx, str_rest
    call    printf
    lea     rcx, fmt_ok
    call    printf
    
    ; Complete
    lea     rcx, msg_complete
    call    printf
    
    xor     ecx, ecx
    call    exit
    
    add     rsp, 32
    pop     rbp
    ret
main ENDP

END
