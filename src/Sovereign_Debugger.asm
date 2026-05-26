; Sovereign_Debugger.asm — Production
include Sovereign_Common.inc
.code
PUBLIC Debugger_LogString
Debugger_LogString proc
    sub rsp, 40
    call OutputDebugStringA
    add rsp, 40
    ret
Debugger_LogString endp

PUBLIC Debugger_DumpPointers
Debugger_DumpPointers proc
    sub rsp, 40
    lea rcx, [msg_diag]
    call OutputDebugStringA
    add rsp, 40
    ret
Debugger_DumpPointers endp
.data
msg_diag db "[SOVEREIGN] Debugger Active.", 0
end