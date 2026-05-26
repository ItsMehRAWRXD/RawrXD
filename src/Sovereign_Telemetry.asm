; Sovereign_Telemetry.asm ? Production
SOVEREIGN_TELEMETRY_MODULE equ 1
; Sovereign_Telemetry.asm ? Production
include Sovereign_Common.inc
.code
PUBLIC Telemetry_LogTick
Telemetry_LogTick proc
    ; RCX = String Pointer
    sub rsp, 40
    call OutputDebugStringA
    add rsp, 40
    ret
Telemetry_LogTick endp
end
