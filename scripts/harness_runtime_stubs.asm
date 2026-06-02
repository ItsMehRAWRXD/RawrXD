OPTION CASEMAP:NONE

INCLUDE d:\linker_ir.inc

PUBLIC CoffLinkerRunWithArena
PUBLIC PEFinalizerConsumeIR
PUBLIC FinalizePEImage
PUBLIC FlushPEToDisk
PUBLIC HeaderBuffer
PUBLIC g_PEFinalizerApplyFixups
PUBLIC g_LastFileHandle
PUBLIC g_LastError
PUBLIC g_BytesWritten
PUBLIC g_WriteFileResult
PUBLIC g_CoffLinkerRunStage
PUBLIC g_ArenaReserveFailPhase
PUBLIC g_ArenaReserveLastError

.data
HeaderBuffer            db 1000h dup(0)
g_PEFinalizerApplyFixups dq 0
g_LastFileHandle        dq 0
g_LastError             dd 0
g_BytesWritten          dq 1
g_WriteFileResult       dd 1
g_CoffLinkerRunStage    dq 0
g_ArenaReserveFailPhase dq 0
g_ArenaReserveLastError dq 0

dummy_symbol_record LABEL BYTE
    dq 0
    dq 0
    dq 0
    dd 0
    dd LINKER_IR_SYMBOL_DEFINED

dummy_fixup_record LABEL BYTE
    dq 0
    dq 0
    dq 0
    dd 0
    dd LINKER_IR_FIXUP_ADDR64

dummy_section_record LABEL BYTE
    db 8 dup(0)
    dd LINKER_IR_SECTION_CODE
    dd 10h
    dd 10h
    dd 0
    dd 0

dummy_data_blob LABEL BYTE
    db 10h dup(0)

dummy_ir_blob LABEL BYTE
    dd LINKER_IR_SIGNATURE
    dd LINKER_IR_VERSION
    dq SIZEOF LINKER_IR_HEADER
    dq LINKER_IR_FLAG_SEALED
    dq dummy_ir_total_size - OFFSET dummy_ir_blob
    dq dummy_symbol_record - OFFSET dummy_ir_blob
    dq 1
    dq 0
    dq 0
    dq dummy_fixup_record - OFFSET dummy_ir_blob
    dq 1
    dq dummy_section_record - OFFSET dummy_ir_blob
    dq 1
    dq dummy_data_blob - OFFSET dummy_ir_blob
    dq 10h

dummy_ir_total_size LABEL BYTE
    db 1

.code
CoffLinkerRunWithArena PROC
    lea rax, dummy_ir_blob
    ret
CoffLinkerRunWithArena ENDP

PEFinalizerConsumeIR PROC
    mov eax, 1
    ret
PEFinalizerConsumeIR ENDP

FinalizePEImage PROC
    mov eax, 1
    ret
FinalizePEImage ENDP

FlushPEToDisk PROC
    mov eax, 1
    ret
FlushPEToDisk ENDP

END
