; ==========================================================================
; MASM Qt6 Component Conversion: SyntaxHighlighter Layer (CLEAN)
; ==========================================================================

option casemap:none

include windows.inc
include masm_master_defs.inc

.code

PUBLIC syntax_highlighter_create
syntax_highlighter_create PROC
    xor rax, rax
    ret
syntax_highlighter_create ENDP

PUBLIC syntax_highlighter_highlight_block
syntax_highlighter_highlight_block PROC
    xor rax, rax
    ret
syntax_highlighter_highlight_block ENDP

END
