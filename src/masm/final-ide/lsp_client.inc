; ============================================================================
; LSP_CLIENT.INC - Language Server Protocol Header
; ============================================================================

EXTERN lsp_client_init:PROC
EXTERN lsp_client_shutdown:PROC
EXTERN lsp_initialize_workspace:PROC
EXTERN lsp_did_open:PROC
EXTERN lsp_did_change:PROC
EXTERN lsp_did_save:PROC
EXTERN lsp_completion:PROC
EXTERN lsp_hover:PROC
EXTERN lsp_diagnostics:PROC
EXTERN lsp_document_symbols:PROC
EXTERN lsp_goto_definition:PROC
EXTERN lsp_references:PROC

LSP_COMPLETION_ITEM STRUCT
    label_ptr QWORD ?
    kind QWORD ?
    detail QWORD ?
    documentation QWORD ?
    start_line DWORD ?
    start_col DWORD ?
    end_line DWORD ?
    end_col DWORD ?
LSP_COMPLETION_ITEM ENDS

LSP_DIAGNOSTIC STRUCT
    message QWORD ?
    severity DWORD ?
    line DWORD ?
    column DWORD ?
    source QWORD ?
LSP_DIAGNOSTIC ENDS
