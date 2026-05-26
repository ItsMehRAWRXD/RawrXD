; ==============================================================================
; Sovereign_Persistence.asm
; Logic: High-Speed World State Serialization & Persistence
; Features: Tool-Bridge File I/O (Bypassing Kernel32 overhead)
; ==============================================================================

INCLUDE Sovereign_Execution_Graph_ABI.inc

; ------------------------------------------------------------------------------
; EXTERNAL SYMBOLS (From ToolExecutor)
; ------------------------------------------------------------------------------
EXTERN Tool_WriteFile : PROC
EXTERN Tool_ReadFile  : PROC

.DATA
    align 8
    g_SaveFileName      db "sovereign_save.bin", 0
    g_SaveBuffer        dq 0

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: SaveGameState
; Input: RCX = StateBuffer, RDX = BufferSize
; Logic: Serializes all WorldEntities and PlayerState using the Tool Bridge.
; ------------------------------------------------------------------------------
PUBLIC SaveGameState
SaveGameState PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Tool_WriteFile(pszPath, pBuffer, size)
    ; RCX is already buffer, RDX is size. We need path in RCX.
    mov r8, rdx             ; size
    mov rdx, rcx             ; pBuffer
    lea rcx, g_SaveFileName  ; pszPath
    call Tool_WriteFile
    
    mov rsp, rbp
    pop rbp
    ret
SaveGameState ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: LoadGameState
; ------------------------------------------------------------------------------
PUBLIC LoadGameState
LoadGameState PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Tool_ReadFile(pszPath, pBuffer, size)
    ; RCX = pszPath, RDX = pBuffer, R8 = size
    mov r8, rdx             ; size
    mov rdx, rcx             ; pBuffer (Buffer to read INTO)
    lea rcx, g_SaveFileName  ; pszPath
    call Tool_ReadFile
    
    mov rsp, rbp
    pop rbp
    ret
LoadGameState ENDP

END
    xor rax, rax
    ret
LoadGameState ENDP

END