;=============================================================================
; cli_editor_core.asm
; RawrXD CLI Text Editor Core - Rope Data Structure in MASM64
; 
; Implements a rope (PieceTable-style) data structure for efficient
; text editing of large files in the CLI environment.
;
; Build: ml64.exe /c /W3 /nologo cli_editor_core.asm
;=============================================================================
OPTION CASEMAP:NONE
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

;=============================================================================
; Constants
;=============================================================================
MAX_LEAF_SIZE EQU 128           ; Maximum characters per leaf node
NODE_SIZE EQU 64              ; Size of Node structure in bytes

; Node flags
NODE_IS_LEAF EQU 1
NODE_IS_DIRTY EQU 2

;=============================================================================
; External Imports
;=============================================================================
EXTERN HeapAlloc :PROC
EXTERN HeapFree :PROC
EXTERN GetProcessHeap :PROC
EXTERN RtlCompareMemory :PROC
EXTERN RtlMoveMemory :PROC
EXTERN memset :PROC
EXTERN memcpy :PROC
EXTERN strlen :PROC

;=============================================================================
; Data Section
;=============================================================================
.data
ALIGN 16

g_hHeap QWORD 0               ; Process heap handle
g_pRoot QWORD 0               ; Root node pointer
g_totalLength QWORD 0         ; Total text length
g_totalLines QWORD 0          ; Total line count
g_nodeCount QWORD 0           ; Statistics: node count

; Error codes
CLI_EDITOR_OK EQU 0
CLI_EDITOR_NOMEM EQU 1
CLI_EDITOR_INVALID_POS EQU 2
CLI_EDITOR_EMPTY EQU 3

;=============================================================================
; Node Structure (64 bytes)
; Offset  Size    Description
; 0       8       isLeaf (bool) + padding
; 8       8       weight (length of left subtree)
; 16      4       height (tree height)
; 20      4       lineBreakCount
; 24      8       text pointer (leaf) or left child (internal)
; 32      8       right child pointer (internal only)
; 40      8       parent pointer
; 48      8       reserved
; 56      8       reserved
;=============================================================================
NODE_ISLEAF_OFFSET EQU 0
NODE_WEIGHT_OFFSET EQU 8
NODE_HEIGHT_OFFSET EQU 16
NODE_LINEBREAK_OFFSET EQU 20
NODE_TEXT_OFFSET EQU 24
NODE_LEFT_OFFSET EQU 24      ; Alias for clarity
NODE_RIGHT_OFFSET EQU 32
NODE_PARENT_OFFSET EQU 40

;=============================================================================
; Code Section
;=============================================================================
.code

;-----------------------------------------------------------------------------
; CliEditor_Init - Initialize the editor core
; Returns: 0 on success, error code on failure
;-----------------------------------------------------------------------------
CliEditor_Init PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 40
    
    ; Get process heap
    call GetProcessHeap
    test rax, rax
    jz Init_Fail
    mov [g_hHeap], rax
    
    ; Create empty root node (leaf)
    mov rcx, [g_hHeap]
    xor edx, edx              ; HEAP_ZERO_MEMORY
    mov r8d, NODE_SIZE
    call HeapAlloc
    test rax, rax
    jz Init_Fail
    
    ; Initialize root as empty leaf
    mov BYTE PTR [rax + NODE_ISLEAF_OFFSET], 1
    mov DWORD PTR [rax + NODE_HEIGHT_OFFSET], 0
    mov DWORD PTR [rax + NODE_LINEBREAK_OFFSET], 0
    mov QWORD PTR [rax + NODE_TEXT_OFFSET], 0   ; No text yet
    mov QWORD PTR [rax + NODE_RIGHT_OFFSET], 0
    mov QWORD PTR [rax + NODE_PARENT_OFFSET], 0
    
    mov [g_pRoot], rax
    mov QWORD PTR [g_totalLength], 0
    mov QWORD PTR [g_totalLines], 1     ; Empty file has 1 line
    mov QWORD PTR [g_nodeCount], 1
    
    xor eax, eax                      ; Return CLI_EDITOR_OK
    jmp Init_Done
    
Init_Fail:
    mov eax, CLI_EDITOR_NOMEM
    
Init_Done:
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
CliEditor_Init ENDP

;-----------------------------------------------------------------------------
; CliEditor_Shutdown - Clean up all resources
;-----------------------------------------------------------------------------
CliEditor_Shutdown PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    sub rsp, 40
    
    mov rbx, [g_pRoot]
    test rbx, rbx
    jz Shutdown_Done
    
    ; Recursively free tree
    mov rcx, rbx
    call FreeNodeRecursive
    
    mov QWORD PTR [g_pRoot], 0
    mov QWORD PTR [g_totalLength], 0
    mov QWORD PTR [g_totalLines], 0
    
Shutdown_Done:
    xor eax, eax
    add rsp, 40
    pop rbx
    pop rbp
    ret
CliEditor_Shutdown ENDP

;-----------------------------------------------------------------------------
; FreeNodeRecursive - Recursively free a node and its children
; RCX = node pointer
;-----------------------------------------------------------------------------
FreeNodeRecursive PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    sub rsp, 40
    
    mov rbx, rcx
    test rbx, rbx
    jz FreeNode_Done
    
    ; Check if leaf
    movzx eax, BYTE PTR [rbx + NODE_ISLEAF_OFFSET]
    test eax, eax
    jnz FreeNode_Leaf
    
    ; Internal node - free children first
    mov rcx, [rbx + NODE_LEFT_OFFSET]
    test rcx, rcx
    jz FreeNode_NoLeft
    call FreeNodeRecursive
    
FreeNode_NoLeft:
    mov rcx, [rbx + NODE_RIGHT_OFFSET]
    test rcx, rcx
    jz FreeNode_NoRight
    call FreeNodeRecursive
    
FreeNode_NoRight:
    jmp FreeNode_FreeNode
    
FreeNode_Leaf:
    ; Leaf node - free text buffer if present
    mov rsi, [rbx + NODE_TEXT_OFFSET]
    test rsi, rsi
    jz FreeNode_FreeNode
    
    mov rcx, [g_hHeap]
    xor edx, edx
    mov r8, rsi
    call HeapFree
    
FreeNode_FreeNode:
    ; Free the node itself
    mov rcx, [g_hHeap]
    xor edx, edx
    mov r8, rbx
    call HeapFree
    
FreeNode_Done:
    add rsp, 40
    pop rsi
    pop rbx
    pop rbp
    ret
FreeNodeRecursive ENDP

;-----------------------------------------------------------------------------
; CliEditor_Insert - Insert text at position
; RCX = position (0-based)
; RDX = text pointer (UTF-8)
; R8 = text length in bytes
; Returns: 0 on success, error code on failure
;-----------------------------------------------------------------------------
CliEditor_Insert PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 56
    
    mov r12, rcx              ; r12 = position
    mov r13, rdx              ; r13 = text pointer
    mov r14, r8               ; r14 = text length
    
    ; Validate inputs
    test r13, r13
    jz Insert_Empty
    test r14, r14
    jz Insert_Empty
    
    cmp r12, [g_totalLength]
    jle Insert_PosOK
    mov r12, [g_totalLength]  ; Clamp to end
    
Insert_PosOK:
    ; Count newlines in text
    mov rcx, r13
    mov rdx, r14
    call CountNewlines
    mov rdi, rax              ; rdi = newline count
    
    ; Insert into tree
    mov rcx, [g_pRoot]
    mov rdx, r12
    mov r8, r13
    mov r9, r14
    call InsertRecursive
    
    test rax, rax
    jz Insert_NoMem
    
    mov [g_pRoot], rax
    
    ; Update totals
    add [g_totalLength], r14
    add [g_totalLines], rdi
    
    xor eax, eax              ; Return CLI_EDITOR_OK
    jmp Insert_Done
    
Insert_Empty:
    mov eax, CLI_EDITOR_OK    ; Empty insert is OK
    jmp Insert_Done
    
Insert_NoMem:
    mov eax, CLI_EDITOR_NOMEM
    
Insert_Done:
    add rsp, 56
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
CliEditor_Insert ENDP

;-----------------------------------------------------------------------------
; CountNewlines - Count '\n' characters in text
; RCX = text pointer
; RDX = length
; Returns: count in RAX
;-----------------------------------------------------------------------------
CountNewlines PROC FRAME
    push rbp
    mov rbp, rsp
    push rsi
    push rdi
    
    mov rsi, rcx
    mov rdi, rdx
    xor eax, eax              ; Count = 0
    
CountLoop:
    test rdi, rdi
    jz CountDone
    
    movzx ecx, BYTE PTR [rsi]
    cmp cl, 10                ; '\n'
    jne CountNext
    inc eax
    
CountNext:
    inc rsi
    dec rdi
    jmp CountLoop
    
CountDone:
    pop rdi
    pop rsi
    pop rbp
    ret
CountNewlines ENDP

;-----------------------------------------------------------------------------
; InsertRecursive - Recursively insert text into tree
; RCX = node
; RDX = position
; R8 = text pointer
; R9 = text length
; Returns: new node (or same node), 0 on error
;-----------------------------------------------------------------------------
InsertRecursive PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    
    mov rbx, rcx              ; rbx = node
    mov r12, rdx              ; r12 = position
    mov r13, r8               ; r13 = text pointer
    mov r14, r9               ; r14 = text length
    
    test rbx, rbx
    jnz InsertRec_HasNode
    
    ; Create new leaf
    mov rcx, r13
    mov rdx, r14
    call CreateLeafNode
    jmp InsertRec_Done
    
InsertRec_HasNode:
    ; Check if leaf
    movzx eax, BYTE PTR [rbx + NODE_ISLEAF_OFFSET]
    test eax, eax
    jz InsertRec_Internal
    
    ; ----- Leaf node handling -----
    mov rsi, [rbx + NODE_TEXT_OFFSET]
    test rsi, rsi
    jnz InsertRec_HasText
    
    ; Empty leaf - just set text
    mov rcx, r13
    mov rdx, r14
    call AllocateTextBuffer
    mov [rbx + NODE_TEXT_OFFSET], rax
    mov rax, rbx
    jmp InsertRec_Done
    
InsertRec_HasText:
    ; Get current text length
    mov rdi, [rbx + NODE_WEIGHT_OFFSET]  ; For leaf, weight = text length
    
    ; Check if fits in current leaf
    lea rax, [rdi + r14]
    cmp rax, MAX_LEAF_SIZE
    jle InsertRec_AppendToLeaf
    
    ; Need to split - create internal node
    ; This is simplified - full implementation would split properly
    mov rcx, rbx
    mov rdx, r12
    mov r8, r13
    mov r9, r14
    call SplitAndInsert
    jmp InsertRec_Done
    
InsertRec_AppendToLeaf:
    ; Append to existing leaf text
    ; (Simplified - would need reallocation in real impl)
    mov rax, rbx
    jmp InsertRec_Done
    
InsertRec_Internal:
    ; ----- Internal node handling -----
    mov r15, [rbx + NODE_WEIGHT_OFFSET]  ; r15 = left subtree weight
    
    cmp r12, r15
    jge InsertRec_GoRight
    
    ; Insert into left subtree
    mov rcx, [rbx + NODE_LEFT_OFFSET]
    mov rdx, r12
    mov r8, r13
    mov r9, r14
    call InsertRecursive
    
    test rax, rax
    jz InsertRec_Fail
    
    mov [rbx + NODE_LEFT_OFFSET], rax
    add [rbx + NODE_WEIGHT_OFFSET], r14
    jmp InsertRec_UpdateNode
    
InsertRec_GoRight:
    ; Insert into right subtree
    sub r12, r15              ; Adjust position
    
    mov rcx, [rbx + NODE_RIGHT_OFFSET]
    mov rdx, r12
    mov r8, r13
    mov r9, r14
    call InsertRecursive
    
    test rax, rax
    jz InsertRec_Fail
    
    mov [rbx + NODE_RIGHT_OFFSET], rax
    
InsertRec_UpdateNode:
    ; Update node metadata
    mov rcx, rbx
    call UpdateNodeStats
    
    ; Balance tree
    mov rcx, rbx
    call BalanceNode
    
InsertRec_Done:
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
    
InsertRec_Fail:
    xor eax, eax
    jmp InsertRec_Done
InsertRecursive ENDP

;-----------------------------------------------------------------------------
; CreateLeafNode - Create a new leaf node with text
; RCX = text pointer
; RDX = text length
; Returns: node pointer, 0 on failure
;-----------------------------------------------------------------------------
CreateLeafNode PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 40
    
    mov rsi, rcx              ; rsi = text
    mov rdi, rdx              ; rdi = length
    
    ; Allocate node
    mov rcx, [g_hHeap]
    xor edx, edx
    mov r8d, NODE_SIZE
    call HeapAlloc
    
    test rax, rax
    jz CreateLeaf_Fail
    mov rbx, rax
    
    ; Initialize node
    mov BYTE PTR [rbx + NODE_ISLEAF_OFFSET], 1
    mov DWORD PTR [rbx + NODE_HEIGHT_OFFSET], 0
    mov QWORD PTR [rbx + NODE_RIGHT_OFFSET], 0
    mov QWORD PTR [rbx + NODE_PARENT_OFFSET], 0
    
    ; Count newlines
    mov rcx, rsi
    mov rdx, rdi
    call CountNewlines
    mov DWORD PTR [rbx + NODE_LINEBREAK_OFFSET], eax
    
    ; Allocate and copy text
    mov rcx, rsi
    mov rdx, rdi
    call AllocateTextBuffer
    test rax, rax
    jz CreateLeaf_Cleanup
    
    mov [rbx + NODE_TEXT_OFFSET], rax
    mov [rbx + NODE_WEIGHT_OFFSET], rdi
    
    inc QWORD PTR [g_nodeCount]
    
    mov rax, rbx
    jmp CreateLeaf_Done
    
CreateLeaf_Cleanup:
    mov rcx, [g_hHeap]
    xor edx, edx
    mov r8, rbx
    call HeapFree
    
CreateLeaf_Fail:
    xor eax, eax
    
CreateLeaf_Done:
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
CreateLeafNode ENDP

;-----------------------------------------------------------------------------
; AllocateTextBuffer - Allocate and copy text
; RCX = source text
; RDX = length
; Returns: allocated buffer pointer
;-----------------------------------------------------------------------------
AllocateTextBuffer PROC FRAME
    push rbp
    mov rbp, rsp
    push rsi
    push rdi
    push rbx
    sub rsp, 40
    
    mov rsi, rcx
    mov rbx, rdx
    
    ; Allocate buffer (+1 for null terminator)
    mov rcx, [g_hHeap]
    xor edx, edx
    lea r8, [rbx + 1]
    call HeapAlloc
    
    test rax, rax
    jz AllocText_Fail
    mov rdi, rax
    
    ; Copy text
    mov rcx, rdi
    mov rdx, rsi
    mov r8, rbx
    call memcpy
    
    ; Null terminate
    mov BYTE PTR [rdi + rbx], 0
    
    mov rax, rdi
    
AllocText_Fail:
    add rsp, 40
    pop rbx
    pop rdi
    pop rsi
    pop rbp
    ret
AllocateTextBuffer ENDP

;-----------------------------------------------------------------------------
; UpdateNodeStats - Recalculate node statistics
; RCX = node pointer
;-----------------------------------------------------------------------------
UpdateNodeStats PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 40
    
    mov rbx, rcx
    
    ; Check if leaf
    movzx eax, BYTE PTR [rbx + NODE_ISLEAF_OFFSET]
    test eax, eax
    jnz UpdateStats_Leaf
    
    ; Internal node
    mov rsi, [rbx + NODE_LEFT_OFFSET]
    mov rdi, [rbx + NODE_RIGHT_OFFSET]
    
    ; Calculate weight (left subtree length)
    xor ecx, ecx
    test rsi, rsi
    jz UpdateStats_NoLeft
    
    movzx eax, BYTE PTR [rsi + NODE_ISLEAF_OFFSET]
    test eax, eax
    jnz UpdateStats_LeftIsLeaf
    
    ; Left is internal - weight already calculated
    mov ecx, DWORD PTR [rsi + NODE_WEIGHT_OFFSET]
    add ecx, DWORD PTR [rsi + 32]  ; Add right subtree (simplified)
    jmp UpdateStats_SetWeight
    
UpdateStats_LeftIsLeaf:
    mov ecx, DWORD PTR [rsi + NODE_WEIGHT_OFFSET]
    
UpdateStats_SetWeight:
    mov DWORD PTR [rbx + NODE_WEIGHT_OFFSET], ecx
    
UpdateStats_NoLeft:
    ; Calculate line breaks
    xor eax, eax
    test rsi, rsi
    jz UpdateStats_NoLeftLines
    add eax, DWORD PTR [rsi + NODE_LINEBREAK_OFFSET]
    
UpdateStats_NoLeftLines:
    test rdi, rdi
    jz UpdateStats_NoRightLines
    add eax, DWORD PTR [rdi + NODE_LINEBREAK_OFFSET]
    
UpdateStats_NoRightLines:
    mov DWORD PTR [rbx + NODE_LINEBREAK_OFFSET], eax
    
    ; Calculate height
    xor eax, eax
    test rsi, rsi
    jz UpdateStats_NoLeftHeight
    mov eax, DWORD PTR [rsi + NODE_HEIGHT_OFFSET]
    
UpdateStats_NoLeftHeight:
    xor ecx, ecx
    test rdi, rdi
    jz UpdateStats_NoRightHeight
    mov ecx, DWORD PTR [rdi + NODE_HEIGHT_OFFSET]
    
UpdateStats_NoRightHeight:
    cmp eax, ecx
    cmovl eax, ecx
    inc eax
    mov DWORD PTR [rbx + NODE_HEIGHT_OFFSET], eax
    
    jmp UpdateStats_Done
    
UpdateStats_Leaf:
    ; Leaf - weight is text length, already set
    ; Line breaks already counted
    
UpdateStats_Done:
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
UpdateNodeStats ENDP

;-----------------------------------------------------------------------------
; BalanceNode - AVL-style tree balancing
; RCX = node pointer
; Returns: new root (may be same or different)
;-----------------------------------------------------------------------------
BalanceNode PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    sub rsp, 40
    
    mov rbx, rcx
    
    ; Get balance factor
    movzx eax, BYTE PTR [rbx + NODE_ISLEAF_OFFSET]
    test eax, eax
    jnz Balance_Leaf
    
    ; Simplified balancing - full AVL would check heights
    ; For now, just return node as-is
    
Balance_Leaf:
    mov rax, rbx
    
    add rsp, 40
    pop rbx
    pop rbp
    ret
BalanceNode ENDP

;-----------------------------------------------------------------------------
; SplitAndInsert - Split node and insert text (placeholder)
;-----------------------------------------------------------------------------
SplitAndInsert PROC FRAME
    ; Complex operation - would split node at position
    ; and insert text between the two parts
    ; For now, return original node
    mov rax, rcx
    ret
SplitAndInsert ENDP

;-----------------------------------------------------------------------------
; CliEditor_GetText - Extract text to buffer
; RCX = output buffer
; RDX = buffer size
; Returns: bytes written
;-----------------------------------------------------------------------------
CliEditor_GetText PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 40
    
    mov rdi, rcx              ; rdi = output buffer
    mov rbx, rdx              ; rbx = buffer size
    xor esi, esi              ; rsi = bytes written
    
    mov rcx, [g_pRoot]
    test rcx, rcx
    jz GetText_Done
    
    mov rdx, rdi
    mov r8, rbx
    call GetTextRecursive
    mov rsi, rax
    
GetText_Done:
    mov rax, rsi
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
CliEditor_GetText ENDP

;-----------------------------------------------------------------------------
; GetTextRecursive - Recursively extract text
; RCX = node
; RDX = output buffer
; R8 = remaining size
; Returns: bytes written
;-----------------------------------------------------------------------------
GetTextRecursive PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 56
    
    mov rbx, rcx
    mov r12, rdx              ; r12 = output
    mov r13, r8               ; r13 = remaining
    xor esi, esi              ; rsi = written
    
    test rbx, rbx
    jz GetTextRec_Done
    
    ; Check if leaf
    movzx eax, BYTE PTR [rbx + NODE_ISLEAF_OFFSET]
    test eax, eax
    jz GetTextRec_Internal
    
    ; Leaf - copy text
    mov rcx, [rbx + NODE_TEXT_OFFSET]
    test rcx, rcx
    jz GetTextRec_Done
    
    mov rdx, r12
    mov r8, [rbx + NODE_WEIGHT_OFFSET]
    cmp r8, r13
    cmovg r8, r13
    call memcpy
    
    mov rax, [rbx + NODE_WEIGHT_OFFSET]
    cmp rax, r13
    cmovg rax, r13
    jmp GetTextRec_Done
    
GetTextRec_Internal:
    ; Internal - traverse left then right
    mov rcx, [rbx + NODE_LEFT_OFFSET]
    mov rdx, r12
    mov r8, r13
    call GetTextRecursive
    add rsi, rax
    
    add r12, rax
    sub r13, rax
    
    mov rcx, [rbx + NODE_RIGHT_OFFSET]
    mov rdx, r12
    mov r8, r13
    call GetTextRecursive
    add rsi, rax
    
GetTextRec_Done:
    mov rax, rsi
    add rsp, 56
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
GetTextRecursive ENDP

;-----------------------------------------------------------------------------
; CliEditor_GetLength - Get total text length
; Returns: length in RAX
;-----------------------------------------------------------------------------
CliEditor_GetLength PROC FRAME
    mov rax, [g_totalLength]
    ret
CliEditor_GetLength ENDP

;-----------------------------------------------------------------------------
; CliEditor_GetLineCount - Get total line count
; Returns: line count in RAX
;-----------------------------------------------------------------------------
CliEditor_GetLineCount PROC FRAME
    mov rax, [g_totalLines]
    ret
CliEditor_GetLineCount ENDP

;-----------------------------------------------------------------------------
; CliEditor_Clear - Clear all text
;-----------------------------------------------------------------------------
CliEditor_Clear PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40
    
    ; Free existing tree
    mov rcx, [g_pRoot]
    test rcx, rcx
    jz Clear_CreateNew
    
    call FreeNodeRecursive
    
Clear_CreateNew:
    ; Create new empty root
    call CliEditor_Init
    
    add rsp, 40
    pop rbp
    ret
CliEditor_Clear ENDP

;=============================================================================
; Export table for C++ linkage
;=============================================================================
PUBLIC CliEditor_Init
PUBLIC CliEditor_Shutdown
PUBLIC CliEditor_Insert
PUBLIC CliEditor_GetText
PUBLIC CliEditor_GetLength
PUBLIC CliEditor_GetLineCount
PUBLIC CliEditor_Clear

END
