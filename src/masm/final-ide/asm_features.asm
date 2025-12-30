;==========================================================================
; ASM FEATURES - Drop-in implementations for panes
;==========================================================================

;==========================================================================
; Editor Pane ASM Features
;==========================================================================

; Syntax Highlighting
asm_highlight_syntax PROC
    ; rcx = text buffer, rdx = buffer length
    push rbx

    push rsi
    push rdi
    
    mov rsi, rcx        ; source text
    mov rdi, rcx        ; destination (in-place)
    mov rbx, rdx        ; length
    
highlight_loop:
    test rbx, rbx
    jz highlight_done
    
    mov al, [rsi]
    
    ; Check for instruction keywords
    call is_asm_instruction
    test eax, eax
    jnz highlight_instruction
    
    ; Check for registers
    call is_asm_register  
    test eax, eax
    jnz highlight_register
    
    ; Check for directives
    call is_asm_directive
    test eax, eax
    jnz highlight_directive
    
    ; Default - no highlighting
    mov [rdi], al
    inc rsi
    inc rdi
    dec rbx
    jmp highlight_loop
    
highlight_instruction:
    ; Apply instruction color (blue)
    mov byte ptr [rdi], 0x1F    ; Blue on black
    jmp highlight_next
    
highlight_register:
    ; Apply register color (green)  
    mov byte ptr [rdi], 0x2F    ; Green on black
    jmp highlight_next
    
highlight_directive:
    ; Apply directive color (red)
    mov byte ptr [rdi], 0x4F    ; Red on black
    
highlight_next:
    inc rsi
    inc rdi  
    dec rbx
    jmp highlight_loop
    
highlight_done:

    pop rsi pop rdi

    pop rbx

asm_highlight_syntax ENDP

; Intellisense
asm_get_completions PROC
    ; rcx = cursor position, rdx = context buffer
    
    ; Parse current word
    call parse_current_word
    
    ; Match against instruction set
    call match_instructions
    
    ; Match against registers
    call match_registers
    
    ; Match against labels/symbols
    call match_symbols
    
    ret
asm_get_completions ENDP

;==========================================================================
; Debugger Pane ASM Features  
;==========================================================================

; Register Viewer
asm_format_registers PROC
    ; rcx = register context
    push rbx
    
    ; Format general purpose registers
    lea rdx, reg_display_buffer
    
    ; RAX
    mov rax, [rcx + 0]
    call format_hex_qword
    
    ; RBX  
    mov rax, [rcx + 8]
    call format_hex_qword
    
    ; Continue for all registers...
    
    pop rbx

asm_format_registers ENDP

; Memory Inspector
asm_read_memory PROC
    ; rcx = address, rdx = size
    push rbx

    push rsi
    push mov rsi, rcx        ; address
    mov rbx, rdx        ; size
    lea rdi, memory_display_buffer
    
read_loop:
    test rbx, rbx
    jz read_done
    
    mov al, [rsi]
    call format_hex_byte
    
    inc rsi
    dec rbx
    jmp read_loop
    
read_done:

    pop rsi
    pop asm
    pop rbx_read_memory ENDP

;==========================================================================
; Assembler Pane ASM Features
;==========================================================================

; Build System
asm_invoke_masm PROC
    ; rcx = source file path
    push rbx
    
    ; Construct MASM command line
    lea rdx, masm_cmdline
    call build_masm_command
    
    ; Execute MASM
    call execute_process
    
    ; Parse output for errors
    call parse_masm_output
    
    pop rbx

asm_invoke_masm ENDP

; Linker Interface  
asm_invoke_linker PROC
    ; rcx = object files, rdx = output path
    
    ; Build LINK command
    lea r8, link_cmdline
    call build_link_command
    
    ; Execute linker
    call execute_process
    
    ; Parse link map
    call parse_link_map
    
    ret
asm_invoke_linker ENDP

;==========================================================================
; Performance Pane ASM Features
;==========================================================================

; Code Profiler
asm_start_profiling PROC
    ; rcx = executable path
    
    ; Insert performance counters
    call insert_perf_counters
    
    ; Start execution with profiling
    call start_profiled_execution
    
    ret
asm_start_profiling ENDP

; Optimizer
asm_suggest_optimizations PROC
    ; rcx = asm code buffer
    
    ; Analyze instruction patterns
    call analyze_instruction_patterns
    
    ; Check for optimization opportunities
    call find_optimization_opportunities
    
    ; Generate suggestions
    call generate_optimization_suggestions
    
    ret
asm_suggest_optimizations ENDP

;==========================================================================
; Helper Functions
;==========================================================================

is_asm_instruction PROC
    ; rcx = text pointer
    ; Returns: eax = 1 if instruction, 0 if not
    
    ; Check against instruction table
    lea rdx, instruction_table
    call string_match_table
    
    ret
is_asm_instruction ENDP

is_asm_register PROC
    ; rcx = text pointer  
    ; Returns: eax = 1 if register, 0 if not
    
    lea rdx, register_table
    call string_match_table
    
    ret
is_asm_register ENDP

format_hex_qword PROC
    ; rax = value, rdx = output buffer
    
    ; Convert to hex string
    call qword_to_hex
    
    ret
format_hex_qword ENDP

;==========================================================================
; Data Tables
;==========================================================================
.data

instruction_table:
    db "mov", 0
    db "add", 0  
    db "sub", 0
    db "mul", 0
    db "div", 0
    db "jmp", 0
    db "call", 0
    db "ret", 0
    db 0        ; End marker

register_table:
    db "rax", 0
    db "rbx", 0
    db "rcx", 0
    db "rdx", 0
    db "rsi", 0
    db "rdi", 0
    db "rsp", 0
    db "rbp", 0
    db 0        ; End marker

reg_display_buffer      db 1024 dup(0)
memory_display_buffer   db 4096 dup(0)
masm_cmdline           db 512 dup(0)
link_cmdline           db 512 dup(0)

END




