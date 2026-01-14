;==============================================================================
; terminal_pool.inc - MASM Terminal Pool Manager Header
; Purpose: Declare exported functions and constants for terminal management
; Author: RawrXD CI/CD
; Date: Dec 29, 2025
;==============================================================================

IFNDEF TERMINAL_POOL_INC
TERMINAL_POOL_INC EQU 1

;==============================================================================
; CONSTANTS
;==============================================================================

; Process state constants
PROCESS_STATE_IDLE      EQU 0
PROCESS_STATE_RUNNING   EQU 1
PROCESS_STATE_PAUSED    EQU 2
PROCESS_STATE_TERMINATED EQU 3
PROCESS_STATE_ERROR     EQU 4

; Shell type constants
SHELL_TYPE_POWERSHELL   EQU 1
SHELL_TYPE_CMD          EQU 2
SHELL_TYPE_CUSTOM       EQU 3

; Maximum limits
MAX_TERMINALS           EQU 16
MAX_COMMAND_LINE        EQU 2048
MAX_OUTPUT_BUFFER       EQU 65536

; Special timeout values
WAIT_TIMEOUT_INFINITE   EQU -1

;==============================================================================
; FUNCTION PROTOTYPES
;==============================================================================

; Initialize the terminal pool system
; Returns: 1 = success, 0 = failure
IFNDEF @masm_terminal_pool_init
IFNDEF @masm_terminal_pool_init
EXTERN masm_terminal_pool_init:PROC
ENDIF
ENDIF

; Shut down the terminal pool system
; Returns: 1 = success, 0 = failure
IFNDEF @masm_terminal_pool_shutdown
IFNDEF @masm_terminal_pool_shutdown
EXTERN masm_terminal_pool_shutdown:PROC
ENDIF
ENDIF

; Spawn a new terminal process
; Args: RCX = shell type (SHELL_TYPE_*), RDX = command line (NULL for default)
; Returns: process ID or 0 if failure
IFNDEF @masm_terminal_spawn_process
IFNDEF @masm_terminal_spawn_process
EXTERN masm_terminal_spawn_process:PROC
ENDIF
ENDIF

; Terminate a process
; Args: RCX = process ID
; Returns: 1 = success, 0 = failure
IFNDEF @masm_terminal_kill_process
IFNDEF @masm_terminal_kill_process
EXTERN masm_terminal_kill_process:PROC
ENDIF
ENDIF

; Read output from a terminal process
; Args: RCX = process ID, RDX = output buffer pointer, R8 = buffer size
; Returns: bytes read or -1 if error
IFNDEF @masm_terminal_read_output
IFNDEF @masm_terminal_read_output
EXTERN masm_terminal_read_output:PROC
ENDIF
ENDIF

; Write input to a terminal process
; Args: RCX = process ID, RDX = input buffer pointer, R8 = input size
; Returns: bytes written or -1 if error
IFNDEF @masm_terminal_write_input
IFNDEF @masm_terminal_write_input
EXTERN masm_terminal_write_input:PROC
ENDIF
ENDIF

; Get status of a terminal process
; Args: RCX = process ID
; Returns: process state (PROCESS_STATE_*)
IFNDEF @masm_terminal_get_status
IFNDEF @masm_terminal_get_status
EXTERN masm_terminal_get_status:PROC
ENDIF
ENDIF

; Get exit code of terminated process
; Args: RCX = process ID
; Returns: exit code or -1 if still running
IFNDEF @masm_terminal_get_exit_code
IFNDEF @masm_terminal_get_exit_code
EXTERN masm_terminal_get_exit_code:PROC
ENDIF
ENDIF

; List all active process IDs
; Args: RCX = output buffer (DWORD array), RDX = max count
; Returns: actual count filled in buffer
IFNDEF @masm_terminal_list_processes
IFNDEF @masm_terminal_list_processes
EXTERN masm_terminal_list_processes:PROC
ENDIF
ENDIF

; Wait for process to terminate
; Args: RCX = process ID, RDX = timeout in milliseconds (INFINITE = -1)
; Returns: 1 if terminated, 0 if timeout, -1 if error
IFNDEF @masm_terminal_wait_for_process
IFNDEF @masm_terminal_wait_for_process
EXTERN masm_terminal_wait_for_process:PROC
ENDIF
ENDIF

; Get current process count
; Returns: number of processes in pool
IFNDEF @masm_terminal_get_process_count
IFNDEF @masm_terminal_get_process_count
EXTERN masm_terminal_get_process_count:PROC
ENDIF
ENDIF

ENDIF


