;==============================================================================
; logging.inc - Logging System Include File
; ==============================================================================
; Provides declarations for the logging system.
;==============================================================================

; Log levels
LOG_LEVEL_DEBUG     EQU 0
LOG_LEVEL_INFO      EQU 1
LOG_LEVEL_WARNING   EQU 2
LOG_LEVEL_ERROR     EQU 3
LOG_LEVEL_SUCCESS   EQU 4

; External function declarations
EXTERN LogInitialize:PROC
EXTERN LogDebug:PROC
EXTERN LogInfo:PROC
EXTERN LogWarning:PROC
EXTERN LogError:PROC
EXTERN LogSuccess:PROC
EXTERN LogShutdown:PROC

