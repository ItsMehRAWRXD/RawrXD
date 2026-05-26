; =============================================================================
; Titan_SRW_Definitions.inc
; INTERNAL ZERO-INCLUDE PROTOTYPES (Replaces masm64rt.inc)
; =============================================================================

; --- Windows Types ---
HANDLE  TYPEDEF QWORD
LPVOID  TYPEDEF QWORD
HWND    TYPEDEF QWORD
UINT    TYPEDEF DWORD
WPARAM  TYPEDEF QWORD
LPARAM  TYPEDEF QWORD

; --- SRWLOCK Structure ---
SRWLOCK TYPEDEF QWORD

; --- Windows Kernel32 / User32 Prototypes ---
extern AcquireSRWLockExclusive : proc
extern ReleaseSRWLockExclusive : proc
extern AcquireSRWLockShared    : proc
extern ReleaseSRWLockShared    : proc
extern GetCurrentProcess        : proc
extern VirtualLock             : proc
extern ExitProcess             : proc
extern QueryPerformanceCounter  : proc
extern QueryPerformanceFrequency: proc

; --- Vulkan / DirectStorage Prototypes ---
extern vkQueueBindSparse        : proc
extern vkCmdPushConstants       : proc
extern vkCmdDispatch            : proc
extern vkWaitForFences          : proc
extern vkResetFences            : proc
extern DStorageGetFactory       : proc

; --- Titan Macros ---
ACQUIRE_LOCK MACRO lock_ptr
    mov rcx, lock_ptr
    call AcquireSRWLockExclusive
ENDM

RELEASE_LOCK MACRO lock_ptr
    mov rcx, lock_ptr
    call ReleaseSRWLockExclusive
ENDM
