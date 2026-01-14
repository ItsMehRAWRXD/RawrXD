;==========================================================================
; custom_system.inc - Custom System Definitions (No Windows SDK)
;==========================================================================
; Pure assembly system interface without any Windows dependencies
;==========================================================================

;--------------------------------------------------------------------------
; Custom Data Types
;--------------------------------------------------------------------------
BYTE    TYPEDEF BYTE
WORD    TYPEDEF WORD  
DWORD   typedef DWORD
QWORD   typedef QWORD
REAL4   TYPEDEF REAL4
REAL8   TYPEDEF REAL8

;--------------------------------------------------------------------------
; System Call Numbers (Linux x64 ABI)
;--------------------------------------------------------------------------
SYS_READ        EQU 0
SYS_WRITE       EQU 1
SYS_OPEN        EQU 2
SYS_CLOSE       EQU 3
SYS_STAT        EQU 4
SYS_FSTAT       EQU 5
SYS_LSTAT       EQU 6
SYS_POLL        EQU 7
SYS_LSEEK       EQU 8
SYS_MMAP        EQU 9
SYS_MPROTECT    EQU 10
SYS_MUNMAP      EQU 11
SYS_BRK         EQU 12
SYS_RT_SIGACTION EQU 13
SYS_RT_SIGPROCMASK EQU 14
SYS_RT_SIGRETURN EQU 15
SYS_IOCTL       EQU 16
SYS_PREAD64     EQU 17
SYS_PWRITE64    EQU 18
SYS_READV       EQU 19
SYS_WRITEV      EQU 20
SYS_ACCESS      EQU 21
SYS_PIPE        EQU 22
SYS_SELECT      EQU 23
SYS_SCHED_YIELD EQU 24
SYS_MREMAP      EQU 25
SYS_MSYNC       EQU 26
SYS_MINCORE     EQU 27
SYS_MADVISE     EQU 28
SYS_SHMGET      EQU 29
SYS_SHMAT       EQU 30
SYS_SHMCTL      EQU 31
SYS_DUP         EQU 32
SYS_DUP2        EQU 33
SYS_PAUSE       EQU 34
SYS_NANOSLEEP   EQU 35
SYS_GETITIMER   EQU 36
SYS_ALARM       EQU 37
SYS_SETITIMER   EQU 38
SYS_GETPID      EQU 39
SYS_SENDFILE    EQU 40
SYS_SOCKET      EQU 41
SYS_CONNECT     EQU 42
SYS_ACCEPT      EQU 43
SYS_SENDTO      EQU 44
SYS_RECVFROM    EQU 45
SYS_SENDMSG     EQU 46
SYS_RECVMSG     EQU 47
SYS_SHUTDOWN    EQU 48
SYS_BIND        EQU 49
SYS_LISTEN      EQU 50
SYS_GETSOCKNAME EQU 51
SYS_GETPEERNAME EQU 52
SYS_SOCKETPAIR  EQU 53
SYS_SETSOCKOPT  EQU 54
SYS_GETSOCKOPT  EQU 55
SYS_CLONE       EQU 56
SYS_FORK        EQU 57
SYS_VFORK       EQU 58
SYS_EXECVE      EQU 59
SYS_EXIT        EQU 60

;--------------------------------------------------------------------------
; Memory Protection Flags
;--------------------------------------------------------------------------
PROT_NONE       EQU 0
PROT_READ       EQU 1
PROT_WRITE      EQU 2
PROT_EXEC       EQU 4

;--------------------------------------------------------------------------
; Memory Mapping Flags
;--------------------------------------------------------------------------
MAP_SHARED      EQU 1
MAP_PRIVATE     EQU 2
MAP_FIXED       EQU 10h
MAP_ANONYMOUS   EQU 20h
MAP_GROWSDOWN   EQU 100h
MAP_DENYWRITE   EQU 800h
MAP_EXECUTABLE  EQU 1000h
MAP_LOCKED      EQU 2000h
MAP_NORESERVE   EQU 4000h

;--------------------------------------------------------------------------
; File Access Modes
;--------------------------------------------------------------------------
O_RDONLY        EQU 0
O_WRONLY        EQU 1
O_RDWR          EQU 2
O_CREAT         EQU 40h
O_EXCL          EQU 80h
O_NOCTTY        EQU 100h
O_TRUNC         EQU 200h
O_APPEND        EQU 400h
O_NONBLOCK      EQU 800h
O_SYNC          EQU 1000h

;--------------------------------------------------------------------------
; Socket Types
;--------------------------------------------------------------------------
SOCK_STREAM     EQU 1
SOCK_DGRAM      EQU 2
SOCK_RAW        EQU 3
SOCK_RDM        EQU 4
SOCK_SEQPACKET  EQU 5

;--------------------------------------------------------------------------
; Address Families
;--------------------------------------------------------------------------
AF_UNSPEC       EQU 0
AF_UNIX         EQU 1
AF_LOCAL        EQU 1
AF_INET         EQU 2
AF_AX25         EQU 3
AF_IPX          EQU 4
AF_APPLETALK    EQU 5
AF_NETROM       EQU 6
AF_BRIDGE       EQU 7
AF_ATMPVC       EQU 8
AF_X25          EQU 9
AF_INET6        EQU 10

;--------------------------------------------------------------------------
; Protocol Families
;--------------------------------------------------------------------------
PF_UNSPEC       EQU AF_UNSPEC
PF_UNIX         EQU AF_UNIX
PF_LOCAL        EQU AF_LOCAL
PF_INET         EQU AF_INET
PF_AX25         EQU AF_AX25
PF_IPX          EQU AF_IPX
PF_APPLETALK    EQU AF_APPLETALK
PF_NETROM       EQU AF_NETROM
PF_BRIDGE       EQU AF_BRIDGE
PF_ATMPVC       EQU AF_ATMPVC
PF_X25          EQU AF_X25
PF_INET6        EQU AF_INET6

;--------------------------------------------------------------------------
; Standard File Descriptors
;--------------------------------------------------------------------------
STDIN_FILENO    EQU 0
STDOUT_FILENO   EQU 1
STDERR_FILENO   EQU 2

;--------------------------------------------------------------------------
; Error Codes
;--------------------------------------------------------------------------
EPERM           EQU 1
ENOENT          EQU 2
ESRCH           EQU 3
EINTR           EQU 4
EIO             EQU 5
ENXIO           EQU 6
E2BIG           EQU 7
ENOEXEC         EQU 8
EBADF           EQU 9
ECHILD          EQU 10
EAGAIN          EQU 11
ENOMEM          EQU 12
EACCES          EQU 13
EFAULT          EQU 14
ENOTBLK         EQU 15
EBUSY           EQU 16
EEXIST          EQU 17
EXDEV           EQU 18
ENODEV          EQU 19
ENOTDIR         EQU 20

;--------------------------------------------------------------------------
; Custom Macros
;--------------------------------------------------------------------------
SYSCALL MACRO syscall_num:REQ, arg1, arg2, arg3, arg4, arg5, arg6
    mov rax, syscall_num
    IFNB <arg1>
        mov rdi, arg1
    ENDIF
    IFNB <arg2>
        mov rsi, arg2
    ENDIF
    IFNB <arg3>
        mov rdx, arg3
    ENDIF
    IFNB <arg4>
        mov r10, arg4
    ENDIF
    IFNB <arg5>
        mov r8, arg5
    ENDIF
    IFNB <arg6>
        mov r9, arg6
    ENDIF
    syscall
ENDM

PRINT_STRING MACRO str_addr:REQ, str_len:REQ
    SYSCALL SYS_WRITE, STDOUT_FILENO, str_addr, str_len
ENDM

ALLOCATE_MEMORY MACRO size:REQ
    SYSCALL SYS_MMAP, 0, size, PROT_READ OR PROT_WRITE, MAP_PRIVATE OR MAP_ANONYMOUS, -1, 0
ENDM

FREE_MEMORY MACRO addr:REQ, size:REQ
    SYSCALL SYS_MUNMAP, addr, size
ENDM

;--------------------------------------------------------------------------
; Custom Structure Templates
;--------------------------------------------------------------------------
CUSTOM_SOCKADDR_IN STRUCT
    sin_family      WORD ?
    sin_port        WORD ?
    sin_addr        DWORD ?
    sin_zero        BYTE 8 DUP (?)
CUSTOM_SOCKADDR_IN ENDS

CUSTOM_STAT STRUCT
    st_dev          QWORD ?
    st_ino          QWORD ?
    st_nlink        QWORD ?
    st_mode         DWORD ?
    st_uid          DWORD ?
    st_gid          DWORD ?
    st_rdev         QWORD ?
    st_size         QWORD ?
    st_blksize      QWORD ?
    st_blocks       QWORD ?
    st_atime        QWORD ?
    st_atime_nsec   QWORD ?
    st_mtime        QWORD ?
    st_mtime_nsec   QWORD ?
    st_ctime        QWORD ?
    st_ctime_nsec   QWORD ?
CUSTOM_STAT ENDS

CUSTOM_TIMESPEC STRUCT
    tv_sec          QWORD ?
    tv_nsec         QWORD ?
CUSTOM_TIMESPEC ENDS

;--------------------------------------------------------------------------
; Crypto Constants
;--------------------------------------------------------------------------
AES_BLOCK_SIZE      EQU 16
AES_KEY_SIZE_128    EQU 16
AES_KEY_SIZE_192    EQU 24
AES_KEY_SIZE_256    EQU 32

SHA1_DIGEST_SIZE    EQU 20
SHA256_DIGEST_SIZE  EQU 32
SHA512_DIGEST_SIZE  EQU 64

MD5_DIGEST_SIZE     EQU 16

;--------------------------------------------------------------------------
; Network Constants
;--------------------------------------------------------------------------
IPPROTO_IP          EQU 0
IPPROTO_ICMP        EQU 1
IPPROTO_TCP         EQU 6
IPPROTO_UDP         EQU 17

INADDR_ANY          EQU 0
INADDR_LOOPBACK     EQU 7F000001h

;--------------------------------------------------------------------------
; Custom Function Prototypes
;--------------------------------------------------------------------------
custom_syscall      PROTO
custom_malloc       PROTO
custom_free         PROTO
custom_memcpy       PROTO
custom_memset       PROTO
custom_strlen       PROTO
custom_strcmp       PROTO
custom_strcpy       PROTO
custom_aes_encrypt  PROTO
custom_aes_decrypt  PROTO
custom_sha256       PROTO
custom_socket_create PROTO
custom_socket_bind  PROTO
custom_socket_listen PROTO
custom_socket_accept PROTO
custom_socket_connect PROTO
custom_socket_send  PROTO
custom_socket_recv  PROTO
custom_socket_close PROTO


