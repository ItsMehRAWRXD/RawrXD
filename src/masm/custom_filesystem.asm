;==========================================================================
; custom_filesystem.asm - Zero-Dependency File System for RawrXD IDE
; ==========================================================================
; Implements file operations using direct disk access and BIOS interrupts
; Replaces CreateFile, ReadFile, WriteFile, FindFirstFile, etc.
;==========================================================================

option casemap:none

;==========================================================================
; BIOS INTERRUPT CONSTANTS
;==========================================================================
BIOS_DISK_READ          equ 02h
BIOS_DISK_WRITE         equ 03h
BIOS_GET_DRIVE_PARAMS   equ 08h
BIOS_EXT_READ           equ 42h
BIOS_EXT_WRITE          equ 43h

;==========================================================================
; DISK STRUCTURES
;==========================================================================
DISK_ADDRESS_PACKET STRUCT
    packet_size         BYTE ?
    reserved            BYTE ?
    sector_count        WORD ?
    buffer_offset       WORD ?
    buffer_segment      WORD ?
    lba_low             DWORD ?
    lba_high            DWORD ?
DISK_ADDRESS_PACKET ENDS

FILE_HANDLE STRUCT
    path                QWORD ?
    position            DWORD ?
    size                DWORD ?
    sector              DWORD ?
    buffer              QWORD ?
    mode                BYTE ?
FILE_HANDLE ENDS

DIRECTORY_ENTRY STRUCT
    name                BYTE 11 DUP(?)
    attributes          BYTE ?
    reserved            BYTE 10 DUP(?)
    time                WORD ?
    date                WORD ?
    cluster             WORD ?
    size                DWORD ?
DIRECTORY_ENTRY ENDS

;==========================================================================
; GLOBAL VARIABLES
;==========================================================================
.data
    current_drive       BYTE 0
    sector_size         WORD 512
    heads               WORD 0
    sectors_per_track   WORD 0
    cylinders           WORD 0
    
    ; File handle table
    file_handles        QWORD 16 DUP(0)
    handle_count        DWORD 0
    
    ; Current directory
    current_path        BYTE "C:\\", 0
    path_buffer         BYTE 260 DUP(0)

;==========================================================================
; DISK OPERATIONS
;==========================================================================
.code

;--------------------------------------------------------------------------
; init_disk_system - Initialize disk parameters
;--------------------------------------------------------------------------
init_disk_system PROC
    push rbp
    mov rbp, rsp
    
    ; Get drive parameters
    mov ah, BIOS_GET_DRIVE_PARAMS
    mov dl, current_drive
    int 13h
    jc disk_init_failed
    
    ; Extract parameters
    mov sectors_per_track, cl
    and sectors_per_track, 3Fh
    mov heads, dh
    inc heads  ; DH is max head number
    mov cylinders, ch
    mov cl, cl
    shr cl, 6
    mov ch, ch
    mov ax, cx
    mov cylinders, ax
    
disk_init_failed:
    leave
    ret
init_disk_system ENDP

;--------------------------------------------------------------------------
; read_sectors - Read sectors from disk
; rcx = lba, rdx = count, r8 = buffer
; Returns: success in rax (0 = success)
;--------------------------------------------------------------------------
read_sectors PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Convert LBA to CHS if needed
    call lba_to_chs
    
    ; Use extended read if available
    mov ah, BIOS_EXT_READ
    lea si, [rsp + 16]
    mov dl, current_drive
    int 13h
    jc try_chs_read
    xor rax, rax
    jmp read_done
    
try_chs_read:
    ; Fall back to CHS read
    mov ah, BIOS_DISK_READ
    mov al, dl  ; sector count
    mov ch, bl  ; cylinder
    mov cl, bh  ; sector
    mov dh, dl  ; head
    mov dl, current_drive
    mov bx, r8w
    int 13h
    jc read_error
    xor rax, rax
    jmp read_done
    
read_error:
    mov rax, 1
    
read_done:
    leave
    ret
read_sectors ENDP

;--------------------------------------------------------------------------
; write_sectors - Write sectors to disk
; rcx = lba, rdx = count, r8 = buffer
; Returns: success in rax (0 = success)
;--------------------------------------------------------------------------
write_sectors PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Convert LBA to CHS if needed
    call lba_to_chs
    
    ; Use extended write if available
    mov ah, BIOS_EXT_WRITE
    lea si, [rsp + 16]
    mov dl, current_drive
    int 13h
    jc try_chs_write
    xor rax, rax
    jmp write_done
    
try_chs_write:
    ; Fall back to CHS write
    mov ah, BIOS_DISK_WRITE
    mov al, dl  ; sector count
    mov ch, bl  ; cylinder
    mov cl, bh  ; sector
    mov dh, dl  ; head
    mov dl, current_drive
    mov bx, r8w
    int 13h
    jc write_error
    xor rax, rax
    jmp write_done
    
write_error:
    mov rax, 1
    
write_done:
    leave
    ret
write_sectors ENDP

;--------------------------------------------------------------------------
; lba_to_chs - Convert LBA to CHS addressing
; rcx = lba
; Returns: ch=cylinder, cl=sector, dh=head
;--------------------------------------------------------------------------
lba_to_chs PROC
    push rbp
    mov rbp, rsp
    
    mov eax, ecx
    xor edx, edx
    mov ebx, sectors_per_track
    div ebx
    mov cl, dl  ; sector = (LBA % sectors_per_track) + 1
    inc cl
    
    xor edx, edx
    mov ebx, heads
    div ebx
    mov ch, al  ; cylinder = temp / heads
    mov dh, dl  ; head = temp % heads
    
    leave
    ret
lba_to_chs ENDP

;==========================================================================
; FILE OPERATIONS
;==========================================================================

;--------------------------------------------------------------------------
; fs_open - Open a file (replaces CreateFileA)
; rcx = path, rdx = mode
; Returns: handle in rax
;--------------------------------------------------------------------------
fs_open PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    
    ; Allocate file handle
    mov rcx, sizeof FILE_HANDLE
    call sys_alloc_memory
    mov rsi, rax
    
    ; Copy path
    mov rcx, 260
    call sys_alloc_memory
    mov QWORD PTR [rsi + FILE_HANDLE.path], rax
    
    mov rdi, rax
    mov rsi, rcx
path_copy:
    mov al, BYTE PTR [rsi]
    mov BYTE PTR [rdi], al
    test al, al
    jz path_copied
    inc rsi
    inc rdi
    jmp path_copy
    
path_copied:
    ; Initialize handle
    mov DWORD PTR [rsi + FILE_HANDLE.position], 0
    mov DWORD PTR [rsi + FILE_HANDLE.size], 0
    mov DWORD PTR [rsi + FILE_HANDLE.sector], 0
    mov QWORD PTR [rsi + FILE_HANDLE.buffer], 0
    mov BYTE PTR [rsi + FILE_HANDLE.mode], dl
    
    ; Find file and get size
    call find_file
    test rax, rax
    jz open_failed
    mov DWORD PTR [rsi + FILE_HANDLE.size], eax
    
    ; Allocate buffer
    mov rcx, rax
    call sys_alloc_memory
    mov QWORD PTR [rsi + FILE_HANDLE.buffer], rax
    
    ; Read file content
    mov rcx, rsi
    call read_entire_file
    
    ; Add to handle table
    call add_file_handle
    
    mov rax, rsi
    jmp open_done
    
open_failed:
    ; Free allocated memory
    mov rcx, QWORD PTR [rsi + FILE_HANDLE.path]
    call sys_free_memory
    mov rcx, rsi
    call sys_free_memory
    xor rax, rax
    
open_done:
    leave
    ret
fs_open ENDP

;--------------------------------------------------------------------------
; fs_close - Close a file (replaces CloseHandle)
; rcx = handle
;--------------------------------------------------------------------------
fs_close PROC
    push rbp
    mov rbp, rsp
    
    mov rsi, rcx
    
    ; Write changes if needed
    test BYTE PTR [rsi + FILE_HANDLE.mode], 2  ; Write mode
    jz no_write
    call write_entire_file
    
no_write:
    ; Free buffers
    mov rcx, QWORD PTR [rsi + FILE_HANDLE.buffer]
    call sys_free_memory
    mov rcx, QWORD PTR [rsi + FILE_HANDLE.path]
    call sys_free_memory
    
    ; Remove from handle table
    call remove_file_handle
    
    ; Free handle
    mov rcx, rsi
    call sys_free_memory
    
    leave
    ret
fs_close ENDP

;--------------------------------------------------------------------------
; fs_read - Read from file (replaces ReadFile)
; rcx = handle, rdx = buffer, r8 = length, r9 = bytes_read
; Returns: success in rax
;--------------------------------------------------------------------------
fs_read PROC
    push rbp
    mov rbp, rsp
    
    mov rsi, rcx
    
    ; Check bounds
    mov eax, DWORD PTR [rsi + FILE_HANDLE.position]
    mov ebx, DWORD PTR [rsi + FILE_HANDLE.size]
    cmp eax, ebx
    jge read_eof
    
    ; Calculate bytes to read
    mov ecx, r8d
    mov edx, ebx
    sub edx, eax
    cmp ecx, edx
    jle read_ok
    mov ecx, edx
    
read_ok:
    ; Copy data
    mov rdi, rdx
    mov rsi, QWORD PTR [rsi + FILE_HANDLE.buffer]
    add rsi, rax
    rep movsb
    
    ; Update position
    add DWORD PTR [rsi + FILE_HANDLE.position], ecx
    
    ; Set bytes read
    mov DWORD PTR [r9], ecx
    xor rax, rax
    jmp read_done
    
read_eof:
    mov DWORD PTR [r9], 0
    mov rax, 1
    
read_done:
    leave
    ret
fs_read ENDP

;--------------------------------------------------------------------------
; fs_write - Write to file (replaces WriteFile)
; rcx = handle, rdx = buffer, r8 = length, r9 = bytes_written
; Returns: success in rax
;--------------------------------------------------------------------------
fs_write PROC
    push rbp
    mov rbp, rsp
    
    mov rsi, rcx
    
    ; Check if write mode
    test BYTE PTR [rsi + FILE_HANDLE.mode], 2
    jz write_error
    
    ; Expand buffer if needed
    mov eax, DWORD PTR [rsi + FILE_HANDLE.position]
    add eax, r8d
    cmp eax, DWORD PTR [rsi + FILE_HANDLE.size]
    jle no_expand
    
    ; Reallocate buffer
    mov DWORD PTR [rsi + FILE_HANDLE.size], eax
    mov rcx, QWORD PTR [rsi + FILE_HANDLE.buffer]
    call sys_free_memory
    mov rcx, rax
    call sys_alloc_memory
    mov QWORD PTR [rsi + FILE_HANDLE.buffer], rax
    
no_expand:
    ; Copy data
    mov rdi, QWORD PTR [rsi + FILE_HANDLE.buffer]
    add rdi, DWORD PTR [rsi + FILE_HANDLE.position]
    mov rsi, rdx
    mov ecx, r8d
    rep movsb
    
    ; Update position
    add DWORD PTR [rsi + FILE_HANDLE.position], r8d
    
    ; Set bytes written
    mov DWORD PTR [r9], r8d
    xor rax, rax
    jmp write_done
    
write_error:
    mov DWORD PTR [r9], 0
    mov rax, 1
    
write_done:
    leave
    ret
fs_write ENDP

;==========================================================================
; FILE SYSTEM HELPERS
;==========================================================================

;--------------------------------------------------------------------------
; find_file - Find file and get size
; rcx = path
; Returns: size in rax, 0 if not found
;--------------------------------------------------------------------------
find_file PROC
    push rbp
    mov rbp, rsp
    
    ; This is simplified - real implementation would parse FAT/MFT
    ; For now, assume file exists and return fixed size
    mov rax, 4096  ; Default size
    
    leave
    ret
find_file ENDP

;--------------------------------------------------------------------------
; read_entire_file - Read entire file into buffer
; rcx = handle
;--------------------------------------------------------------------------
read_entire_file PROC
    push rbp
    mov rbp, rsp
    
    ; Simplified - just zero the buffer for now
    mov rsi, rcx
    mov rdi, QWORD PTR [rsi + FILE_HANDLE.buffer]
    mov ecx, DWORD PTR [rsi + FILE_HANDLE.size]
    xor al, al
    rep stosb
    
    leave
    ret
read_entire_file ENDP

;--------------------------------------------------------------------------
; write_entire_file - Write buffer to file
; rcx = handle
;--------------------------------------------------------------------------
write_entire_file PROC
    push rbp
    mov rbp, rsp
    
    ; Simplified - would write to disk sectors
    
    leave
    ret
write_entire_file ENDP

;--------------------------------------------------------------------------
; add_file_handle - Add handle to table
; rcx = handle
;--------------------------------------------------------------------------
add_file_handle PROC
    push rbp
    mov rbp, rsp
    
    mov rsi, rcx
    mov ecx, handle_count
    cmp ecx, 16
    jge handle_table_full
    
    lea rax, file_handles
    mov QWORD PTR [rax + rcx*8], rsi
    inc handle_count
    
handle_table_full:
    leave
    ret
add_file_handle ENDP

;--------------------------------------------------------------------------
; remove_file_handle - Remove handle from table
; rcx = handle
;--------------------------------------------------------------------------
remove_file_handle PROC
    push rbp
    mov rbp, rsp
    
    mov rsi, rcx
    mov ecx, handle_count
    lea rdi, file_handles
    
find_handle:
    mov rax, QWORD PTR [rdi + rcx*8]
    cmp rax, rsi
    je remove_it
    dec ecx
    jns find_handle
    jmp remove_done
    
remove_it:
    mov QWORD PTR [rdi + rcx*8], 0
    dec handle_count
    
remove_done:
    leave
    ret
remove_file_handle ENDP

;==========================================================================
; DIRECTORY OPERATIONS
;==========================================================================

;--------------------------------------------------------------------------
; fs_find_first - Find first file (replaces FindFirstFileA)
; rcx = pattern
; Returns: handle in rax
;--------------------------------------------------------------------------
fs_find_first PROC
    push rbp
    mov rbp, rsp
    
    ; Simplified - return dummy handle
    mov rax, 1
    
    leave
    ret
fs_find_first ENDP

;--------------------------------------------------------------------------
; fs_find_next - Find next file (replaces FindNextFileA)
; rcx = handle
; Returns: success in rax
;--------------------------------------------------------------------------
fs_find_next PROC
    push rbp
    mov rbp, rsp
    
    ; Simplified - always fail (no more files)
    xor rax, rax
    
    leave
    ret
fs_find_next ENDP

;--------------------------------------------------------------------------
; fs_find_close - Close find handle (replaces FindClose)
; rcx = handle
;--------------------------------------------------------------------------
fs_find_close PROC
    push rbp
    mov rbp, rsp
    
    ; Nothing to do for dummy handle
    xor rax, rax
    
    leave
    ret
fs_find_close ENDP

;==========================================================================
; EXPORTS
;==========================================================================
PUBLIC init_disk_system
PUBLIC fs_open
PUBLIC fs_close
PUBLIC fs_read
PUBLIC fs_write
PUBLIC fs_find_first
PUBLIC fs_find_next
PUBLIC fs_find_close

END