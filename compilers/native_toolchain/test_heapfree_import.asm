; test_heapfree_import.asm - Test HeapFree import directly
; Build: ml64 /c /nologo test_heapfree_import.asm
; Link: gcc test_heapfree_import.obj test_heapfree_import.c -o test_heapfree_import.exe

EXTRN GetProcessHeap:PROC
EXTRN HeapAlloc:PROC
EXTRN HeapFree:PROC

.data
    g_heap QWORD 0

.code

; void* my_GetProcessHeap(void)
my_GetProcessHeap PROC
    sub rsp, 40        ; Shadow space + alignment
    call GetProcessHeap
    mov g_heap, rax    ; Save for later
    add rsp, 40
    ret
my_GetProcessHeap ENDP

; void* my_HeapAlloc(size_t size)
my_HeapAlloc PROC
    ; RCX = size
    sub rsp, 40        ; Shadow space + alignment
    mov r8, rcx        ; dwBytes = size
    xor rdx, rdx       ; dwFlags = 0
    mov rcx, g_heap    ; hHeap
    call HeapAlloc
    add rsp, 40
    ret
my_HeapAlloc ENDP

; int my_HeapFree(void* ptr)
my_HeapFree PROC
    ; RCX = ptr
    sub rsp, 40        ; Shadow space + alignment
    mov r8, rcx        ; lpMem = ptr
    xor rdx, rdx       ; dwFlags = 0
    mov rcx, g_heap    ; hHeap
    call HeapFree
    add rsp, 40
    ret
my_HeapFree ENDP

END