; Sovereign_Overfeatured_Memory.asm
include Sovereign_Common.inc
.DATA
align 16
g_Slab_64_Base dq 0
g_Slab_64_Bitmap dq 0
g_Slab_256_Base dq 0
g_Slab_256_Bitmap dq 0
.CODE
PUBLIC Sovereign_Slab_Init
Sovereign_Slab_Init PROC
SOVEREIGN_PUSH_FRAME
mov rcx, 0
mov rdx, 4096
mov r8, 3000h
mov r9, 04h
call [g_ApiTable.pVirtualAlloc]
mov [g_Slab_64_Base], rax
mov rdx, 16384
call [g_ApiTable.pVirtualAlloc]
mov [g_Slab_256_Base], rax
SOVEREIGN_POP_FRAME
ret
Sovereign_Slab_Init ENDP
PUBLIC Sovereign_Alloc_64
Sovereign_Alloc_64 PROC
@@Retry:
mov rax, [g_Slab_64_Bitmap]
not rax
test rax, rax
jz @@Full
bsf rdx, rax
mov r8, 1
mov ecx, edx
shl r8, cl
mov rax, [g_Slab_64_Bitmap]
mov r9, rax
or r9, r8
lock cmpxchg [g_Slab_64_Bitmap], r9
jnz @@Retry
mov rax, [g_Slab_64_Base]
shl rdx, 6
add rax, rdx
ret
@@Full:
xor rax, rax
ret
Sovereign_Alloc_64 ENDP
PUBLIC Sovereign_Free_64
Sovereign_Free_64 PROC
mov rax, rcx
sub rax, [g_Slab_64_Base]
shr rax, 6
mov r8, 1
mov ecx, eax
shl r8, cl
not r8
@@Retry:
mov rax, [g_Slab_64_Bitmap]
mov r9, rax
and r9, r8
lock cmpxchg [g_Slab_64_Bitmap], r9
jnz @@Retry
ret
Sovereign_Free_64 ENDP
END
