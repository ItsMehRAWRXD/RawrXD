import re

with open(r'd:\rawrxd\src\asm\Sovereign_Hardening_Core.asm', 'r', encoding='utf-8') as f:
    text = f.read()

# Fix .DATA block
text = text.replace('ALIGN 64', 'ALIGN 16')

# Fix [rdi + rdx * TYPE SOVEREIGN_PAGE_RECORD + SOVEREIGN_PAGE_RECORD.pVirtualAddress]
# We need to replace the loop logic.

# In Sovereign_Alloc_Tracked:
old_alloc_loop = """@@FindSlotLoop:
    mov r8, [rdi + rdx * TYPE SOVEREIGN_PAGE_RECORD + SOVEREIGN_PAGE_RECORD.pVirtualAddress]
    test r8, r8
    jz @@SlotAcquired
    inc rdx
    loop @@FindSlotLoop"""

new_alloc_loop = """@@FindSlotLoop:
    mov r9, TYPE SOVEREIGN_PAGE_RECORD
    imul r9, rdx
    mov r8, [rdi + r9 + SOVEREIGN_PAGE_RECORD.pVirtualAddress]
    test r8, r8
    jz @@SlotAcquired
    inc rdx
    loop @@FindSlotLoop"""

text = text.replace(old_alloc_loop, new_alloc_loop)

old_alloc_acquire = """@@SlotAcquired:
    ; Commit Allocation Map Metrics Into Persistent Global Layout
    mov [rdi + rdx * TYPE SOVEREIGN_PAGE_RECORD + SOVEREIGN_PAGE_RECORD.pVirtualAddress], rax
    mov [rdi + rdx * TYPE SOVEREIGN_PAGE_RECORD + SOVEREIGN_PAGE_RECORD.cbSize], rbx
    mov [rdi + rdx * TYPE SOVEREIGN_PAGE_RECORD + SOVEREIGN_PAGE_RECORD.uAllocationTag], rsi"""

new_alloc_acquire = """@@SlotAcquired:
    ; Commit Allocation Map Metrics Into Persistent Global Layout
    mov r9, TYPE SOVEREIGN_PAGE_RECORD
    imul r9, rdx
    mov [rdi + r9 + SOVEREIGN_PAGE_RECORD.pVirtualAddress], rax
    mov [rdi + r9 + SOVEREIGN_PAGE_RECORD.cbSize], rbx
    mov [rdi + r9 + SOVEREIGN_PAGE_RECORD.uAllocationTag], rsi"""

text = text.replace(old_alloc_acquire, new_alloc_acquire)

# In Sovereign_Free_Tracked:
old_free_loop = """@@LookupLoop:
    mov r8, [rdi + rdx * TYPE SOVEREIGN_PAGE_RECORD + SOVEREIGN_PAGE_RECORD.pVirtualAddress]
    cmp r8, rbx
    je @@TargetMapIdentified
    inc rdx
    loop @@LookupLoop"""

new_free_loop = """@@LookupLoop:
    mov r9, TYPE SOVEREIGN_PAGE_RECORD
    imul r9, rdx
    mov r8, [rdi + r9 + SOVEREIGN_PAGE_RECORD.pVirtualAddress]
    cmp r8, rbx
    je @@TargetMapIdentified
    inc rdx
    loop @@LookupLoop"""

text = text.replace(old_free_loop, new_free_loop)

old_free_clear = """@@TargetMapIdentified:
    ; Clear mapping signature immediately to prevent race reuse vectors
    mov [rdi + rdx * TYPE SOVEREIGN_PAGE_RECORD + SOVEREIGN_PAGE_RECORD.pVirtualAddress], 0
    mov [rdi + rdx * TYPE SOVEREIGN_PAGE_RECORD + SOVEREIGN_PAGE_RECORD.cbSize], 0
    mov [rdi + rdx * TYPE SOVEREIGN_PAGE_RECORD + SOVEREIGN_PAGE_RECORD.uAllocationTag], 0"""

new_free_clear = """@@TargetMapIdentified:
    ; Clear mapping signature immediately to prevent race reuse vectors
    mov r9, TYPE SOVEREIGN_PAGE_RECORD
    imul r9, rdx
    mov qword ptr [rdi + r9 + SOVEREIGN_PAGE_RECORD.pVirtualAddress], 0
    mov qword ptr [rdi + r9 + SOVEREIGN_PAGE_RECORD.cbSize], 0
    mov qword ptr [rdi + r9 + SOVEREIGN_PAGE_RECORD.uAllocationTag], 0"""

text = text.replace(old_free_clear, new_free_clear)

with open(r'd:\rawrxd\src\asm\Sovereign_Hardening_Core.asm', 'w', encoding='utf-8') as f:
    f.write(text)
