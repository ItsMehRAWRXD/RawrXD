import re

with open(r'd:\rawrxd\src\asm\Sovereign_Hardening_Core.asm', 'r', encoding='utf-8') as f:
    text = f.read()

# Move .DATA above STRUCT
struct_block = """SOVEREIGN_PAGE_RECORD STRUCT
    pVirtualAddress DQ 0            ; Base pointer returned by Windows VirtualAlloc
    cbSize          DQ 0            ; Allocation capacity size tracked in bytes
    uAllocationTag  DQ 0            ; Unique signature identifier (e.g., 'WEIGHTS', 'INPUT')
SOVEREIGN_PAGE_RECORD ENDS

.DATA"""

new_block = """.DATA
SOVEREIGN_PAGE_RECORD STRUCT
    pVirtualAddress DQ 0            ; Base pointer returned by Windows VirtualAlloc
    cbSize          DQ 0            ; Allocation capacity size tracked in bytes
    uAllocationTag  DQ 0            ; Unique signature identifier (e.g., 'WEIGHTS', 'INPUT')
SOVEREIGN_PAGE_RECORD ENDS"""

text = text.replace(struct_block, new_block)

with open(r'd:\rawrxd\src\asm\Sovereign_Hardening_Core.asm', 'w', encoding='utf-8') as f:
    f.write(text)
