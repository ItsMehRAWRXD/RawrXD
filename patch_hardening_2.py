import re

with open(r'd:\rawrxd\src\asm\Sovereign_Hardening_Core.asm', 'r', encoding='utf-8') as f:
    text = f.read()

# Remove ALIGN 8 before SOVEREIGN_PAGE_RECORD STRUCT
# It might be: ALIGN 8\nSOVEREIGN_PAGE_RECORD STRUCT
text = text.replace('ALIGN 8\nSOVEREIGN_PAGE_RECORD STRUCT', 'SOVEREIGN_PAGE_RECORD STRUCT')

# Change 16 DUP(<0>) to 16 DUP(<>)
text = text.replace('16 DUP(<0>)', '16 DUP(<>)')

with open(r'd:\rawrxd\src\asm\Sovereign_Hardening_Core.asm', 'w', encoding='utf-8') as f:
    f.write(text)
