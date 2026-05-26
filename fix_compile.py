import re

with open('d:/rawrxd/dequant_simd.asm', 'r', encoding='utf-8') as f:
    text = f.read()

# Fix alignment of .DATA? block
text = text.replace('ALIGN 64', 'ALIGN 16')
text = text.replace('ALIGN 4096\n; Guard page: Access here triggers Exception 0xC0000005\nRedZone_Guard db 4096 dup(0xCC)', '.DATA\nALIGN 16\nRedZone_Guard db 4096 dup(0CCh)\n.DATA?')
with open('d:/rawrxd/dequant_simd.asm', 'w', encoding='utf-8') as f:
    f.write(text)
print("fixed")
