; RFC 1952 gzip wrapper containing RFC 1951 DEFLATE stored blocks.
; Stored blocks are intentionally fast and never expand the payload by more
; than five bytes per 65,535-byte block plus the 18-byte gzip framing.
; CRC32 uses the IEEE polynomial (not SSE4.2 CRC32C).
OPTION casemap:none
PUBLIC deflate_brutal_masm
EXTERN malloc:PROC

.const
ALIGN 4
crc32_table LABEL DWORD
    DWORD 000000000h, 077073096h, 0EE0E612Ch, 0990951BAh, 0076DC419h, 0706AF48Fh, 0E963A535h, 09E6495A3h
    DWORD 00EDB8832h, 079DCB8A4h, 0E0D5E91Eh, 097D2D988h, 009B64C2Bh, 07EB17CBDh, 0E7B82D07h, 090BF1D91h
    DWORD 01DB71064h, 06AB020F2h, 0F3B97148h, 084BE41DEh, 01ADAD47Dh, 06DDDE4EBh, 0F4D4B551h, 083D385C7h
    DWORD 0136C9856h, 0646BA8C0h, 0FD62F97Ah, 08A65C9ECh, 014015C4Fh, 063066CD9h, 0FA0F3D63h, 08D080DF5h
    DWORD 03B6E20C8h, 04C69105Eh, 0D56041E4h, 0A2677172h, 03C03E4D1h, 04B04D447h, 0D20D85FDh, 0A50AB56Bh
    DWORD 035B5A8FAh, 042B2986Ch, 0DBBBC9D6h, 0ACBCF940h, 032D86CE3h, 045DF5C75h, 0DCD60DCFh, 0ABD13D59h
    DWORD 026D930ACh, 051DE003Ah, 0C8D75180h, 0BFD06116h, 021B4F4B5h, 056B3C423h, 0CFBA9599h, 0B8BDA50Fh
    DWORD 02802B89Eh, 05F058808h, 0C60CD9B2h, 0B10BE924h, 02F6F7C87h, 058684C11h, 0C1611DABh, 0B6662D3Dh
    DWORD 076DC4190h, 001DB7106h, 098D220BCh, 0EFD5102Ah, 071B18589h, 006B6B51Fh, 09FBFE4A5h, 0E8B8D433h
    DWORD 07807C9A2h, 00F00F934h, 09609A88Eh, 0E10E9818h, 07F6A0DBBh, 0086D3D2Dh, 091646C97h, 0E6635C01h
    DWORD 06B6B51F4h, 01C6C6162h, 0856530D8h, 0F262004Eh, 06C0695EDh, 01B01A57Bh, 08208F4C1h, 0F50FC457h
    DWORD 065B0D9C6h, 012B7E950h, 08BBEB8EAh, 0FCB9887Ch, 062DD1DDFh, 015DA2D49h, 08CD37CF3h, 0FBD44C65h
    DWORD 04DB26158h, 03AB551CEh, 0A3BC0074h, 0D4BB30E2h, 04ADFA541h, 03DD895D7h, 0A4D1C46Dh, 0D3D6F4FBh
    DWORD 04369E96Ah, 0346ED9FCh, 0AD678846h, 0DA60B8D0h, 044042D73h, 033031DE5h, 0AA0A4C5Fh, 0DD0D7CC9h
    DWORD 05005713Ch, 0270241AAh, 0BE0B1010h, 0C90C2086h, 05768B525h, 0206F85B3h, 0B966D409h, 0CE61E49Fh
    DWORD 05EDEF90Eh, 029D9C998h, 0B0D09822h, 0C7D7A8B4h, 059B33D17h, 02EB40D81h, 0B7BD5C3Bh, 0C0BA6CADh
    DWORD 0EDB88320h, 09ABFB3B6h, 003B6E20Ch, 074B1D29Ah, 0EAD54739h, 09DD277AFh, 004DB2615h, 073DC1683h
    DWORD 0E3630B12h, 094643B84h, 00D6D6A3Eh, 07A6A5AA8h, 0E40ECF0Bh, 09309FF9Dh, 00A00AE27h, 07D079EB1h
    DWORD 0F00F9344h, 08708A3D2h, 01E01F268h, 06906C2FEh, 0F762575Dh, 0806567CBh, 0196C3671h, 06E6B06E7h
    DWORD 0FED41B76h, 089D32BE0h, 010DA7A5Ah, 067DD4ACCh, 0F9B9DF6Fh, 08EBEEFF9h, 017B7BE43h, 060B08ED5h
    DWORD 0D6D6A3E8h, 0A1D1937Eh, 038D8C2C4h, 04FDFF252h, 0D1BB67F1h, 0A6BC5767h, 03FB506DDh, 048B2364Bh
    DWORD 0D80D2BDAh, 0AF0A1B4Ch, 036034AF6h, 041047A60h, 0DF60EFC3h, 0A867DF55h, 0316E8EEFh, 04669BE79h
    DWORD 0CB61B38Ch, 0BC66831Ah, 0256FD2A0h, 05268E236h, 0CC0C7795h, 0BB0B4703h, 0220216B9h, 05505262Fh
    DWORD 0C5BA3BBEh, 0B2BD0B28h, 02BB45A92h, 05CB36A04h, 0C2D7FFA7h, 0B5D0CF31h, 02CD99E8Bh, 05BDEAE1Dh
    DWORD 09B64C2B0h, 0EC63F226h, 0756AA39Ch, 0026D930Ah, 09C0906A9h, 0EB0E363Fh, 072076785h, 005005713h
    DWORD 095BF4A82h, 0E2B87A14h, 07BB12BAEh, 00CB61B38h, 092D28E9Bh, 0E5D5BE0Dh, 07CDCEFB7h, 00BDBDF21h
    DWORD 086D3D2D4h, 0F1D4E242h, 068DDB3F8h, 01FDA836Eh, 081BE16CDh, 0F6B9265Bh, 06FB077E1h, 018B74777h
    DWORD 088085AE6h, 0FF0F6A70h, 066063BCAh, 011010B5Ch, 08F659EFFh, 0F862AE69h, 0616BFFD3h, 0166CCF45h
    DWORD 0A00AE278h, 0D70DD2EEh, 04E048354h, 03903B3C2h, 0A7672661h, 0D06016F7h, 04969474Dh, 03E6E77DBh
    DWORD 0AED16A4Ah, 0D9D65ADCh, 040DF0B66h, 037D83BF0h, 0A9BCAE53h, 0DEBB9EC5h, 047B2CF7Fh, 030B5FFE9h
    DWORD 0BDBDF21Ch, 0CABAC28Ah, 053B39330h, 024B4A3A6h, 0BAD03605h, 0CDD70693h, 054DE5729h, 023D967BFh
    DWORD 0B3667A2Eh, 0C4614AB8h, 05D681B02h, 02A6F2B94h, 0B40BBE37h, 0C30C8EA1h, 05A05DF1Bh, 02D02EF8Dh

.code
deflate_brutal_masm PROC FRAME
    ; Windows x64 ABI: RCX=src, RDX=len, R8=out_len.
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    sub     rsp, 96
    .allocstack 96
    .endprolog

    mov     rsi, rcx
    mov     rbx, rdx
    mov     r14, r8
    test    r14, r14
    jz      _fail
    mov     qword ptr [r14], 0
    test    rbx, rbx
    jz      _source_ok
    test    rsi, rsi
    jz      _fail
_source_ok:
    mov     r13, rsi             ; preserve original source for CRC32

    ; block_count = max(1, ceil(len / 65535)), without len+65534 overflow.
    test    rbx, rbx
    jz      _one_empty_block
    mov     rax, rbx
    xor     rdx, rdx
    mov     rcx, 65535
    div     rcx
    test    rdx, rdx
    jz      _block_count_ready
    inc     rax
    jmp     _block_count_ready
_one_empty_block:
    mov     eax, 1
_block_count_ready:
    imul    rax, rax, 5
    add     rax, rbx
    jc      _fail
    add     rax, 18
    jc      _fail

    ; Allocate exactly header + stored blocks + gzip trailer.
    mov     rcx, rax
    ; 32-byte Windows x64 shadow space is included in the fixed 96-byte frame.
    call    malloc
    test    rax, rax
    jz      _fail

    mov     r15, rax
    mov     rdi, rax

    ; Gzip header: ID1, ID2, CM=DEFLATE, FLG=0, MTIME=0, XFL=0, OS=255.
    mov     dword ptr [rdi], 08B1Fh
    mov     byte ptr [rdi+2], 08h
    mov     byte ptr [rdi+3], 00h
    mov     dword ptr [rdi+4], 0
    mov     byte ptr [rdi+8], 0
    mov     byte ptr [rdi+9], 0FFh
    add     rdi, 10

    ; RFC 1951 stored blocks. Empty input still needs one final empty block.
    mov     r12, rbx
    cld
    test    r12, r12
    jz      _emit_empty_block
_block_loop:
    mov     rax, r12
    cmp     rax, 65535
    jbe     _chunk_ok
    mov     rax, 65535
_chunk_ok:
    mov     rcx, r12
    sub     rcx, rax
    test    rcx, rcx
    jnz     _not_final
    mov     byte ptr [rdi], 1
    jmp     _header_done
_not_final:
    mov     byte ptr [rdi], 0
_header_done:
    inc     rdi
    mov     cx, ax
    mov     word ptr [rdi], cx
    not     cx
    mov     word ptr [rdi+2], cx
    add     rdi, 4
    mov     rcx, rax
    rep     movsb
    sub     r12, rax
    jnz     _block_loop
    jmp     _crc32
_emit_empty_block:
    mov     byte ptr [rdi], 1
    mov     word ptr [rdi+1], 0
    mov     word ptr [rdi+3], 0FFFFh
    add     rdi, 5

    ; CRC-32/ISO-HDLC (poly 0xEDB88320), over the original uncompressed bytes.
_crc32:
    mov     eax, 0FFFFFFFFh
    mov     rsi, r13
    mov     rcx, rbx
    lea     r10, crc32_table
_crc32_byte:
    test    rcx, rcx
    jz      _crc32_done
    movzx   edx, byte ptr [rsi]
    xor     edx, eax
    and     edx, 0FFh
    shr     eax, 8
    xor     eax, dword ptr [r10+rdx*4]
    inc     rsi
    dec     rcx
    jmp     _crc32_byte
_crc32_done:
    not     eax
    mov     dword ptr [rdi], eax
    add     rdi, 4
    mov     eax, ebx
    mov     dword ptr [rdi], eax
    add     rdi, 4

    mov     rax, rdi
    sub     rax, r15
    mov     qword ptr [r14], rax
    mov     rax, r15
    jmp     _exit

_fail:
    xor     eax, eax
_exit:
    add     rsp, 96
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
deflate_brutal_masm ENDP
END
