;============================================================================
; nano_format.inc - RawrXD .nano Container Format Definition
; Binary layout for compressed model storage
;============================================================================

;----------------------------------------------------------------------------
; Header Constants
;----------------------------------------------------------------------------
NANO_MAGIC          equ 0x52415752      ; "RAWR" in ASCII
NANO_VERSION        equ 0x00010000      ; Version 1.0

; Codec Types
NANO_CODEC_RAW      equ 0               ; FP16 (no compression)
NANO_CODEC_Q8       equ 1               ; 8-bit quantization
NANO_CODEC_Q4       equ 2               ; 4-bit quantization
NANO_CODEC_Q2       equ 3               ; 2-bit quantization (LUT-2)
NANO_CODEC_BINARY   equ 4               ; 0.5-bit binary/XNOR

;----------------------------------------------------------------------------
; File Header Structure (64 bytes, fixed offset)
;----------------------------------------------------------------------------
struc NANO_HEADER
    .magic          resd 1              ; 0x00: "RAWR"
    .version        resd 1              ; 0x04: Version
    .tensor_count   resq 1              ; 0x08: Number of tensors
    .codebook_offset resq 1            ; 0x10: Offset to codebook section
    .tensor_dir_offset resq 1           ; 0x18: Offset to tensor directory
    .data_offset    resq 1              ; 0x20: Offset to packed data
    .metadata_size  resq 1              ; 0x28: Size of metadata section
    .flags          resd 1              ; 0x30: Format flags
    .reserved       resd 1              ; 0x34: Padding
    .checksum       resq 1              ; 0x38: CRC64 checksum
endstruc

;----------------------------------------------------------------------------
; Tensor Directory Entry (64 bytes each)
;----------------------------------------------------------------------------
struc NANO_TENSOR_ENTRY
    .name           resb 32             ; 0x00: Tensor name (null-terminated)
    .shape          resd 4              ; 0x20: Dimensions [N,C,H,W]
    .codec_type     resd 1              ; 0x30: Compression codec
    .data_offset    resq 1              ; 0x38: Offset to packed data
    .data_size      resq 1              ; 0x40: Size of packed data
    .codebook_id    resd 1              ; 0x48: Codebook index (-1 = none)
    .importance     resd 1              ; 0x4C: Importance score (0-255)
    .residual_offset resq 1             ; 0x50: Offset to residuals
    .residual_size  resq 1              ; 0x58: Size of residuals
endstruc

;----------------------------------------------------------------------------
; Codebook Header (32 bytes)
;----------------------------------------------------------------------------
struc NANO_CODEBOOK_HEADER
    .entry_count    resd 1              ; Number of entries
    .entry_size     resd 1              ; Bytes per entry (4 for FP32)
    .data_offset    resq 1              ; Offset to codebook data
    .data_size      resq 1              ; Total size
endstruc

;----------------------------------------------------------------------------
; Size Constants
;----------------------------------------------------------------------------
NANO_HEADER_SIZE        equ 64
NANO_TENSOR_ENTRY_SIZE  equ 64
NANO_CODEBOOK_HDR_SIZE  equ 32

;----------------------------------------------------------------------------
; Alignment
;----------------------------------------------------------------------------
NANO_ALIGN              equ 64          ; 64-byte alignment for AVX-512

;============================================================================
; End of nano_format.inc
;============================================================================
