; ============================================================================
; ReverseStream.inc — NanQuant Reverse Streamer ABI Definitions
; ============================================================================
; MASM64 include for ml64.exe. No .MODEL directive — ml64 is flat by default.
; Use with:  include ReverseStream.inc
;
; This defines the exact footer layout and the C-callable ABI surface.
; Every size here is frozen; changing it breaks the on-disk stream format.
; ============================================================================

OPTION CASEMAP:NONE

; ----------------------------------------------------------------------------
; Magic constant: 'NQSR' = NanQuant Stream Reverse
; ----------------------------------------------------------------------------
NANQUANT_MAGIC        EQU 04E515352h
NANQUANT_FOOTER_SIZE  EQU 36          ; sizeof(NanQuantFooter)

; ----------------------------------------------------------------------------
; Footer layout (36 bytes, appended to end of each tensor block)
; ----------------------------------------------------------------------------
; Offset  Size  Field
;   0      4    Magic          DWORD  NQSR
;   4      4    QuantType      DWORD  GGML type enum value
;   8      4    ScaleMin       REAL4  global floor (prevents NaN dispatch)
;  12      4    ScaleMax       REAL4  global ceiling
;  16      8    Rows           QWORD  output dimension
;  24      8    Cols           QWORD  input dimension
;  32      4    (padding to 36 bytes for 8-byte alignment)
; ----------------------------------------------------------------------------

; Offsets into NanQuantFooter (stack / memory layout)
FOOTER_OFS_MAGIC      EQU 0
FOOTER_OFS_QUANTTYPE  EQU 4
FOOTER_OFS_SCALEMIN   EQU 8
FOOTER_OFS_SCALEMAX   EQU 12
FOOTER_OFS_ROWS       EQU 16
FOOTER_OFS_COLS       EQU 24

; Error codes returned by ReverseStream_MapTensorBack
REVSTREAM_OK          EQU 1
REVSTREAM_ERR_MAGIC   EQU 0
REVSTREAM_ERR_READ    EQU -1
REVSTREAM_ERR_OFFSET  EQU -2

; Handle value for uninitialised streamer
INVALID_HANDLE_VALUE  EQU -1
