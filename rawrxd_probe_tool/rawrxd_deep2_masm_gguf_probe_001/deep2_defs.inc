option casemap:none

; ---------- Win32 ----------
GENERIC_READ                equ 80000000h
GENERIC_WRITE               equ 40000000h
FILE_SHARE_READ             equ 00000001h
OPEN_EXISTING               equ 3
CREATE_ALWAYS               equ 2
FILE_ATTRIBUTE_NORMAL       equ 00000080h
PAGE_READONLY               equ 02h
FILE_MAP_READ               equ 0004h
STD_OUTPUT_HANDLE           equ -11
INVALID_HANDLE_VALUE        equ -1

; ---------- GGUF ----------
GGUF_MAGIC                  equ 46554747h ; "GGUF" little-endian
GGUF_TYPE_UINT8             equ 0
GGUF_TYPE_INT8              equ 1
GGUF_TYPE_UINT16            equ 2
GGUF_TYPE_INT16             equ 3
GGUF_TYPE_UINT32            equ 4
GGUF_TYPE_INT32             equ 5
GGUF_TYPE_FLOAT32           equ 6
GGUF_TYPE_BOOL              equ 7
GGUF_TYPE_STRING            equ 8
GGUF_TYPE_ARRAY             equ 9
GGUF_TYPE_UINT64            equ 10
GGUF_TYPE_INT64             equ 11
GGUF_TYPE_FLOAT64           equ 12

DEFAULT_GGUF_ALIGNMENT      equ 32
MAX_TENSORS                 equ 16384
MAX_METADATA                equ 65536
MAX_TRACE                   equ 131072
MAX_DIMS_CAPTURED           equ 4

; ---------- trace / non-time stamps ----------
TRACE_KIND_OBSERVE          equ 1
TRACE_KIND_ATTRIBUTE        equ 2
TRACE_KIND_VERIFY           equ 3
TRACE_KIND_CLASSIFY         equ 4
TRACE_KIND_FORMAT           equ 5
TRACE_KIND_STAMP            equ 6
TRACE_KIND_ERROR            equ 7

CLASS_UNKNOWN               equ 0
CLASS_HARD                  equ 1
CLASS_CONDITIONAL           equ 2
CLASS_PERFORMANCE           equ 3
CLASS_COLD                  equ 4
CLASS_DEAD                  equ 5
CLASS_DECLARED              equ 6
CLASS_PROVEN                equ 7

OP_FILE_OPEN                equ 0001h
OP_FILE_MAP                 equ 0002h
OP_GGUF_HEADER              equ 0010h
OP_METADATA_KEY             equ 0020h
OP_METADATA_VALUE           equ 0021h
OP_TENSOR_INFO              equ 0030h
OP_TENSOR_DATA              equ 0031h
OP_QUANT_CLASS              equ 0040h
OP_ARCH_CLASS               equ 0041h
OP_VERIFY_BOUNDS            equ 0050h
OP_VERIFY_LAYOUT            equ 0051h
OP_EMIT_MODEL_HEADER        equ 0060h
OP_EMIT_TENSOR_HEADER       equ 0061h
OP_EMIT_QUANT_HEADER        equ 0062h
OP_EMIT_SYSTEM_HEADER       equ 0063h
OP_EMIT_STAMP_HEADER        equ 0064h
OP_EMIT_RXI                 equ 0065h
OP_EMIT_TRACE               equ 0066h
OP_COMPLETE                 equ 00FFh

; ---------- system-use bitset ----------
SYS_USE_FILE_IO             equ 00000001h
SYS_USE_FILE_MAPPING        equ 00000002h
SYS_USE_OUTPUT_FILES        equ 00000004h
SYS_USE_STATIC_ARENAS       equ 00000008h
SYS_USE_NETWORK             equ 00000010h
SYS_USE_HEAP                equ 00000020h
SYS_USE_CRT                 equ 00000040h
SYS_USE_GPU                 equ 00000080h

; ---------- structs ----------
TRACE_REC STRUCT
    Seq                     QWORD ?
    ParentSeq               QWORD ?
    Kind                    DWORD ?
    Op                      DWORD ?
    ObjectId                QWORD ?
    InputGen                QWORD ?
    OutputGen               QWORD ?
    A                       QWORD ?
    B                       QWORD ?
    Flags                   DWORD ?
    ClassId                 DWORD ?
TRACE_REC ENDS

; Persistent / relocation-safe tensor record. No process pointers.
TENSOR_REC STRUCT
    NameHash                QWORD ?
    RelativeOffset          QWORD ?
    AbsoluteOffset          QWORD ?
    StorageSpan             QWORD ?
    Dim0                    QWORD ?
    Dim1                    QWORD ?
    Dim2                    QWORD ?
    Dim3                    QWORD ?
    TypeId                  DWORD ?
    NDims                   DWORD ?
TENSOR_REC ENDS

RXI_HEADER STRUCT
    Magic                   DWORD ? ; "RXI1"
    Version                 DWORD ?
    GGUFVersion             DWORD ?
    Flags                   DWORD ?
    ModelFileBytes          QWORD ?
    TensorCount             QWORD ?
    MetadataCount           QWORD ?
    Alignment               QWORD ?
    TensorDataStart         QWORD ?
    QuantMaskLo             QWORD ?
    QuantMaskHi             QWORD ?
    ArchHash                QWORD ?
    TensorRecBytes          DWORD ?
    TraceRecBytes           DWORD ?
    Reserved0               QWORD ?
    Reserved1               QWORD ?
RXI_HEADER ENDS
