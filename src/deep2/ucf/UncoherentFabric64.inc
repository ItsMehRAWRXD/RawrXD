; UncoherentFabric64.inc — logical tensor fabric over discrete domains
; NO CRT / NO CUDA / NO Vulkan / NO WinAPI imports.
IFNDEF UNCOHERENT_FABRIC64_INC
UNCOHERENT_FABRIC64_INC EQU 1

UF_OK                EQU 0
UF_ERR_PARAM         EQU 1
UF_ERR_FULL          EQU 2
UF_ERR_NOTFOUND      EQU 3
UF_ERR_STALE         EQU 4
UF_ERR_LEASE         EQU 5
UF_ERR_BUSY          EQU 6
UF_ERR_NO_SOURCE     EQU 7
UF_ERR_ALLOC         EQU 8
UF_ERR_COPY          EQU 9
UF_ERR_LAST_CURRENT  EQU 10
UF_ERR_NO_CB         EQU 11
UF_E_AMPLITUDE       EQU 12
UF_ERR_PARK_CURRENT  EQU 13

UF_MAX_DOMAIN        EQU 4
UF_MAX_TENSOR        EQU 512

UF_DOM_HOST          EQU 0
UF_DOM_GPU0          EQU 1
UF_DOM_GPU1          EQU 2
UF_DOM_NVME          EQU 3

; DomainDesc: capacity, used, opaque, flags (32 bytes)
UF_DOM_CAPACITY      EQU 0
UF_DOM_USED          EQU 8
UF_DOM_OPAQUE        EQU 16
UF_DOM_FLAGS         EQU 24
UF_DOM_SIZE          EQU 32

; TensorRec
UF_TEN_ID            EQU 0
UF_TEN_BYTES         EQU 8
UF_TEN_LATEST        EQU 16
UF_TEN_RES_CUR       EQU 24
UF_TEN_OWN_BUSY      EQU 32
UF_TEN_GEN0          EQU 40
UF_TEN_LEASE0        EQU 72
UF_TEN_HANDLE0       EQU 88
UF_TEN_SIZE          EQU 120

; BounceChain state
UFB_TID              EQU 0
UFB_LANEA            EQU 8
UFB_LANEB            EQU 16
UFB_CURRENT          EQU 24
UFB_NEXT             EQU 32
UFB_EXPECT           EQU 40
UFB_MAX_HOP_BYTES    EQU 48
UFB_OUT_HANDLE       EQU 56
UFB_FLAGS            EQU 64
UFB_SIZE             EQU 72
UFB_FLAG_LEASED      EQU 1

ENDIF
