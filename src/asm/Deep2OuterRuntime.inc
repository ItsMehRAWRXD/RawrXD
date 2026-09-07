; Deep2OuterRuntime.inc — outer shard/env/header probe (x64, kernel32 only)
OPTION CASEMAP:NONE

OUT_KIND_K2                 EQU 1
OUT_KIND_DEEPSEEK           EQU 2
OUT_EXPECT_K2               EQU 13
OUT_EXPECT_DS               EQU 11

OUT_F_PATH                  EQU 00000001h
OUT_F_DIR                   EQU 00000002h
OUT_F_COMPLETE              EQU 00000004h
OUT_F_NO_DUP                EQU 00000008h
OUT_F_NO_MISS               EQU 00000010h
OUT_F_HDR_OK                EQU 00000020h
OUT_F_ALL                   EQU 0000003Fh

OUT_E_OPEN_ENTERED          EQU 00000001h
OUT_E_OPEN_HANDLE           EQU 00000002h
OUT_E_GEN_ENTERED           EQU 00000004h
OUT_E_GEN_OK                EQU 00000008h
OUT_E_CLOSE_ENTERED         EQU 00000010h
OUT_E_ALL                   EQU 0000001Fh

GGUF_MAGIC_LE               EQU 46554747h
GGUF_VER_MIN                EQU 2
GGUF_VER_MAX                EQU 3

OS_FOUND                    EQU 0
OS_PARSED_TOTAL             EQU 4
OS_EXPECTED                 EQU 8
OS_DUP                      EQU 12
OS_MISS                     EQU 16
OS_HDR_FAIL                 EQU 20
OS_BAD_IDX                  EQU 24
OS_PRESENT                  EQU 28
OS_PRESENT_BYTES            EQU 32
OS_SIZE                     EQU 60

OH_FLAGS                    EQU 0
OH_SHARDS                   EQU 4
OH_EXPECTED                 EQU 8
OH_ENG_FLAGS                EQU 12
OH_QPC                      EQU 16
OH_QPC_T0                   EQU 24
OH_QPC_OPEN                 EQU 32
OH_QPC_FIRST                EQU 40
OH_QPC_END                  EQU 48
OH_SIZE                     EQU 56

OE_OPEN                     EQU 0
OE_GENERATE                 EQU 8
OE_CLOSE                    EQU 16
OE_SIZE                     EQU 24

FILE_ATTRIBUTE_DIRECTORY    EQU 10h
INVALID_FILE_ATTRIBUTES     EQU 0FFFFFFFFh
GENERIC_READ                EQU 80000000h
FILE_SHARE_READ             EQU 1
OPEN_EXISTING               EQU 3
FILE_ATTRIBUTE_NORMAL       EQU 80h
INVALID_HANDLE_VALUE        EQU 0FFFFFFFFFFFFFFFFh
STD_OUTPUT_HANDLE           EQU 0FFFFFFF5h
CREATE_ALWAYS               EQU 2
GENERIC_WRITE               EQU 40000000h

WIN32_FIND_NAME             EQU 44
MAX_PATH_A                  EQU 260
