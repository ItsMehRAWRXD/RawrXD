; P1PRA UTC witness macros — included by RawrXD_Telemetry_Kernel.asm (P1PRA builds only).
IFNDEF P1PRA_UTC_WITNESS_INC
P1PRA_UTC_WITNESS_INC EQU 1

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY

EXTERNDEF P1PRA_UtcEnter:PROC
EXTERNDEF P1PRA_UtcExit:PROC
EXTERNDEF P1PRA_UtcEntry:PROC
EXTERNDEF P1PRA_UtcReturn:PROC
EXTERNDEF P1PRA_UtcCfSnapAll:PROC
EXTERNDEF P1PRA_UtcCfStackLayoutSnap:PROC
EXTERNDEF P1PRA_UtcHandleSnap:PROC
EXTERNDEF P1PRA_UtcLastErrorSnap:PROC
EXTERNDEF P1PRA_UtcRspSnapLight:PROC
EXTERNDEF P1PRA_UtcAlignmentFault:PROC
EXTERNDEF P1PRA_UtcShadowSnapLight:PROC

P1PRA_UtcEnterPathResolve     equ 1
P1PRA_UtcEnterCreateFile      equ 2
P1PRA_UtcEnterStatePub        equ 3
P1PRA_UtcEnterCounterReset    equ 4
P1PRA_UtcEnterInitBanner      equ 5
P1PRA_UtcEnterReturnSuccess   equ 6
P1PRA_UtcEnterReturnError     equ 7
P1PRA_UtcLogSlotReserve       equ 8
P1PRA_UtcLogTimestamp         equ 9
P1PRA_UtcLogMessageCopy       equ 10
P1PRA_UtcLogNewline           equ 11
P1PRA_UtcCfShadow             equ 12
P1PRA_UtcCfArgPath            equ 13
P1PRA_UtcCfArgAccess          equ 14
P1PRA_UtcCfArgShare           equ 15
P1PRA_UtcCfArgSecurity        equ 16
P1PRA_UtcCfStackParams        equ 17
P1PRA_UtcCfCall               equ 18
P1PRA_UtcCfPostcall           equ 19
P1PRA_UtcExportShutdown       equ 20
P1PRA_UtcExportFlush          equ 21
P1PRA_UtcExportGetMetricBase  equ 22
P1PRA_UtcExportGetBufferStats equ 23
P1PRA_UtcExportLogEvent       equ 24
P1PRA_UtcExportInc            equ 25
P1PRA_UtcExportDec            equ 26
P1PRA_UtcExportRead           equ 27
P1PRA_UtcExportReset          equ 28
P1PRA_UtcTsGetFileTime        equ 29
P1PRA_UtcTsSystemTime         equ 30
P1PRA_UtcTsFormat             equ 31
P1PRA_UtcCfSnapPath           equ 32
P1PRA_UtcCfSnapPathChars      equ 33
P1PRA_UtcCfSnapAccess         equ 34
P1PRA_UtcCfSnapShare          equ 35
P1PRA_UtcCfSnapSecurity       equ 36
P1PRA_UtcCfSnapDisp           equ 37
P1PRA_UtcCfSnapAttrs          equ 38
P1PRA_UtcCfSnapTemplate       equ 39
P1PRA_UtcCfSnapRsp            equ 40
P1PRA_UtcFlushInitGate        equ 41
P1PRA_UtcFlushLoopCompare     equ 42
P1PRA_UtcFlushStrlenSlot      equ 43
P1PRA_UtcFlushWriteFile       equ 44
P1PRA_UtcFlushAdvanceTail     equ 45
P1PRA_UtcFlushOsBuffers       equ 46
P1PRA_UtcCfStackLayout        equ 47
P1PRA_UtcCfResultHandle       equ 48
P1PRA_UtcCfHandleCompare      equ 49
P1PRA_UtcCfHandleSuccess      equ 50
P1PRA_UtcCfLastErrorSnap      equ 51
P1PRA_UtcShutdownFlushCall    equ 52
P1PRA_UtcShutdownHandleLoad   equ 53
P1PRA_UtcShutdownHandleGate   equ 54
P1PRA_UtcShutdownCloseCall    equ 55
P1PRA_UtcShutdownStateClear   equ 56
P1PRA_UtcLogSlotAddrCalc      equ 57
P1PRA_UtcLogCopyBounds        equ 58
P1PRA_UtcLogCopyLoopEnter     equ 59
P1PRA_UtcLogCopyLoopDone      equ 60
P1PRA_UtcLogTsInternalCall    equ 61
P1PRA_UtcCfShadowRspPre       equ 62
P1PRA_UtcCfShadowSub56        equ 63
P1PRA_UtcStatePubStoreHandle  equ 64
P1PRA_UtcStatePubSetInit      equ 65
P1PRA_UtcCounterResetMetrics  equ 66
P1PRA_UtcCounterResetRingIdx  equ 67
P1PRA_UtcInitBannerLeaMsg     equ 68
P1PRA_UtcInitBannerLogEvent   equ 69
P1PRA_UtcReturnSuccessZero    equ 70
P1PRA_UtcReturnErrorEnter     equ 71
P1PRA_UtcKernelReturn         equ 72
P1PRA_UtcFlushCounterInc      equ 73
P1PRA_UtcFlushWriteShadow     equ 74
P1PRA_UtcTsAscii2Hour         equ 75
P1PRA_UtcTsAscii2Minute       equ 76
P1PRA_UtcLogTsRspPre          equ 77
P1PRA_UtcLogTsArgs            equ 78
P1PRA_UtcLogTsPost            equ 79
P1PRA_UtcTsGetSystemTime      equ 80
P1PRA_UtcTsTimeToFields       equ 81
P1PRA_UtcTsAscii2Year         equ 82
P1PRA_UtcTsAscii2Month        equ 83
P1PRA_UtcTsAscii2Day          equ 84
P1PRA_UtcTsAscii2Sec          equ 85
P1PRA_UtcTsAscii2Msec         equ 86
P1PRA_UtcLogSlotAddrCalc87    equ 87
P1PRA_UtcLogCopyTsString      equ 88
P1PRA_UtcLogCopyPayloadLoop   equ 89
P1PRA_UtcLogAppendNewline     equ 90
P1PRA_UtcLogCommitSlot        equ 91
P1PRA_UtcLogTsAlignTrap       equ 92
P1PRA_UtcLogTsRspSnapLight    equ 93
P1PRA_UtcLogTsShadowChk       equ 94

P1PRA_UtcWitnessEnter MACRO stageLabel, stageId
    sub  rsp, 28h
    lea  rcx, stageLabel
    mov  edx, stageId
    call P1PRA_UtcEnter
    add  rsp, 28h
endm

P1PRA_UtcWitnessExit MACRO stageLabel
    sub  rsp, 28h
    lea  rcx, stageLabel
    call P1PRA_UtcExit
    add  rsp, 28h
endm

P1PRA_UtcWitnessEnterFlat MACRO stageLabel, stageId
    sub  rsp, 20h
    lea  rcx, stageLabel
    mov  edx, stageId
    call P1PRA_UtcEnter
    add  rsp, 20h
endm

P1PRA_UtcWitnessExitFlat MACRO stageLabel
    sub  rsp, 20h
    lea  rcx, stageLabel
    call P1PRA_UtcExit
    add  rsp, 20h
endm

P1PRA_UtcWitnessEntry MACRO fnLabel, stackPtr, retAddr
    sub  rsp, 28h
    lea  rcx, fnLabel
    mov  rdx, stackPtr
    mov  r8, retAddr
    call P1PRA_UtcEntry
    add  rsp, 28h
endm

P1PRA_UtcWitnessReturn MACRO stackPtr, retAddr
    sub  rsp, 28h
    mov  rcx, stackPtr
    mov  rdx, retAddr
    call P1PRA_UtcReturn
    add  rsp, 28h
endm

ENDIF ; RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
ENDIF ; P1PRA_UTC_WITNESS_INC
