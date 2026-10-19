; g3_masm_vk_data.asm — shared VK solo state
OPTION CASEMAP:NONE
PUBLIC gInst, pdev, dev, pdN, pds, props, memP, qci, devCI, prio
PUBLIC szGate, szMode, szCI, szA0, szOk, szBad, szVram, szName, szMiss, needle

.data
szGate BYTE "GATE=G3_GPU1_MASM_SOLO_A0_001",0
szMode BYTE "MODE=solo_masm_vulkan_iat",0
szCI   BYTE "VK_CREATE_INSTANCE=",0
szA0   BYTE "SOLO_A0_VK_RESULT=",0
szOk   BYTE "SOLO_A0_CREATE=PASS",0
szBad  BYTE "SOLO_A0_CREATE=FAIL",0
szVram BYTE "SOLO_VK_DEVICE_LOCAL_HEAP=",0
szName BYTE "SOLO_NAME=",0
szMiss BYTE "SOLO_TARGET_MISSING=1",0
needle BYTE "7800",0
prio   DWORD 3F800000h
align 8
gInst  QWORD 0
pdev   QWORD 0
dev    QWORD 0
pdN    DWORD 0
pds    QWORD 16 DUP(0)
props  BYTE 1024 DUP(0)
memP   BYTE 1024 DUP(0)
qci    BYTE 40 DUP(0)
devCI  BYTE 72 DUP(0)
END
