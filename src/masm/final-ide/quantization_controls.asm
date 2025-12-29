; ============================================================================
; RawrXD Agentic IDE - Phase 7: Advanced Quantization Controls
; Batch 2 of 10 - Dynamic quantization engine with hardware-aware selection
; Integrates with Hardware Acceleration extension and Performance Dashboard
; ============================================================================

option casemap:none

include windows.inc
include kernel32.inc
include user32.inc
include advapi32.inc
include comctl32.inc

includelib kernel32.lib
includelib user32.lib
includelib advapi32.lib
includelib comctl32.lib

; ============================================================================
; EXTERNAL DECLARATIONS (Phase 4 extensions + Batch 1 dashboard)
; ============================================================================
EXTERN HardwareAccelerator_GetVRAMInfo:PROC
EXTERN HardwareAccelerator_GetComputeUnits:PROC
EXTERN HardwareAccelerator_SwitchQuantization:PROC
EXTERN HardwareAccelerator_GetCurrentQuantization:PROC

EXTERN PerformanceDashboard_GetCurrentStats:PROC
EXTERN PerformanceDashboard_NotifyConfigChange:PROC

EXTERN RegistryOpenKey:PROC
EXTERN RegistryCloseKey:PROC
EXTERN RegistrySetDWORD:PROC
EXTERN RegistryGetDWORD:PROC
EXTERN RegistrySetString:PROC
EXTERN RegistryGetString:PROC

EXTERN wsprintfA:PROC
EXTERN lstrlenA:PROC

; ============================================================================
; CONSTANTS & ENUMS
; ============================================================================
QUANT_Q2_K               EQU 0
QUANT_Q3_K               EQU 1
QUANT_Q4_0               EQU 2
QUANT_Q4_K               EQU 3
QUANT_Q5_0               EQU 4
QUANT_Q5_K               EQU 5
QUANT_Q6_K               EQU 6
QUANT_Q8_0               EQU 7
QUANT_F16                EQU 8
QUANT_F32                EQU 9
QUANT_COUNT              EQU 10

IDC_QUANT_TAB            EQU 3100
IDC_QUANT_COMBO          EQU 3101
IDC_VRAM_LABEL           EQU 3102
IDC_COMPUTE_UNITS_LABEL  EQU 3103
IDC_CURRENT_QUANT_LABEL  EQU 3104
IDC_APPLY_BUTTON         EQU 3105
IDC_AUTO_SELECT_CHECK    EQU 3106
IDC_VRAM_PROGRESS        EQU 3107
IDC_MODEL_SIZE_LABEL     EQU 3108

WM_PERF_CONFIG_CHANGE    EQU WM_USER + 210
PERF_CHANGE_QUANTIZATION EQU 1

VRAM_RESERVE_BYTES       EQU 536870912             ; 512MB reserve
GB_BYTES                 EQU 1073741824            ; 1GB in bytes

; ============================================================================
; STRUCTURES
; ============================================================================
VRAM_INFO STRUCT
	TotalBytes      QWORD ?
	AvailableBytes  QWORD ?
	ComputeUnits    DWORD ?
	padding         DWORD ?
VRAM_INFO ENDS

QUANTIZATION_STATE STRUCT
	Version                 DWORD ?
	DefaultQuantization     DWORD ?
	AutoSelectEnabled       DWORD ?
	CurrentQuantization     DWORD ?
	AvailableQuantMask      DWORD ?
	LastAppliedQuant        DWORD ?
	TotalVRAM               QWORD ?
	AvailableVRAM           QWORD ?
	ComputeUnits            DWORD ?
	padding0                DWORD ?
	ModelPath               BYTE 260 DUP(?)
	ModelQuantOverride      DWORD ?
	padding1                DWORD ?
QUANTIZATION_STATE ENDS

; ============================================================================
; DATA
; ============================================================================
.DATA
regPath_RawrXD_Quantization    DB "Software\\RawrXD\\Quantization",0
regKey_DefaultQuantization     DB "DefaultQuantization",0
regKey_AutoSelectEnabled       DB "AutoSelectEnabled",0
regKey_LastAppliedQuant        DB "LastAppliedQuantization",0
regKey_ModelProfile_Prefix     DB "ModelProfile_",0

str_VRAM_Format                DB "%I64u GB / %I64u GB Free",0
str_ModelProfileKey            DB "ModelProfile_%08X",0

quantStrings   DQ OFFSET str_Q2K, OFFSET str_Q3K, OFFSET str_Q40, OFFSET str_Q4K,
					OFFSET str_Q50, OFFSET str_Q5K, OFFSET str_Q6K, OFFSET str_Q80,
					OFFSET str_F16, OFFSET str_F32

str_Q2K        DB "Q2_K - Ultra Low (2-bit, 0.7GB/1B)",0
str_Q3K        DB "Q3_K - Very Low (3-bit, 1.0GB/1B)",0
str_Q40        DB "Q4_0 - Low (4-bit, 1.3GB/1B)",0
str_Q4K        DB "Q4_K - Balanced (4-bit, 1.5GB/1B)",0
str_Q50        DB "Q5_0 - Medium (5-bit, 1.6GB/1B)",0
str_Q5K        DB "Q5_K - High (5-bit, 1.8GB/1B)",0
str_Q6K        DB "Q6_K - Very High (6-bit, 2.1GB/1B)",0
str_Q80        DB "Q8_0 - Ultra High (8-bit, 2.7GB/1B)",0
str_F16        DB "F16 - Near Full (16-bit, 4.1GB/1B)",0
str_F32        DB "F32 - Full Precision (32-bit, 8.2GB/1B)",0

quantSizeGBPerBillion REAL8 0.7, 1.0, 1.3, 1.5, 1.6, 1.8, 2.1, 2.7, 4.1, 8.2
quantSpeedFactors     REAL8 3.5, 3.2, 2.8, 2.6, 2.3, 2.1, 1.8, 1.3, 0.7, 1.0
real_120_percent      REAL8 1.2
inv_one_billion       REAL8 0.000000001

VRAM_THRESHOLD_4GB    DQ 4000000000
VRAM_THRESHOLD_8GB    DQ 8000000000
VRAM_THRESHOLD_12GB   DQ 12000000000
VRAM_THRESHOLD_16GB   DQ 16000000000
VRAM_THRESHOLD_24GB   DQ 24000000000

currentModelPath      DB 260 DUP(0)
currentModelSizeBytes DQ 0
currentModelParams    DQ 0
currentRecommendedQuant DD -1

vramTextBuffer        DB 128 DUP(0)

.DATA?
pQuantizationState        DQ ?
hQuantizationChangeEvent  DQ ?

; ============================================================================
; CODE
; ============================================================================
.CODE

PUBLIC QuantizationControls_Create
QuantizationControls_Create PROC FRAME USES rbx
	invoke GetProcessHeap
	test rax, rax
	jz qc_create_fail
	mov rbx, rax

	invoke HeapAlloc, rbx, HEAP_ZERO_MEMORY, SIZEOF QUANTIZATION_STATE
	test rax, rax
	jz qc_create_fail
	mov pQuantizationState, rax

	mov DWORD PTR [rax + QUANTIZATION_STATE.Version], 070002h
	mov DWORD PTR [rax + QUANTIZATION_STATE.DefaultQuantization], QUANT_Q4_K
	mov DWORD PTR [rax + QUANTIZATION_STATE.AutoSelectEnabled], 1
	mov DWORD PTR [rax + QUANTIZATION_STATE.AvailableQuantMask], 0FFFFFFFFh
	mov DWORD PTR [rax + QUANTIZATION_STATE.CurrentQuantization], QUANT_Q4_K
	mov DWORD PTR [rax + QUANTIZATION_STATE.LastAppliedQuant], -1

	invoke CreateEventA, NULL, FALSE, FALSE, NULL
	test rax, rax
	jz qc_create_cleanup
	mov hQuantizationChangeEvent, rax

	mov rcx, pQuantizationState
	call QuantizationControls_LoadSettings
	call QuantizationControls_RefreshHardwareInfo

	mov rax, pQuantizationState
	ret

qc_create_cleanup:
	mov rcx, pQuantizationState
	test rcx, rcx
	jz qc_create_fail
	invoke HeapFree, rbx, 0, rcx
	mov pQuantizationState, 0

qc_create_fail:
	xor rax, rax
	ret
QuantizationControls_Create ENDP

PUBLIC QuantizationControls_LoadSettings
QuantizationControls_LoadSettings PROC FRAME USES rbx rdi
	mov rbx, rcx
	test rbx, rbx
	jz qc_load_fail

	invoke RegistryOpenKey, HKEY_CURRENT_USER, ADDR regPath_RawrXD_Quantization, KEY_READ
	test rax, rax
	jz qc_load_fail
	mov rdi, rax

	invoke RegistryGetDWORD, rdi, ADDR regKey_DefaultQuantization, QUANT_Q4_K
	mov [rbx + QUANTIZATION_STATE.DefaultQuantization], eax

	invoke RegistryGetDWORD, rdi, ADDR regKey_AutoSelectEnabled, 1
	mov [rbx + QUANTIZATION_STATE.AutoSelectEnabled], eax

	invoke RegistryGetDWORD, rdi, ADDR regKey_LastAppliedQuant, -1
	mov [rbx + QUANTIZATION_STATE.LastAppliedQuant], eax

	invoke RegistryCloseKey, rdi
	mov rax, 1
	ret

qc_load_fail:
	xor rax, rax
	ret
QuantizationControls_LoadSettings ENDP

PUBLIC QuantizationControls_SaveSettings
QuantizationControls_SaveSettings PROC FRAME USES rbx rdi
	mov rbx, rcx
	test rbx, rbx
	jz qc_save_fail

	invoke RegistryOpenKey, HKEY_CURRENT_USER, ADDR regPath_RawrXD_Quantization, KEY_ALL_ACCESS
	test rax, rax
	jz qc_save_fail
	mov rdi, rax

	mov r8d, [rbx + QUANTIZATION_STATE.DefaultQuantization]
	invoke RegistrySetDWORD, rdi, ADDR regKey_DefaultQuantization, r8d

	mov r8d, [rbx + QUANTIZATION_STATE.AutoSelectEnabled]
	invoke RegistrySetDWORD, rdi, ADDR regKey_AutoSelectEnabled, r8d

	mov r8d, [rbx + QUANTIZATION_STATE.LastAppliedQuant]
	invoke RegistrySetDWORD, rdi, ADDR regKey_LastAppliedQuant, r8d

	invoke RegistryCloseKey, rdi
	mov rax, 1
	ret

qc_save_fail:
	xor rax, rax
	ret
QuantizationControls_SaveSettings ENDP

PUBLIC QuantizationControls_RefreshHardwareInfo
QuantizationControls_RefreshHardwareInfo PROC FRAME USES rbx
	LOCAL vinfo:VRAM_INFO

	test pQuantizationState, pQuantizationState
	jz qc_hwinfo_fail

	lea rcx, vinfo
	invoke HardwareAccelerator_GetVRAMInfo, rcx
	test rax, rax
	jz qc_hwinfo_default

	mov rbx, pQuantizationState
	mov rax, vinfo.TotalBytes
	mov [rbx + QUANTIZATION_STATE.TotalVRAM], rax
	mov rax, vinfo.AvailableBytes
	mov [rbx + QUANTIZATION_STATE.AvailableVRAM], rax
	mov eax, vinfo.ComputeUnits
	mov [rbx + QUANTIZATION_STATE.ComputeUnits], eax
	mov rax, 1
	ret

qc_hwinfo_default:
	mov rbx, pQuantizationState
	mov rax, 8000000000
	mov [rbx + QUANTIZATION_STATE.TotalVRAM], rax
	mov [rbx + QUANTIZATION_STATE.AvailableVRAM], rax
	mov DWORD PTR [rbx + QUANTIZATION_STATE.ComputeUnits], 0
	mov rax, 1
	ret

qc_hwinfo_fail:
	xor rax, rax
	ret
QuantizationControls_RefreshHardwareInfo ENDP

PUBLIC QuantizationControls_GetRecommendedQuantization
QuantizationControls_GetRecommendedQuantization PROC FRAME USES rbx rsi rdi
	LOCAL modelGB:REAL8

	mov rbx, rcx                        ; model size in bytes
	mov currentModelSizeBytes, rbx

	test pQuantizationState, pQuantizationState
	jz qc_rec_default

	mov rdi, pQuantizationState
	mov rax, [rdi + QUANTIZATION_STATE.AvailableVRAM]
	cmp rax, VRAM_RESERVE_BYTES
	jb qc_no_reserve
	sub rax, VRAM_RESERVE_BYTES
qc_no_reserve:
	mov rsi, rax                        ; available bytes after reserve

	cvtsi2sd xmm0, rbx                  ; model size (bytes) -> double
	movsd xmm1, inv_one_billion
	mulsd xmm0, xmm1                    ; approximate "GB-equivalent"
	movsd modelGB, xmm0

	xor ecx, ecx                        ; quant index
qc_rec_loop:
	cmp ecx, QUANT_COUNT
	jge qc_rec_lowest

	mov eax, ecx
	cdqe
	movsd xmm1, quantSizeGBPerBillion[rax*8]
	movsd xmm0, modelGB
	mulsd xmm0, xmm1                    ; base GB requirement
	movsd xmm2, real_120_percent
	mulsd xmm0, xmm2                    ; 20% overhead

	; available GB (bytes -> GB)
	mov rax, rsi
	cvtsi2sd xmm3, rax
	movsd xmm4, inv_one_billion
	mulsd xmm3, xmm4

	ucomisd xmm0, xmm3
	ja qc_next_quant

	mov eax, ecx
	mov currentRecommendedQuant, eax
	ret

qc_next_quant:
	inc ecx
	jmp qc_rec_loop

qc_rec_lowest:
	mov eax, QUANT_Q2_K
	mov currentRecommendedQuant, eax
	ret

qc_rec_default:
	mov eax, QUANT_Q4_K
	mov currentRecommendedQuant, eax
	ret
QuantizationControls_GetRecommendedQuantization ENDP

PUBLIC QuantizationControls_ApplyQuantization
QuantizationControls_ApplyQuantization PROC FRAME USES rbx
	mov ebx, ecx                        ; target quant type

	test pQuantizationState, pQuantizationState
	jz qc_apply_fail

	mov eax, [pQuantizationState + QUANTIZATION_STATE.AvailableQuantMask]
	bt eax, ebx
	jnc qc_apply_fail

	invoke HardwareAccelerator_GetCurrentQuantization
	cmp eax, ebx
	je qc_apply_success

	mov ecx, ebx
	invoke HardwareAccelerator_SwitchQuantization, rcx
	test rax, rax
	jz qc_apply_fail

	mov rax, pQuantizationState
	mov [rax + QUANTIZATION_STATE.CurrentQuantization], ebx
	mov [rax + QUANTIZATION_STATE.LastAppliedQuant], ebx
	invoke QuantizationControls_SaveSettings, rax

	invoke SetEvent, hQuantizationChangeEvent
	mov ecx, PERF_CHANGE_QUANTIZATION
	mov edx, ebx
	invoke PerformanceDashboard_NotifyConfigChange, rcx, rdx

qc_apply_success:
	mov rax, 1
	ret

qc_apply_fail:
	xor rax, rax
	ret
QuantizationControls_ApplyQuantization ENDP

PUBLIC QuantizationControls_PopulateComboBox
QuantizationControls_PopulateComboBox PROC FRAME USES rbx rsi rdi
	mov rbx, rcx
	test rbx, rbx
	jz qc_combo_done

	invoke SendMessage, rbx, CB_RESETCONTENT, 0, 0
	xor esi, esi

qc_combo_loop:
	cmp esi, QUANT_COUNT
	jge qc_combo_select

	mov eax, [pQuantizationState + QUANTIZATION_STATE.AvailableQuantMask]
	bt eax, esi
	jnc qc_combo_next

	mov rax, quantStrings[esi*8]
	invoke SendMessage, rbx, CB_ADDSTRING, 0, rax
	mov rdi, rax                      ; returned index
	invoke SendMessage, rbx, CB_SETITEMDATA, rdi, rsi

qc_combo_next:
	inc esi
	jmp qc_combo_loop

qc_combo_select:
	mov eax, [pQuantizationState + QUANTIZATION_STATE.CurrentQuantization]
	invoke SendMessage, rbx, CB_SETCURSEL, eax, 0

qc_combo_done:
	ret
QuantizationControls_PopulateComboBox ENDP

PUBLIC QuantizationControls_UpdateVRAMDisplay
QuantizationControls_UpdateVRAMDisplay PROC FRAME USES rbx rsi rdi
	mov rbx, rcx                      ; progress bar
	mov rsi, rdx                      ; label handle

	test pQuantizationState, pQuantizationState
	jz qc_vram_done

	mov rax, [pQuantizationState + QUANTIZATION_STATE.AvailableVRAM]
	mov rdi, [pQuantizationState + QUANTIZATION_STATE.TotalVRAM]
	test rdi, rdi
	jz qc_vram_done

	mov rcx, 100
	mul rcx                           ; rdx:rax = available * 100
	div rdi                           ; eax = percentage
	mov r8d, eax

	.IF rbx != 0
		invoke SendMessage, rbx, PBM_SETPOS, r8d, 0
	.ENDIF

	; Build label text: "%I64u GB / %I64u GB Free"
	mov rax, [pQuantizationState + QUANTIZATION_STATE.AvailableVRAM]
	xor rdx, rdx
	mov rcx, GB_BYTES
	div rcx
	mov r8, rax                       ; available GB

	mov rax, [pQuantizationState + QUANTIZATION_STATE.TotalVRAM]
	xor rdx, rdx
	mov rcx, GB_BYTES
	div rcx
	mov r9, rax                       ; total GB

	.IF rsi != 0
		invoke wsprintfA, ADDR vramTextBuffer, ADDR str_VRAM_Format, r8, r9
		invoke SetWindowTextA, rsi, ADDR vramTextBuffer
	.ENDIF

qc_vram_done:
	ret
QuantizationControls_UpdateVRAMDisplay ENDP

; ============================================================================
; INTERNAL HELPERS
; ============================================================================

QuantizationControls_HashString PROC FRAME USES rbx rsi
	mov rbx, rcx
	mov eax, 2166136261

qc_hash_loop:
	movzx esi, WORD PTR [rbx]
	test si, si
	jz qc_hash_done
	xor eax, esi
	imul eax, eax, 16777619
	add rbx, 2
	jmp qc_hash_loop

qc_hash_done:
	ret
QuantizationControls_HashString ENDP

QuantizationControls_GenerateModelKey PROC FRAME USES rbx rsi
	mov rsi, rdx                     ; output buffer
	invoke QuantizationControls_HashString, rcx
	mov r8d, eax
	invoke wsprintfA, rsi, ADDR str_ModelProfileKey, r8d
	ret
QuantizationControls_GenerateModelKey ENDP

; ============================================================================
; FNV-1a Hash Implementation for Model Path Hashing
; ============================================================================
PRIVATE HashString
HashString PROC FRAME USES rbx rsi
	; RCX = input string
	; Returns: EAX = 32-bit FNV-1a hash
	
	mov rsi, rcx
	test rsi, rsi
	jz hash_empty
	
	mov eax, 2166136261     ; FNV offset basis (32-bit)
	xor ecx, ecx
	
hash_loop:
	movzx ecx, BYTE PTR [rsi]
	test cl, cl
	jz hash_done
	
	xor eax, ecx
	imul eax, 16777619      ; FNV prime (32-bit)
	
	inc rsi
	jmp hash_loop
	
hash_empty:
	mov eax, 2166136261
hash_done:
	ret
HashString ENDP

PUBLIC QuantizationControls_GenerateModelKey
QuantizationControls_GenerateModelKey PROC FRAME USES rbx rsi rdi
	; RCX = model path (string)
	; RDX = destination buffer for key name (260 bytes)
	; Returns: RAX = length of key name
	
	mov rsi, rcx
	mov rdi, rdx
	test rsi, rsi
	jz qc_gen_key_fail
	
	mov rcx, rsi
	call HashString
	mov ebx, eax            ; hash in EBX
	
	; Format: "ModelProfile_XXXXXXXX" (FNV-1a hash as hex)
	lea rcx, str_ModelProfileKey
	mov rdx, rdi
	mov r8d, ebx
	invoke wsprintfA, rdx, rcx, r8d
	ret
	
qc_gen_key_fail:
	xor rax, rax
	ret
QuantizationControls_GenerateModelKey ENDP

PUBLIC QuantizationControls_LoadModelProfile
QuantizationControls_LoadModelProfile PROC FRAME USES rbx rsi rdi
	LOCAL profileKey[260]:BYTE

	test rcx, rcx
	jz qc_profile_none

	lea rdx, profileKey
	invoke QuantizationControls_GenerateModelKey, rcx, rdx

	invoke RegistryOpenKey, HKEY_CURRENT_USER, ADDR regPath_RawrXD_Quantization, KEY_READ
	test rax, rax
	jz qc_profile_none
	mov rdi, rax

	invoke RegistryGetDWORD, rdi, rdx, -1
	invoke RegistryCloseKey, rdi
	ret

qc_profile_none:
	mov eax, -1
	ret
QuantizationControls_LoadModelProfile ENDP

PUBLIC QuantizationControls_SaveModelProfile
QuantizationControls_SaveModelProfile PROC FRAME USES rbx rsi rdi
	LOCAL profileKey[260]:BYTE
	LOCAL overrideVal:DWORD

	test rcx, rcx
	jz qc_profile_save_fail

	mov overrideVal, edx

	lea rdx, profileKey
	invoke QuantizationControls_GenerateModelKey, rcx, rdx

	invoke RegistryOpenKey, HKEY_CURRENT_USER, ADDR regPath_RawrXD_Quantization, KEY_ALL_ACCESS
	test rax, rax
	jz qc_profile_save_fail
	mov rdi, rax

	mov r8d, overrideVal
	invoke RegistrySetDWORD, rdi, rdx, r8d
	invoke RegistryCloseKey, rdi
	mov rax, 1
	ret

qc_profile_save_fail:
	xor rax, rax
	ret
QuantizationControls_SaveModelProfile ENDP

; ============================================================================
; Phase 5 Test Integration
; ============================================================================

PUBLIC QuantizationControls_Destroy
QuantizationControls_Destroy PROC FRAME USES rbx
	mov rbx, pQuantizationState
	test rbx, rbx
	jz qc_destroy_done
	
	mov rcx, hQuantizationChangeEvent
	test rcx, rcx
	jz qc_destroy_free
	invoke CloseHandle, rcx
	
qc_destroy_free:
	invoke GetProcessHeap
	test rax, rax
	jz qc_destroy_done
	invoke HeapFree, rax, 0, rbx
	mov pQuantizationState, 0
	
qc_destroy_done:
	mov rax, 1
	ret
QuantizationControls_Destroy ENDP

; ============================================================================
; Phase 5 Test Integration
; ============================================================================

PUBLIC Test_QuantizationControls_ValidateVRAMCalculations
Test_QuantizationControls_ValidateVRAMCalculations PROC FRAME USES rbx
	; Ensure state exists
	test pQuantizationState, pQuantizationState
	jnz qc_test_have_state
	call QuantizationControls_Create
qc_test_have_state:

	mov rbx, pQuantizationState
	mov QWORD PTR [rbx + QUANTIZATION_STATE.AvailableVRAM], 8000000000

	mov rcx, 7000000000
	call QuantizationControls_GetRecommendedQuantization

	cmp eax, QUANT_Q5_K
	jl qc_test_fail

	mov rax, 1
	ret

qc_test_fail:
	xor rax, rax
	ret
Test_QuantizationControls_ValidateVRAMCalculations ENDP

PUBLIC Test_QuantizationControls_HashFunctionality
Test_QuantizationControls_HashFunctionality PROC FRAME
	; Test FNV-1a hashing
	lea rcx, testModelPath
	call HashString
	
	cmp eax, 0
	je qc_hash_test_fail
	
	mov rax, 1
	ret

qc_hash_test_fail:
	xor rax, rax
	ret
Test_QuantizationControls_HashFunctionality ENDP

.DATA
testModelPath DB "test-model.gguf",0

END
