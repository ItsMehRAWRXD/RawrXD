; =============================================================================
; rawrxd_unresolved_stubs.asm ? Internal stub implementations for all unresolved
; symbols so RawrXD.exe links without external C++ bridges or Vulkan SDK libs.
; All functions are no-op / safe-default implementations.
; =============================================================================

INCLUDE rawrxd_win64.inc

OPTION DOTNAME
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

; ---------------------------------------------------------------------------
; Global data definitions for EXTERNDEF symbols
; ---------------------------------------------------------------------------

PUBLIC g_hInstance
PUBLIC g_hHeap
PUBLIC g_last_zmm_heartbeat

.data
ALIGN 16
g_hInstance             DQ 0
g_hHeap                 DQ 0
g_last_zmm_heartbeat    DQ 0

; ---------------------------------------------------------------------------
; Code section
; ---------------------------------------------------------------------------

.code

; ---------------------------------------------------------------------------
; Helper macro: zero-argument stub that returns 0
; ---------------------------------------------------------------------------

STUB0 MACRO name
    name PROC
        xor rax, rax
        ret
    name ENDP
ENDM

; ---------------------------------------------------------------------------
; GDI / User32 import stubs (used by Phase1_CoreUX)
; ---------------------------------------------------------------------------

STUB0 __imp_SetBkMode
STUB0 __imp_SetTextColor
STUB0 __imp_TextOutA
STUB0 __imp_CreateFontA
STUB0 __imp_WinHttpAddRequestHeaders
STUB0 __imp_WinHttpCloseHandle
STUB0 __imp_WinHttpConnect
STUB0 __imp_WinHttpOpen
STUB0 __imp_WinHttpOpenRequest
STUB0 __imp_WinHttpQueryDataAvailable
STUB0 __imp_WinHttpReadData
STUB0 __imp_WinHttpReceiveResponse
STUB0 __imp_WinHttpSendRequest

; ---------------------------------------------------------------------------
; WinHTTP / WinInet stubs (used by AgenticShellBridge, GenesisP0_AiBackendBridge)
; ---------------------------------------------------------------------------

STUB0 WinHttpCloseHandle
STUB0 WinHttpConnect
STUB0 WinHttpOpen
STUB0 WinHttpOpenRequest
STUB0 WinHttpQueryDataAvailable
STUB0 WinHttpReadData
STUB0 WinHttpReceiveResponse
STUB0 WinHttpSendRequest
STUB0 HttpOpenRequestA
STUB0 HttpSendRequestA
STUB0 InternetCloseHandle
STUB0 InternetConnectA
STUB0 InternetOpenA
STUB0 InternetReadFile

; ---------------------------------------------------------------------------
; DWM stub
; ---------------------------------------------------------------------------

STUB0 DwmSetWindowAttribute

; ---------------------------------------------------------------------------
; C runtime / memory stubs
; ---------------------------------------------------------------------------

memcmp PROC
    xor rax, rax
    ret
memcmp ENDP

; ---------------------------------------------------------------------------
; Internal cross-module stubs
; ---------------------------------------------------------------------------

STUB0 Apply_FFN_SwiGLU
STUB0 Apply_RMSNorm
STUB0 Apply_RoPE_Direct
STUB0 asm_orchestrator_dispatch
STUB0 asm_orchestrator_drain_queue
STUB0 asm_orchestrator_init
STUB0 asm_orchestrator_queue_async
STUB0 asm_orchestrator_shutdown
STUB0 BeaconSend
STUB0 Compute_MHA_Parallel
STUB0 Encrypted_Main_Entry
STUB0 GetLlamaBridge
STUB0 InferenceEngine_Submit
STUB0 Initialize_Sovereign_APIs
STUB0 masm_ai_tensor_simd_process
STUB0 ModelState_AcquireInstance
STUB0 pVirtualAlloc
STUB0 rawr_ssot_active_owner
STUB0 rawr_ssot_owner_for_hash
STUB0 RawrXD_AgenticDeepThinking_Init
STUB0 RawrXD_AgenticMemorySystem_Alloc
STUB0 RawrXD_AgenticMemorySystem_Free
STUB0 RawrXD_AgenticToolExecutor_Execute
STUB0 RawrXD_AgenticToolExecutor_Init
STUB0 RawrXD_Disasm_HandleReq
STUB0 RawrXD_InferenceEngine_Detokenize
STUB0 RawrXD_InferenceEngine_Init
STUB0 RawrXD_InferenceEngine_Run
STUB0 RawrXD_InferenceEngine_Tokenize
STUB0 RawrXD_Module_HandleReq
STUB0 RawrXD_Symbol_HandleReq
STUB0 RunInference
STUB0 Sample_Logits_TopP
STUB0 Titan_ResetDMAStats

; ---------------------------------------------------------------------------
; C++ class stubs ? LlamaNativeBridge
; ---------------------------------------------------------------------------

; public: bool __cdecl LlamaNativeBridge::Initialize(wchar_t const *)
?Initialize@LlamaNativeBridge@@QEAA_NPEB_W@Z PROC
    xor rax, rax
    ret
?Initialize@LlamaNativeBridge@@QEAA_NPEB_W@Z ENDP

; public: bool __cdecl LlamaNativeBridge::IsModelLoaded(void)const
?IsModelLoaded@LlamaNativeBridge@@QEBA_NXZ PROC
    xor rax, rax
    ret
?IsModelLoaded@LlamaNativeBridge@@QEBA_NXZ ENDP

; public: bool __cdecl LlamaNativeBridge::LoadModel(wchar_t const *,int,long)
?LoadModel@LlamaNativeBridge@@QEAA_NPEB_WHJ@Z PROC
    xor rax, rax
    ret
?LoadModel@LlamaNativeBridge@@QEAA_NPEB_WHJ@Z ENDP

; public: char const * __cdecl LlamaNativeBridge::GetLastError(void)const
?GetLastError@LlamaNativeBridge@@QEBAPEBDXZ PROC
    lea rax, szEmpty
    ret
?GetLastError@LlamaNativeBridge@@QEBAPEBDXZ ENDP

; public: struct LlamaNativeBridge::GenerationResult __cdecl LlamaNativeBridge::Generate(...)
?Generate@LlamaNativeBridge@@QEAA?AUGenerationResult@1@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@HMMM@Z PROC
    xor rax, rax
    ret
?Generate@LlamaNativeBridge@@QEAA?AUGenerationResult@1@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@HMMM@Z ENDP

; public: void __cdecl LlamaNativeBridge::ClearKVCache(void)
?ClearKVCache@LlamaNativeBridge@@QEAAXXZ PROC
    ret
?ClearKVCache@LlamaNativeBridge@@QEAAXXZ ENDP

; public: void __cdecl LlamaNativeBridge::Shutdown(void)
?Shutdown@LlamaNativeBridge@@QEAAXXZ PROC
    ret
?Shutdown@LlamaNativeBridge@@QEAAXXZ ENDP

; public: void __cdecl LlamaNativeBridge::UnloadModel(void)
?UnloadModel@LlamaNativeBridge@@QEAAXXZ PROC
    ret
?UnloadModel@LlamaNativeBridge@@QEAAXXZ ENDP

; ---------------------------------------------------------------------------
; C++ class stubs ? RawrXD::GPU::VulkanContext
; ---------------------------------------------------------------------------

; public: struct VkDevice_T * __cdecl RawrXD::GPU::VulkanContext::device(void)
?device@VulkanContext@GPU@RawrXD@@QEAAPEAUVkDevice_T@@XZ PROC
    xor rax, rax
    ret
?device@VulkanContext@GPU@RawrXD@@QEAAPEAUVkDevice_T@@XZ ENDP

; public: struct VkQueue_T * __cdecl RawrXD::GPU::VulkanContext::computeQueue(void)
?computeQueue@VulkanContext@GPU@RawrXD@@QEAAPEAUVkQueue_T@@XZ PROC
    xor rax, rax
    ret
?computeQueue@VulkanContext@GPU@RawrXD@@QEAAPEAUVkQueue_T@@XZ ENDP

; public: unsigned int __cdecl RawrXD::GPU::VulkanContext::findMemoryType(unsigned int,long)
?findMemoryType@VulkanContext@GPU@RawrXD@@QEAAIIJ@Z PROC
    xor rax, rax
    ret
?findMemoryType@VulkanContext@GPU@RawrXD@@QEAAIIJ@Z ENDP

; public: unsigned int __cdecl RawrXD::GPU::VulkanContext::queueFamilyIndex(void)
?queueFamilyIndex@VulkanContext@GPU@RawrXD@@QEAAIXZ PROC
    xor rax, rax
    ret
?queueFamilyIndex@VulkanContext@GPU@RawrXD@@QEAAIXZ ENDP

; ---------------------------------------------------------------------------
; Data
; ---------------------------------------------------------------------------

.data
szEmpty DB 0

; ---------------------------------------------------------------------------
; End
; ---------------------------------------------------------------------------

END

