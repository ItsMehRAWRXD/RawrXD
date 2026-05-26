include D:\rawrxd\src\Sovereign_Common.inc
include D:\rawrxd\src\asm\Sovereign_Registry.inc

.DATA
PUBLIC g_ApiTable
PUBLIC g_pGov
PUBLIC g_pTPS
PUBLIC g_ModelState
PUBLIC g_TpsSpace
PUBLIC g_GovState
PUBLIC g_ExecutionTick
PUBLIC g_JIT_StagingArea
PUBLIC g_ResidencyMask
PUBLIC g_SchedulerState
PUBLIC g_SovereignHub
PUBLIC g_NodeRegistryTable
PUBLIC g_GraphStatus
PUBLIC g_ExecutionPlan
PUBLIC g_TensorRegistry
PUBLIC g_TensorCount
PUBLIC g_HeapBase
PUBLIC g_HeapPtr
PUBLIC g_HeapLimit
PUBLIC g_ManifestPtr
PUBLIC g_NodeCount
PUBLIC g_pGlobalRing
PUBLIC g_RingCapacity
PUBLIC g_MiamiLat
PUBLIC g_MiamiLon
PUBLIC Titan_Peak_Cycles
PUBLIC g_DbgMallocRet
PUBLIC g_DbgLoaderR13
PUBLIC g_DbgPIdxFieldAddr
PUBLIC g_DbgPIdxReadback
PUBLIC g_DbgTocPIdx

g_DbgMallocRet     dq 0
g_DbgLoaderR13     dq 0
g_DbgPIdxFieldAddr dq 0
g_DbgPIdxReadback  dq 0
g_DbgTocPIdx       dq 0

align 16
Titan_Peak_Cycles dq 0
g_ManifestPtr dq 0
g_NodeCount dq 0
g_pGlobalRing dq 0
g_RingCapacity dq 1048576 ; 1MB Ring default
g_MiamiLat real8 25.7617
g_MiamiLon real8 -80.1918

g_GovState GOV_STATE <>
g_ModelState MODEL_STATE <>
g_TpsSpace TPS_WORKSPACE <>
g_SchedulerState db 256 dup(0) ; Opaque scheduler state
g_NodeRegistryTable db 1024 dup(0) ; Node descriptors
g_GraphStatus dq 0
g_ExecutionPlan db 8192 dup(0) ; Compiled graph execution plan
g_TensorRegistry dq 256 dup(0) ; tensor pointers
g_TensorCount dq 0

g_HeapBase  dq 0
g_HeapPtr   dq 0
g_HeapLimit dq 0

g_ApiTable SOVEREIGN_API_TABLE <>
g_pGov dq offset g_GovState
g_pTPS dq offset g_TpsSpace

g_ExecutionTick dq 0
g_ResidencyMask dq 4 dup(0)

align 16
g_SovereignHub SovereignHub <>

align 16
g_JIT_StagingArea db 1048576 dup(0) ; 1MB JIT Area
END
