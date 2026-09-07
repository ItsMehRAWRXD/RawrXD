; UncoherentFabric64.asm — uncoherent multi-domain tensor fabric (x64 MASM)
;
; Reconstruct from published API (ChatGPT sandbox drop not present on disk).
; Law: never sum HOST+GPU0+GPU1 into one coherent PA pool.
;
; ml64 /c /Fo UncoherentFabric64.obj UncoherentFabric64.asm
;
OPTION CASEMAP:NONE
INCLUDE UncoherentFabric64.inc

PUBLIC UF_FabricInit
PUBLIC UF_InitProfile_192G_2x24G_4T
PUBLIC UF_SetCallbacks
PUBLIC UF_RegisterDomain
PUBLIC UF_SetDomainOpaque
PUBLIC UF_CreateTensor
PUBLIC UF_FindTensor
PUBLIC UF_BindResidency
PUBLIC UF_AcquireRead
PUBLIC UF_AcquireWrite
PUBLIC UF_CommitWrite
PUBLIC UF_Release
PUBLIC UF_EnsureCurrent
PUBLIC UF_EnsureCurrentStaged
PUBLIC UF_Evict
PUBLIC UF_QueryCurrentMask
PUBLIC UF_QueryResidentMask
PUBLIC UF_QueryGeneration
PUBLIC UF_QueryStaleMask
PUBLIC UF_BounceChainInit
PUBLIC UF_BounceChainSync
PUBLIC UF_BouncePeekNext
PUBLIC UF_BounceBeginRW
PUBLIC UF_BounceCommitRW

INCLUDE uf_data.asm
INCLUDE uf_init.asm
INCLUDE uf_tensor.asm
INCLUDE uf_lease.asm
INCLUDE uf_ensure.asm
INCLUDE uf_evict.asm
INCLUDE uf_bounce.asm

END
