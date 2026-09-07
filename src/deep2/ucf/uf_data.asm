; uf_data.asm — fabric BSS (included once from UncoherentFabric64.asm)
INCLUDE UncoherentFabric64.inc

.data?
ALIGN 16
g_uf_ready      dq ?
g_uf_ctx        dq ?
g_uf_allocCb    dq ?
g_uf_freeCb     dq ?
g_uf_copyCb     dq ?
g_uf_nextId     dq ?
g_uf_tensorN    dq ?
g_uf_domains    db (UF_MAX_DOMAIN * UF_DOM_SIZE) dup (?)
g_uf_tensors    db (UF_MAX_TENSOR * UF_TEN_SIZE) dup (?)
ALIGN 16
g_uf_bounce     db UFB_SIZE dup (?)
