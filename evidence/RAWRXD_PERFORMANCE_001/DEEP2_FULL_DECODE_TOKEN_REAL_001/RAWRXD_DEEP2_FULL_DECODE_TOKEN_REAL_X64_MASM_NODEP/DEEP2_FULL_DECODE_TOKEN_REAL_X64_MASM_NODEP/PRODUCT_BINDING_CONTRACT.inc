; ============================================================================
; PRODUCT BINDING CONTRACT — documentation-only MASM include
; No code or fixture is emitted by this file.
;
; Bind D2_BIND_FORWARD_FN directly to the product function which executes:
;
;   current autoregressive input
;       -> RunResolvedBlock(0..60)
;       -> final RMSNorm
;       -> real LM head
;       -> actual float logits pointer + vocabulary count
;
; Bind D2_BIND_COMMIT_FN to the real token-stream/state commit path.
; Bind D2_BIND_ADVANCE_FN to the actual autoregressive token/KV position update.
;
; FORBIDDEN BINDINGS:
;   block-0-only output
;   abbreviated/product-chain timing output
;   cached logits from a prior position
;   synthetic logits
;   fixture logits
;   a callback that returns success before work completes
;
; The decode module invokes the bound functions; no declaration bit can replace them.
; ============================================================================
