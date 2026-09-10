; RawrXD_RealMathAttention_x64.asm
; Pure x64 MASM math + single-head attention. No CRT/imports/invoke/stubs.
; Bodies split ≤99 lines; assemble as one unit (no EXTERN).
OPTION CASEMAP:NONE
INCLUDE XR_RealMath_const.inc
.code
INCLUDE XR_ExpF32_body.inc
INCLUDE XR_SiLU_body.inc
INCLUDE XR_Softmax_body.inc
INCLUDE XR_RMSNorm_Dot_body.inc
INCLUDE XR_AttentionHead_body.inc
END
