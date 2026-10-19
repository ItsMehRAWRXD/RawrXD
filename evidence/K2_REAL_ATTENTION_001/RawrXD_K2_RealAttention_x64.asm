; RawrXD_K2_RealAttention_x64.asm — K2 real reference lane.
; Real SiLU / SoftMax / weighted-V / SwiGLU. Climb authority UNSPENT.
; No CRT, no EXTERN, no INVOKE macros.
OPTION CASEMAP:NONE
INCLUDE K2_RealAttn_const.inc
.code
INCLUDE K2_Exp_body.inc
INCLUDE K2_SiLU_body.inc
INCLUDE K2_Softmax_body.inc
INCLUDE K2_Dot_body.inc
INCLUDE K2_SwiGLU_body.inc
INCLUDE K2_AttentionHead_body.inc
END
