; K2_RealAttn_const.inc — F32 consts + XR_AttnCtx layout. ≤99.
IFNDEF K2_REAL_ATTN_CONST_INC
K2_REAL_ATTN_CONST_INC EQU 1
ATTN_Q          EQU 00h
ATTN_K          EQU 08h
ATTN_V          EQU 10h
ATTN_SCORES     EQU 18h
ATTN_OUT        EQU 20h
ATTN_SEQ_LEN    EQU 28h
ATTN_HEAD_DIM   EQU 30h
.const
ALIGN 16
c_exp_min       REAL4 -87.33654475
c_exp_max       REAL4  88.00000000
c_log2e         REAL4   1.4426950408889634
c_ln2_hi        REAL4   0.6931457519531250
c_ln2_lo        REAL4   0.00000142860676533
c_one           REAL4   1.0
c_half          REAL4   0.5
c_inv6          REAL4   0.1666666666666667
c_inv24         REAL4   0.0416666666666667
c_inv120        REAL4   0.0083333333333333
c_inv720        REAL4   0.0013888888888889
ENDIF
