# First-divergence qualification

The reported threshold crossing is not sufficient to identify the responsible
kernel. Surrounding retained rows show earlier nonzero differences.

POSITION0_BLOCK11_PRE_ATTN_OUT=Q/K/V already differ
POSITION0_Q_MAX_ABS=0.0990643501282
POSITION0_K_MAX_ABS=0.0477659702301
POSITION0_V_MAX_ABS=0.0546969771385
POSITION0_ATTN_OUT_MAX_ABS=0.0224211215973

POSITION1_BLOCK3_PRE_FFN_DOWN=FFN norm/gate/up/SwiGLU already differ
POSITION1_FFN_NORM_MAX_ABS=0.00500054657459
POSITION1_GATE_MAX_ABS=0.0136980861425
POSITION1_UP_MAX_ABS=0.00991386175156
POSITION1_SWIGLU_MAX_ABS=0.00680559873581
POSITION1_FFN_DOWN_MAX_ABS=0.00506956130266

INTERPRETATION=The current trace localizes threshold crossings, not proven root causes.
NEXT_DIAGNOSTIC=Trace backward to the earliest nonzero divergence under a declared
comparison tolerance, with equivalent tensor identity, precision and state.
REPAIR_STATUS=NOT_STARTED
