# Deep2 P0-P8 no-dependency source drop

Source-only integration pack for the post-Attempt2 audit. It preserves externally sealed full-model TPS authority and leaves PROMOTE/TIP_CLIMB fail-closed until all product gates are real.

Priority mapping:
- P0 `d2_daily_streamer_live.cpp`
- P1 `d2_stage_timing_authority.cpp`
- P2 `d2_packed_q2k_tiled.cpp`
- P3 `d2_deviceio_ssvk.cpp`
- P4 `d2_dual_aggregate_ssvk.cpp`
- P5 `d2_missing15_conjunction.cpp`
- P6 `d2_model_size_next4.cpp`
- P7 `d2_ide_sse_cancel.cpp`
- P8 `d2_promotion_tip_hold.cpp`

No code in this drop promotes mock output to product authority.
