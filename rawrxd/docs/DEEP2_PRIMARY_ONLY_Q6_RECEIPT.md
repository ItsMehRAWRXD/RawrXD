# Primary-only Q6 route receipt

## Result

The completed 3-sample run used the existing Q6 packed-byte shader candidate with `LAYER_SPLIT`, Q4 tile `8`, Q4/Q6 hot paths, one warmup, no trace output, and `DEEP2_DENSE_PRIMARY_ONLY=1`.

| Measure | Result |
| --- | ---: |
| Runs | 3 |
| Decode TPS | 30.998, 31.401, 31.392 |
| Median TPS | 31.392 |
| Range | 30.998–31.401 |
| Generated tokens | 32/32 on every run |
| Host-forward layers | 0 on every run |
| Fence failures | 0 on every run |
| NaN / Inf | 0 / 0 on every run |

Evidence: `F:\wt_ide1\deep2_primary_only_q6packed_3x32\flight_recorder_report.json`.

The earlier 38.103 TPS result was a single probe and is retained as exploratory evidence, not as the certified median. This receipt does not promote the route to the production default. Long-generation output parity, an A/B/A comparison, and the paused controlled D2 capture remain required.
