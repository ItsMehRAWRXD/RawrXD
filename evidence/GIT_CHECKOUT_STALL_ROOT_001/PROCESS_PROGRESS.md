# Process progress

Two read-only observations were taken approximately 30 seconds apart.

| PID | T0 CPU / working set | Later CPU / working set | Interpretation |
|---:|---|---|---|
| 9272 | 103.67 s / 1.71 GB | 110.09 s / 1.78 GB | CPU and memory increased; still active |
| 14112 | 41.02 s / 1.23 GB | 48.78 s / 0.84 GB | CPU increased; still active |

Both remained responsive. The permitted PowerShell process object did not expose usable read/write I/O counters, so byte-counter progress is `UNAVAILABLE`, not zero. The worktrees remained locked `initializing`, with 301,819 tracked changes and the runtime files absent at the later filesystem observation.

Classification from available evidence: `CHECKOUT_STILL_PROGRESSING`.

