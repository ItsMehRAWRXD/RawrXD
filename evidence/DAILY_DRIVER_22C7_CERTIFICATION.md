# RawrXD daily-driver acceptance baseline

Candidate SHA-256: `22C7C76CC256CD80481A60B53641AB937946C82DEC607212C03C7657BE39669D`

This manifest records the reported acceptance evidence for the native IDE candidate. It is not a promotion or final certification record.

| Gate | Reported result | Evidence |
| --- | --- | --- |
| Subprocess regression suite | 5/5 PASS | `benchmarks/terminal_runner_regression_latest.log` |
| C++ compile → link → execute | PASS | `RAWRXD_BUILD_RECEIPT_latest.log` |
| Build completion receipt | PASS | `RAWRXD_BUILD_RECEIPT_latest.log` |
| T080 diagnostic → editor line | PASS | `T080_CLICK_TO_LINE_20261108_073653/T080_click_to_line_receipt_20261108_073654.json` |
| T10 save/reopen recovery | PASS | `T10_RECOVERY_20261108_073741/T10.receipt.json` |
| T05 cancellation recovery | PASS | `T05_CANCELLATION_20261108_073852/T05.receipt.json` |

## Certification state

```ini
DAILY_DRIVER_CORE=PASS_REPORTED
ADVANCED_CERTIFICATION=INCOMPLETE
PROMOTE=0
CERTIFIED=0
T25=HELD
```

The executable itself is not committed here; rebuild it from the committed sources and verify its SHA-256 before release use.
