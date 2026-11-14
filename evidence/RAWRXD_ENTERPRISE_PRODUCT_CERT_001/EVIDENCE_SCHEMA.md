# Evidence schema (mandatory for every PASS)

| Field | Required |
|-------|----------|
| GATE_ID | Unique (e.g. G01.03) |
| GIT_SHA | Full commit of tested tree |
| EXE_SHA256 | Exact tested binary |
| MODEL_SHA256 | When inference/model path |
| HARDWARE | CPU, GPU, driver, RAM, OS |
| COMMAND | Reproducible invocation |
| EXIT_CODE | Actual |
| RESULT | PASS / FAIL / BLOCKED / NOT_RUN |
| ARTIFACTS | Paths to logs/traces/screenshots |
| REVIEWER | Independent identity |
| TIMESTAMP | Execution time (ISO) |
| CROSS_SHA_CREDIT | Must be **0** |

Receipt path: `receipts/<GATE_ID>_<YYYYMMDD>_<shortsha>.md`  
Related-but-not-PASS: `RELATED_INDEX.md` only; do not flip matrix to PASS.
