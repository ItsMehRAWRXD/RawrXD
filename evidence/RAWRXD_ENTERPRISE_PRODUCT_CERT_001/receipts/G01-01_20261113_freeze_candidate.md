# G01-01 Freeze exact release Git commit and submodule revisions

| Field | Value |
|-------|-------|
| GATE_ID | G01-01 |
| GIT_SHA | 70ec558062cfd42fb5676d53266618c3091dc8f9 |
| EXE_SHA256 | (n/a — source freeze gate) |
| MODEL_SHA256 | (n/a) |
| HARDWARE | win32 local (measure host) |
| COMMAND | `git rev-parse HEAD`; `git submodule status`; `git push origin work/v0-first-divergence` |
| EXIT_CODE | 0 (rev-parse / submodule status) |
| RESULT | EVIDENCE_PARTIAL |
| ARTIFACTS | FREEZE_PIN.txt; this receipt |
| REVIEWER | SELF_MEASURE (independent review required for PASS) |
| TIMESTAMP | 2026-11-13T22:25-05:00 |
| CROSS_SHA_CREDIT | 0 |

## Measured pins
- BRANCH=`work/v0-first-divergence`
- SUBMODULE `3rdparty/quickjs`=`f1139494d18a2053630c5ed3384a42bb70db3c53`
- SUBMODULE `3rdparty/quickjs_ng`=`6d2a9bacbc9feb5c1f46f80b3cf4c25bedd2187b`
- `.gitmodules` also lists `remove-refusals-with-transformers` (confirm presence on clean checkout)

## Why not PASS
Candidate freeze recorded; independent reviewer + complete submodule inventory + release-tag intent not yet signed. GATE_MATRIX remains NOT_RUN for G01-01.
