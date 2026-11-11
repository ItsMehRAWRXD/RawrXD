# RELEASE_SCOPE_FREEZE — Windows daily-driver IDE

ASOF_UTC=2026-11-09T14:50:00Z
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
CONTROLLING_TIP=CC79
A4F_IMMUTABLE=1
TIP_MOVE_AUTHORIZED=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
HIDDEN_GAP_AUDIT=SEALED
NO_ARITHMETIC_FROM_120_INVESTIGATE=1

## Meaning of 100% (this freeze)

**100% = all agreed release gates PASS on one final EXE SHA.**  
Promotion and certification remain separately controlled (`PROMOTE=0` until authorized).  
Investigation targets ≠ confirmed defects. Days saved cannot be estimated without live blocker register + candidate evidence (this freeze supplies the register; estimate still held).

## Required for release (user-visible chain)

Must all PASS on **one** candidate SHA:

1. Open / edit / save workspace file
2. Compile / link / run (native MSVC path)
3. Output pane (Build HWND) + Problems list + click-to-line navigation
4. Model response in Chat (real backend)
5. Agent tool action with durable filesystem effect
6. Cancellation and recovery
7. Session persistence across restart
8. Extension load → activate → deactivate → shutdown (FORCE_KILL=0)
9. Clean exit (no orphan workers)
10. Repeated-use + failure-recovery checks on the same SHA
11. Package → clean-machine launch → rollback evidence

## Explicit optional / deferred (OUT of this freeze)

| Feature | Decision | Reason |
|---------|----------|--------|
| Multi-platform compilers (ELF/Mach-O/Android) | OPTIONAL / DEFER | Exceeds Windows daily-driver minimum (#57 B13–B15) |
| Multi-GPU partitioning oracles | OPTIONAL / DEFER | OUT_OF_SCOPE vs daily-driver |
| Marketplace / signed extension store | OPTIONAL / DEFER | Not on integrated chain |
| Exactly-once chat delivery cert | DEPENDENCY of Chat | Keep in scope only as chat acceptance subgate — not a separate maturity climb |
| Full Issue #57 45-gate matrix | DEFER extras | Only gates required by chain above |

## Dependencies of required features (keep even if invisible)

- ConPTY pipe ownership / cancel tree (Terminal + PowerShell + Build)
- ProblemsAggregator + VS_UNICODE_OUTPUT scrub (H27)
- Output channel HWND bind 1604–1611 (H16/H22 axis)
- AgentSession single owner + cancel (H57/H58)
- ExtensionHost IPC handshake/shutdown (H51)
- Panel routing: PowerShell/Build/etc. must not leak into Chat

## Candidate strategy (anti-churn)

```
STOP_PARALLEL_TIP_SPRAWL=1
ONE_CANDIDATE_BRANCH=1
BUILD_ONCE_THEN_INTEGRATED_E2E=1
REBUILD_ONLY_AFTER_FAILURE_ON_THAT_SHA=1
NO_CROSS_SHA_PASS_INHERITANCE=1
```

Absorb prior tip_hwnd_repair / tip_input_event / tip_ps_routing fixes into **one** package tip (e.g. `tip_integ_candidate_001`) before integrated run. Do not treat 30B9 / 2B1D / C43B partials as integrated PASS.
