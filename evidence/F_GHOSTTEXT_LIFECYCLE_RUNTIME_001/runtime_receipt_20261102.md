# GhostText lifecycle runtime receipt

## Candidate

- Executable: `F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe`
- SHA-256: `70E6B1700F8EDF7A3770F63A5B89565AB05798CAB4B8DFC784200153B786F9DA`
- Fixture: `F:\rawrxd\tmp_build\ghosttext_e2e_20261030\ghosttext_fixture.cpp`
- Fixture SHA-256 after test: `4BAB8CEFA856176FB195C60AD4A3FFF09A5F9E55D729B15F1ACBACCC7689A2E0`

## Observed lifecycle

- Request 1: `TRIGGER -> REQUEST_SENT -> RESPONSE_RECEIVED(success=1) -> RENDERED -> ACCEPTED -> DISMISSED`
- Request 2: `TRIGGER -> REQUEST_SENT -> RESPONSE_RECEIVED(success=1) -> RENDERED -> DISMISSED`
- Editor content was restored to the fixture's original text; on-disk hash remained unchanged.
- IDE remained responsive throughout the observed interactions.

## Results

- Successful completion and Tab acceptance: PASS
- Dismissal without committing the second suggestion: PASS
- Request correlation: PASS (`request_id=1`, `request_id=2`)
- On-disk fixture preservation: PASS
- Cancellation: FAIL in this run. An Escape sent immediately after editing did not prevent request 3 from being triggered and rendered; no `GHOSTTEXT_CANCELLED` event was observed.
- Stale-response fencing: NOT VERIFIED
- Clean shutdown in this run: NOT RUN

## Finding

The main model selector displayed `qwen3:8b`, but GhostText `Auto Local` emitted the observed route `bigdaddyg-productivity-local:latest`. This run therefore verifies the GhostText lifecycle, not Qwen3-specific routing. The route-selection discrepancy remains open.

PROMOTE=0
