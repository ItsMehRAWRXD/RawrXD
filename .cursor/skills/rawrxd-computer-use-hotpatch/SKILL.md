---
name: rawrxd-computer-use-hotpatch
description: Fail-closed GUI acceptance and Ollama routing evidence for RawrXD.
---

# RawrXD computer-use hotpatch

Use the exact executable hash supplied for the run. Launch with `Start-RawrXDAcceptance.ps1`, perform GUI actions through the computer-use tool, and capture request-correlated model identity from RawrXD's redacted routing log. Never infer routing from visible text.

Required for a routing PASS: two agent cases and two GhostText cases, each with request id, selected GUI model, resolved model, outbound Ollama model, exact-output confirmation, and the same executable SHA. Cancellation and stale-output recovery must also be true. Otherwise the validator must fail closed with `PROMOTE=0`, `CERTIFIED=0`, `T25=HELD`.

The launcher never patches binaries, injects into processes, overwrites evidence, or promotes a build.
