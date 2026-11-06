# RawrXD IDE: 15-blocker evidence ledger

This ledger is scoped to the audit branch, not a certification of the entire IDE.
**PASS** requires an executed gate against the relevant production code. **SIM-PASS**
requires an executed simulation and cannot be promoted to a real-device PASS.
A committed test without an observed successful run is **NOT VERIFIED**.

| # | Acceptance area | Gate required | Status as of 2026-11-06 |
|---|---|---|---|
| 01 | Extension host build selection | Identify real Win32IDE QuickJS implementation and confirm target linkage | NOT VERIFIED |
| 02 | Extension command registry | Compile/run production registry contract on Linux and MSVC | FAIL (CI workflow; root cause unconfirmed) |
| 03 | VSIX install | Install a local fixture VSIX, reject path traversal, verify installed files | NOT RUN |
| 04 | Extension activation/deactivation | Execute real JS fixture and verify disposal and reload | NOT RUN |
| 05 | Extension permissions | Reject unauthorized filesystem/process/network capabilities | NOT RUN |
| 06 | Extension API compatibility | Exercise supported vscode.* API contracts and document gaps | NOT RUN |
| 07 | Extension fault isolation | Throw in extension callbacks; confirm IDE stays responsive | PARTIAL TEST AUTHORED, NOT VERIFIED |
| 08 | CLI argument handling | Compile real CLI and test valid/invalid arguments and exit codes | NOT RUN |
| 09 | CLI file mutations | Sandbox approved edit, denial, traversal, and rollback cases | NOT RUN |
| 10 | Agent tool dispatch | Real agent-loop fixture must emit, authorize, execute and report tool calls | NOT RUN |
| 11 | Mock inference integration | Real IDE transport connects to local fixture; stream and error cases | FIXTURE TESTS AUTHORED, INTEGRATION NOT RUN |
| 12 | Win32 cancellation | Request A -> Stop -> B with crash/timeout checks | NOT RUN; historical failure |
| 13 | Editor recovery | Edit -> forced termination -> restart -> recover content | NOT RUN in current branch |
| 14 | GUI daily usability | Keyboard navigation, file tabs, dialogs, focus and offscreen windows | NOT RUN |
| 15 | Packaging/release | Independent clean install, launch, smoke, checksums and rollback | NOT RUN |

## 2026-11-06 isolated execution evidence

- **PASS (reconstructed subset only):** GCC C++17 `-Wall -Wextra -Werror -pthread`
  compiled a manually transferred reconstruction of the production command
  registry; an isolated concurrency scenario passed (unregister during an
  in-flight callback, reject later dispatch, allow the active callback to
  complete). This is **not** execution of the repository's exact translation
  unit or its full `extension_command_contract.cpp` test suite.
- GitHub Actions run `42183798152` reported both Linux and Windows jobs
  failed, with no job steps or logs returned by the connector. Do not promote
  this isolated result to CI PASS or IDE certification.
- The registry still does **not** wait for already-running extension callbacks
  to finish before extension-owned state is destroyed; this requires separate
  lifecycle coordination and integration verification.

## Reproduction

- Fixture transport: `python -m unittest discover -s tests/headless -p 'test_mock_inference_server.py' -v`
- Linux production command registry: `g++ -std=c++17 -Wall -Wextra -Werror -pthread tests/headless/extension_command_contract.cpp -o /tmp/extension_command_contract && timeout 15s /tmp/extension_command_contract`
- Windows registry: run the `Windows MSVC extension registry contract` CI job.
- CI: `.github/workflows/headless-mock-contract.yml`.

The mock server does **not** test a real inference model, GPU, IDE HTTP client,
or Win32 Stop button. The production command registry is **not** the QuickJS
host. Neither test can certify VSIX installation.

## Isolated local evidence

- VSIX signature-policy contract: **LOCAL PASS** on Linux GCC C++17 with
  `-Wall -Wextra -Werror`. This checks only the header policy, not VSIX
  installation or the Windows extension host.
- Windows MSVC manifest and signature-policy jobs are authored but **NOT VERIFIED**.
- Do not infer a full extension-host PASS from these isolated checks.

## CI incident

GitHub workflow run 42175796159 reported **failure** for both the Python and
Windows MSVC jobs. The job log endpoint returned a missing blob; the root cause
is therefore **unknown**. Do not mark either job PASS based on source inspection.

## Completion metric

The historical 68% planning estimate is **not** a measured completion score.
Verified closures in this ledger: **0/15**. Increase only when a gate has
a reproducible passing result and links to the exact commit/build artifact.
