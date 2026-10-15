# Production Hardening Runtime

The operational layer for RawrXD: configuration, observability, reliability,
security and readiness gates that a production deployment needs and a
development build did not have.

Everything in this directory is a **static library with no external
dependency** beyond the Windows C runtime and CNG (`bcrypt`). It does not link
Qt, ggml or Vulkan, so it can be built and verified on its own, and any failure
inside it cannot be caused by a subsystem it does not use.

```
src/production/
  SovereignProductionConfig.hpp/.cpp        typed, validated, env-overridable config
  SovereignObservability.hpp/.cpp           JSON logs + rotation, metrics, tracing, health
  SovereignReliabilityFaultTolerance.hpp/.cpp  circuit breakers, retry, bulkheads, fallbacks
  SovereignSecurityHardening.hpp/.cpp       AES-256-GCM, validation, hash-chained audit log
  ProductionRuntime.hpp/.cpp                the single init/shutdown entry point
  CMakeLists.txt                            library + tests + probe binary
  tests/production_hardening_tests.cpp      77 behavioural checks
  tools/health_probe.cpp                    standalone liveness/readiness probe
```

## Usage

One call boots the whole hardened surface, one call tears it down.

```cpp
#include "ProductionRuntime.hpp"

using namespace Sovereign::Production;

// main() guard: initialises, runs the body, shuts down cleanly, and returns
// 2 when a readiness gate blocked startup.
int wmain() {
    return production_main_guard({}, [] { return run_the_ide(); });
}
```

Or call the pieces directly when the embedding application owns `main`:

```cpp
ProductionRuntime::Options opts;
opts.enforce_gates = true;
opts.install_signal_handlers = true;
if (!ProductionRuntime::init(opts)) return 3;   // a gate failed; do not serve
// ... run ...
ProductionRuntime::shutdown();
```

## Configuration

Every setting resolves in priority order:
**default -> config file -> environment variable -> CLI override**.

```bash
# Disable a subsystem entirely
set RAWRXD_METRICS_ENABLED=false
# Widen a timeout
set RAWRXD_DEFAULT_TIMEOUT_MS=60000
# Point at a config file
set RAWRXD_CONFIG=C:\etc\rawrxd.json
# Override a single field on the command line
rawrxd_health_probe --general.environment=production

# Ask the process for its effective configuration fingerprint
# (a stable hash, so two builds can be compared without diffing secrets)
```

A value that fails a declared rule (range, enum, emptiness) **blocks
startup** with a message naming the offending field, rather than silently
becoming a zero or empty timeout:

```
RawrXD: invalid configuration (2 problem(s)):
  - logging.level: value 'loud' is not permitted
  - reliability.cb_failure_threshold: below the allowed minimum
```

Secrets are never read from a source file. `RAWRXD_SECURITY_KEY_FILE` names a
256-bit key file generated on first use.

## Observability

**Logging.** JSON records with a stable field set (`ts`, `service`,
`instance`, `level`, `category`, `message`, `file`, plus `trace_id`/`span_id`
when a span is active), rotated by size with retention, mirrored to the
console. Warnings and errors go to stderr so `> file` still shows them.

```json
{"ts":1792054183123,"thread":"2716","service":"rawrxd","instance":"local",
 "level":"error","category":"deepload","message":"GGUF load failed",
 "error_code":"GGUF_MISSING_KV","error_what":"header field absent"}
```

Records below the configured level are counted, not silently discarded, so a
mute process is measurable. Sink failures are counted too, so a sink that
throws on every write cannot look configured while delivering nothing.

**Metrics.** Counters, gauges and histograms with labels, exposed in
Prometheus text format:

```
rawrxd_circuit_state_transitions_total{circuit="deepload",from="closed",to="open"} 1
rawrxd_fallback_tier_seconds{tier="gpu"} 1.42
rawrxd_log_records_total 1481
```

Series identity is `(kind, name, canonical labels)`, so two call sites with
different labels never merge into one corrupt series.

**Tracing.** `ScopedTrace` records spans, links them through a trace id
inherited from the caller, and logs anything slower than
`trace_slow_operation_ms` even when no waterfall was requested.

**Health.** Named component checks with liveness, readiness and deep variants,
rendered as JSON for probes.

## Reliability

**Circuit breakers** stop hammering a dependency that is already down, and
recover on their own after the cooldown (open -> half-open -> closed) so no
operator action is needed. Rejected calls are never recorded as failures,
because a busy system would otherwise keep its own breaker open forever.

**Retry** uses bounded exponential backoff with jitter (so retries do not
synchronise into a second thundering herd), an optional global retry budget,
and classifier-based permanent-failure short-circuit. Backoff treats a
reversed `min > max` range as a configuration error, not as a zero delay.

**Bulkheads** cap concurrency per resource and reject immediately when
saturated, so one slow dependency surfaces as a fast error instead of a slow
death by queue backlog.

**Fallback chains** record which tier served and count escalations, so "we
silently fell back to CPU for a week" is visible in the metrics instead of
inferred.

## Security

**Encryption at rest.** AES-256-GCM through the Windows CNG provider, so
persisted state is not plaintext without pulling in OpenSSL. Every
`encrypt()` uses a fresh random nonce (verified by test), and authentication
failure is always reported as a failure — there is no code path that returns
plaintext from a bad tag.

**Audit log.** Append-only, hash-chained records: each record commits to the
previous one, so a truncated or edited trail is detectable after the fact.
Verified by the startup readiness gate (full walk) and by health probes
(tail walk). Two related invariants are enforced and tested:

- An unreadable trailing record **stops the log** instead of being written
  past, because a chain that skips a link is indistinguishable from an untampered one.
- An audit log is only encrypted when the key **survives a restart**. Writing
  ciphertext with an in-memory key would produce a log the next process
  cannot read, which turns tamper detection into noise. When no key file is
  configured the log is written plaintext with a warning instead.

**Input validation** rejects device/UNC paths, non-whitelisted extensions,
oversized inputs and control characters (which is how terminal and log
injection are performed).

**Redaction** masks `token=`, `password:`, `api_key=` style pairs so a
configuration dump can be logged or attached to a bug report safely.

## Readiness gates

Ordered, named checks evaluated at startup. A blocking failure refuses to
serve unless explicitly opted into degraded startup
(`RAWRXD_FAIL_FAST_GATES=false`), and a gate that throws is a failure rather
than an unknown state.

```
config_valid           effective configuration passes every declared rule
logging_operational    a sink is attached and nothing has been silently dropped
metrics_operational    series can be created and rendered
security_primitives    encryption/audit controls report ready, chain intact
reliability_primitives breakers, bulkheads and retry executor are constructed
health_components      every registered component reports healthy
```

## Crash handling

`enable_crash_dumps()` installs an unhandled-exception filter that writes a
minidump and a breadcrumb file (including the config fingerprint) to
`%LOCALAPPDATA%\RawrXD\crashes`, so a release build can still be diagnosed.

## Building and running

```bash
cmake -S . -B build -A x64 -DRAWRXD_BUILD_TESTS=ON
cmake --build build --config Release --target rawrxd_production_hardening -- /m
cmake --build build --config Release --target rawrxd_production_tests      -- /m
cmake --build build --config Release --target rawrxd_health_probe          -- /m

ctest -C Release -R rawrxd_production --output-on-failure
```

## Command-line interface

```
rawrxd_health_probe                 # "healthy (liveness=true readiness=true)"
rawrxd_health_probe --json          # full per-component report

RawrXD-Win32IDE.exe --health-check
RawrXD-Win32IDE.exe --health-check-json
```

Exit codes: `0` healthy, `1` degraded/not ready, `2` the probe itself failed.

Compatible with the convention already present in the repository: exit 0 on
success, non-zero with the reason written to stderr otherwise.

## Test suite

`rawrxd_production_tests` asserts **observable behaviour**, not compilation:
encryption round-trip with tamper rejection and per-call randomisation, audit
chain verification, chain-continuation across a reopen, refusal to append
into a broken chain, circuit breaker state transitions including half-open
recovery, retry exhaustion vs permanent-failure short-circuit, bulkhead
saturation, labelled metric identity, range/enum validation, health override
behaviour, and the runtime's init/record-failure/shutdown cycle.

```
77/77 checks passed
```

The suite runs three consecutive times with the same result, which is what
caught the cross-restart audit-log defect: an in-memory key on the second run
made run one's records unreadable.
