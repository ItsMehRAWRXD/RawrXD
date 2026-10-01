# B15 Acceptance Fixture — measured baseline

Authority: `RAWRXD_AGENTIC_IDE_001`
Fixture: `F:\~dev\cert_agentic\b15_fixture`
Build dir: `F:\~dev\cert_agentic\b15_build` (kept outside the fixture)

## Purpose

A real, small, deliberately broken C++ repository. The agent receives ONE
natural-language prompt and must discover, inspect, edit, build, observe a
real compiler diagnostic, repair, test, observe real test failures, repair,
rebuild, retest, inspect the final diff, and report factually.

## Prompt (the only input)

> Add validation to the configuration loader, update callers as necessary,
> build the project, run its tests, and fix any regressions you introduce.

## Contract the agent must discover (not be told)

`include/cfix/config_loader.h` declares the contract in its doc comment:
host must be non-empty, port must be 1..65535, violation raises
`std::invalid_argument`. `docs/config_format.md` restates it as a table and
explains the consequence of accepting an out-of-range port.

The agent is expected to *read* these. The prompt never states the range.

## Measured baseline — 2026-10-01

Toolchain: VS 2022 BuildTools MSVC 14.44.35207, CMake + Ninja.

### Branch 1 — build failure (forces diagnose/repair before any test can run)

```
main.cpp(15): error C2039: 'portNumber': is not a member of 'cfix::Config'
include/cfix/config_loader.h(8): note: see declaration of 'cfix::Config'
ninja: build stopped: subcommand failed.
```

`src/main.cpp` calls `cfg.portNumber()`. The struct field is `port`. The
agent must observe this diagnostic, read the header, and repair the caller
— this is the "update callers as necessary" half of the request.

### Branch 2 — test failure (forces implement, then verify)

Build of the test target alone succeeds, then:

```
ok:   valid config: host parsed
ok:   valid config: port parsed
ok:   valid config: verbose parsed
FAIL: empty host rejected
FAIL: port 0 rejected
FAIL: port above 65535 rejected
FAIL: negative port rejected
FAIL: non-numeric port rejected
FAIL: missing host rejected
ok:   port 1 accepted
ok:   port 65535 accepted

CHECKS=11 FAILURES=6
0% tests passed, 1 tests failed out of 1
```

`src/config_loader.cpp` parses but never validates. The 6 failures are
exactly the documented contract; the 5 passes guard against a fix that
over-validates and breaks the valid/boundary cases.

## Why this fixture is honest

- The contract is in the repository, not in the prompt.
- The compile error and the test failure are independent, so an agent that
  only "makes it compile" still fails, and an agent that only makes tests
  pass still fails.
- The boundary checks (`port 1`, `port 65535`) catch an off-by-one
  "fix" that rejects valid configuration.
- Nothing here is satisfiable by editing the test file. A diff that weakens
  `test_config_loader.cpp` must be caught by the verifier inspecting the
  final diff against the request, not by the test exit code alone.

## Third-party dependencies

THIRD_PARTY_DEPS=0 — no test framework; the test file is a plain
`main()` with its own check counter, so no network or package fetch is
possible during certification.
