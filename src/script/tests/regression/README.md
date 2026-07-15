# RawrXD-Script Regression Database

## Purpose

Every discovered bug becomes a permanent regression test. Never delete them.

## Naming Convention

```
bug_<category>_<number>.js

Categories:
  - parser: Parser bugs
  - emitter: Bytecode emitter bugs
  - interp: Interpreter bugs
  - runtime: Runtime bugs
  - ic: Inline cache bugs
  - memory: Memory management bugs
  - exception: Exception handling bugs
  - fuzz: Discovered by fuzzing

Examples:
  bug_parser_0001.js
  bug_ic_0042.js
  bug_fuzz_0123.js
```

## Test Format

Each regression test is a self-contained JavaScript file with metadata:

```javascript
// @bug: parser_0001
// @description: Parser failed on nested ternary expressions
// @discovered: 2026-07-03
// @fixed: 2026-07-03
// @expected: "success"
// @actual: "SyntaxError: Unexpected token"

// Test case
var result = true ? false ? "a" : "b" : "c";
assert(result === "b");
```

## Adding New Tests

When a bug is discovered:

1. Create minimal reproduction case
2. Name it `bug_<category>_<next_number>.js`
3. Add metadata comments
4. Run `run_validation.ps1` to verify it fails before fix
5. Fix the bug
6. Verify test passes
7. Commit both test and fix

## Running Regression Tests

```powershell
# Run all regression tests
.\scripts\run_validation.ps1

# Run only regression tests
.\scripts\run_validation.ps1 -RegressionOnly
```

## Statistics

Current count: 0 tests

| Category | Count |
|----------|-------|
| parser | 0 |
| emitter | 0 |
| interp | 0 |
| runtime | 0 |
| ic | 0 |
| memory | 0 |
| exception | 0 |
| fuzz | 0 |
