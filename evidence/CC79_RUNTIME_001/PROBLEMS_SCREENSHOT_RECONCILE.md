# PROBLEMS_SCREENSHOT_RECONCILE — visible population only

ASOF_UTC=2026-11-09T15:05:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82%_UNCHANGED
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED

## Observed (screenshot / UI)

Fixture: `broken_multi.cpp` — **3 errors, 0 warnings**

| Diagnostic | Line |
|---|---:|
| C2065 — `y`: undeclared identifier | 3 |
| C2660 — `undeclared_fn`: function does not take 2 arguments | 4 |
| C2440 — cannot convert string literal to `float` | 5 |

Tabs visible: Terminal, Output, Problems, Debug Console.

```
PROBLEMS_VISIBLE_POPULATION=SUPPORTED
EXECUTABLE_SHA_FROM_SCREENSHOT=NOT_ESTABLISHED
FRESH_COMPILER_CAPTURE=NOT_ESTABLISHED
CLICK_TO_LINE=NOT_VERIFIED
FOUR_PANEL_FUNCTION=NOT_ESTABLISHED_BY_SCREENSHOT_ALONE
```

## Law

```
VISIBLE_DIAGNOSTICS ≠ SHA_BOUND_PASS
SCREENSHOT ≠ CLICK_TO_LINE
SCREENSHOT ≠ INTEGRATED_ACCEPTANCE
PROMOTE=0
```

## Next acceptance step

1. Bind this run to full executable SHA-256
2. Activate each diagnostic → editor navigation to lines **3, 4, 5**
3. Exercise Terminal / Output / Problems / Debug on **that same** executable
