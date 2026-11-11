# Slim daily-driver — extension scope disposition

ASOF_UTC=2026-11-09T07:37:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0

```
PROFILE=SLIM_WIN32IDE_NATIVE
CONTROLLING_SHA=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
EXT_GATE=OUT_OF_SCOPE_FOR_SLIM_PROFILE
EXT_LOAD=NOT_RUN
EXT_PASS=0
```

## Decision

**Slim daily driver** (path B): Extensions / ExtensionHost / VSIX load are **explicitly excluded** from the slim Native `RawrXD-Win32IDE-Native` acceptance conjunction.

Rationale:

- Tip EXE has no linked ExtensionHost / loadVSIX / QuickJS activate surface (`SMOKE_T16_EXT.md`).
- Slim profile aligns with Sovereign Engine protocol (no managed host for extensions in this binary).
- Historical full-IDE ExtensionHost seals (e.g. POST_E59D / 3B72) **must not** transfer onto this SHA.

## Law

```
EXT_NOT_RUN ≠ EXT_PASS
OUT_OF_SCOPE ≠ PASS
FULL_FEATURE_DAILY_DRIVER still requires a separate ExtensionHost-wired candidate
SLIM_PROFILE_ACCEPTANCE may close without EXT
CERTIFIED=0 PROMOTE=0 until higher authority conjunction
FINISH_25_HISTORICAL_19/25 ≠ rewritten by this disposition
```

## Full-feature path (not chosen for this tip)

Integrate ExtensionHost into the candidate, same-SHA EXT load smoke, then reopen full-feature acceptance. Do not record that work as done here.
