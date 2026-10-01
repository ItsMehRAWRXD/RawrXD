# RAWRXD_B81_CANONICAL_SWEEP_BUILD_001

    GATE      = Reproducible link for the regime-sweep lane
    ARTIFACT  = tools/build_regime_sweep.ps1
    DATE      = 2026-10-01
    VERDICT   = PASS (link succeeds; two defects fixed, one self-inflicted
               source-destruction incident recorded in full)

---

## 1. The three link failures, and their distinct causes

These were previously three unrelated-looking errors treated as "build flakiness".
They are three different bugs and only one of them is about staleness.

| Error | Real cause |
|---|---|
| `LNK2019` / `LNK1120` unresolved externals | `regime_sweep.cpp` had gained calls to `cpu::DispatchPendingAtReturn()`, `DispatchActiveAtReturn()`, `DispatchGenerationAtReturn()`, `DispatchCount()` while the pre-existing `rawrxd_cpu_math.obj` predated them. A freshly compiled caller against a stale library object links only if the library happens to export what the caller wants. |
| `LNK2038` + `LNK2005` | Runtime-library mismatch. The pre-existing objects were `/MD` (dynamic CRT). Compiling one TU `/MT` produced `libcpmt` and `msvcprt` duplicate definitions *and* a `RuntimeLibrary` mismatch against the `/MD` objects. |
| `LNK1104 cannot open file 'X.exe'` | A previous sweep binary was still running and held the image. |

The unresolved-externals failure is the dangerous one, because it is
**silent in the wrong direction**: a stale object can satisfy a link that should
have failed, producing a binary that mixes two different source revisions.

## 2. Repair

One command builds the lane:

```powershell
pwsh -File tools/build_regime_sweep.ps1 -Out sweep.exe
```

- **Every TU is recompiled from source on every invocation.** There is no cached
  object that can go stale, which removes the `LNK2019` class entirely rather
  than making it rarer.
- **The runtime library is pinned once** (`$CrtCl = '/MD'`) and applied to every
  TU, so a per-invocation flag difference cannot produce `LNK2038`.
- **A live binary is detected** and reported by PID rather than surfacing as
  `LNK1104`.
- **The output path is checked** — see section 4.
- **The linked output is verified to begin with `MZ`**, so a misdirected `/Fe`
  is caught after the fact as well as before.

Measured:

```ini
MSVC   = C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207
SDK    = 10.0.26100.0
CRT    = /MD
TUs    = 4  (gguf_loader, rawrxd_transformer, rawrxd_cpu_math, regime_sweep)
LINK_OK bytes=183296 magic=MZ
COMPILE_FAILED=0
LINK_FAILED=0
```

## 3. Flag-spelling defect found by the script itself

The first run of the script failed with:

```
LINK : fatal error LNK1104 : cannot open file
  'cl : Command line warning D9002 : ignoring unknown option '/MultiThreadedDLL' regime_sweep.cpp'
```

The CRT variable had been written in the CMake property spelling
(`MultiThreadedDLL`). `cl.exe` does not accept that form; it warns `D9002`,
ignores it, and then treats the following argument as an input file — so the
link was handed a filename assembled from the warning text. Fixed to `/MD`, with
a comment recording that the two spellings are not interchangeable.

## 4. Self-inflicted incident: a source file was overwritten by a linked binary

**`regime_sweep.cpp` was destroyed and recovered. This is recorded rather than
quietly repaired.**

Sequence:

1. The script captured compiler output in a variable named `$out`.
2. **PowerShell variable names are case-insensitive**, so `$out = & cl ...`
   silently overwrote the `$Out` *parameter*.
3. The link therefore ran as `cl ... /Fe:<the compiler's last echo line>`, and
   that echo line was the string `regime_sweep.cpp`.
4. `/Fe` names an output **path**. cl wrote the linked executable over the
   source file.

Measured damage:

```ini
BEFORE  regime_sweep.cpp  24516 bytes  first bytes 2F 2F 20 72   ("// r")
AFTER   regime_sweep.cpp 186368 bytes  first bytes 4D 5A 90 00   ("MZ" + DOS stub)
```

Recovery was possible **only because a derived copy happened to exist**
(`regime_sweep_d4096.cpp`, created earlier for an unrelated experiment). The file
was restored from it and the one post-copy edit re-applied. A guard that depends
on a lucky backup is not a guard, so two guards were added:

- **Pre-link:** refuse outright when the output path has a source extension
  (`.cpp .c .h .hpp .hxx .cc .asm .inc`), exit 4. Checked **before** the
  live-binary test — with a source path, `Get-Process` matches any running sweep
  by shared stem and would have reported "regime_sweep.cpp is running as PID…",
  which is true but names the wrong hazard.
- **Post-link:** assert the produced file begins with `MZ`, exit 5.

Both verified:

```
$ ... -Out regime_sweep.cpp
FAIL: refusing to link to 'regime_sweep.cpp'.
      That is a source extension. /Fe writes a BINARY at that path;
      a source file would be overwritten.
```

and afterwards `regime_sweep.cpp` is still 25631 bytes beginning `2F 2F 20 72`.

### Residual risk that remains

`regime_sweep.cpp` is **untracked** (`??` in `git status`). It is therefore not
recoverable from git; the derived copy was the only safety net, and there is no
second net now. Until it is committed, an equivalent clobber is a total loss.

## 5. Interaction with the concurrent editor

`src/rawrxd_cpu_math.cpp` was being edited by another session throughout this
build and was observed **mid-write** twice: once with
`last_total_rows_` / `last_chunk_` / `last_inlined_` referenced but undeclared
(`C2065`), and once with `GeometryForRequested` declared in the header but not
yet defined in the translation unit (`LNK2019`). Both resolved without action
once the writer finished.

This is a second argument for the always-recompile design: an object file
compiled from a half-written source is a hazard, and the canonical script reduces
the window by never reusing an object across invocations.

## 6. Explicitly NOT established

```ini
SWEEP_GATE_CERTIFICATION = NOT_ESTABLISHED
THREAD_SCALING_CURVE     = NOT_ESTABLISHED
BASE_DRIFT_CORRECTED     = MEASURED_PENDING (fix built, run not yet consumed)
```

This receipt covers the build. It makes no claim about any measurement the built
binary produces. The old speedup table remains discarded.