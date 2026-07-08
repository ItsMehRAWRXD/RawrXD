# RawrXD Symbol Governance Manifesto

## The Real Problem (Not Linker Errors)

You just experienced the symptom:

```
LNK1120: 341 unresolved externals  →  Add stubs
LNK2005: duplicate symbols           →  Remove stubs
Build succeeds                       →  System "works"
```

But the **root cause** is:

> **Unstructured symbol ownership across a large build graph**

## What Actually Happened

### Phase A: False Root Cause
- "341 unresolved externals"
- Interpreted as missing implementations

### Phase B: Synthetic Patch
- Created stub implementations
- `link_closure_stubs.cpp`
- `unresolved_stubs_production.asm`

### Phase C: Second-Order Failure
- Those stubs **already existed elsewhere**
- Produced: `LNK2005 duplicate symbols`

### Phase D: Resolution by Removal
- Deleted conflicting stubs
- Restored consistency of symbol space
- Build succeeds

## The Pattern You Must Recognize

Your system oscillates between:

```
"Fix compilation"  →  add stubs
     ↓
"Fix linkage"      →  remove stubs
     ↓
"Fix again"        →  discover hidden duplicates
     ↓
(repeat)
```

This is a **feedback loop caused by missing ownership rules**, not missing code.

## The CoreRuntime Solution

CoreRuntime is not just a smaller build. It is a **symbol governance boundary**.

### What CoreRuntime Enforces

| Rule | Enforcement |
|------|-------------|
| Single definition per symbol | CMake validation + compile-time guards |
| Explicit ownership | `symbol_ownership.h` domain macros |
| No UI contamination | Header guards that `#error` on violation |
| No stub fallbacks | `RAWRXD_ALLOW_STUBS` blocked in Core builds |
| Truth baseline | CoreRuntime-Test validates correctness |

### Symbol Domain Matrix

```
┌─────────────────┬──────────────────────┬────────────────────────┐
│ Domain          │ Symbol Prefix        │ Implementation         │
├─────────────────┼──────────────────────┼────────────────────────┤
│ CoreRuntime     │ InferenceEngine_*    │ src/inference/         │
│                 │ GGUFLoader_*         │ src/gguf/              │
│                 │ CoreMemory_*         │ src/memory/            │
├─────────────────┼──────────────────────┼────────────────────────┤
│ ASM Kernels     │ asm_*                │ src/asm/ (prebuilt)    │
├─────────────────┼──────────────────────┼────────────────────────┤
│ UI Layer        │ Win32IDE_*           │ src/win32app/          │
│                 │ UI_*                 │ src/ui/                │
├─────────────────┼──────────────────────┼────────────────────────┤
│ Debug Only      │ Stub_*               │ tests/ (never release) │
└─────────────────┴──────────────────────┴────────────────────────┘
```

## The Key Insight

> Your system is already *functionally complete*, but not *structurally separable*

This is a very different class of problem.

### Before CoreRuntime
- Missing externals = structural gaps
- Duplicate symbols = governance failure

### After CoreRuntime
- Missing externals = real work needed
- Duplicate symbols = impossible (enforced by build)

## Build Target Hierarchy (Clean)

```
RawrXD-CoreRuntime (STATIC)
    ├── No dependencies on UI/IDE
    ├── Real implementations only
    └── Truth baseline for system

RawrXD-Win32IDE (EXECUTABLE)
    ├── Links CoreRuntime
    ├── Adds UI layer
    └── Cannot contaminate Core

RawrXD-Gold (EXECUTABLE)
    ├── Links CoreRuntime
    ├── Adds legacy modules
    └── Must respect Core boundaries
```

## Migration Checklist

### Phase 1: CoreRuntime Extraction ✓
- [x] Create `cmake/CoreRuntime.cmake`
- [x] Define `RawrXD-CoreRuntime` target
- [x] Create `symbol_ownership.h` guards
- [x] Implement `inference_engine.cpp` (real code)
- [x] Create `test_inference_loop.cpp` (truth baseline)

### Phase 2: Build Validation
- [ ] `cmake --build . --target RawrXD-CoreRuntime`
- [ ] Verify < 2 minute build time
- [ ] `cmake --build . --target RawrXD-CoreRuntime-Test`
- [ ] Verify all tests pass

### Phase 3: Dependency Revelation
- [ ] Compare Core deps vs full build deps
- [ ] Document hidden coupling
- [ ] Fix accidental includes
- [ ] Enforce `RAWRXD_DOMAIN_*` macros

### Phase 4: Capability Gating
- [ ] Make UI depend on Core (not reverse)
- [ ] Remove stub generation from release
- [ ] Add compile-time feature switches
- [ ] Document symbol ownership rules

## The Discipline

### What CoreRuntime Must NOT Include

- ❌ Win32IDE / UI layer
- ❌ Codex / dialogs / panels
- ❌ QuickJS / scripting layer
- ❌ Marketplace / plugins
- ❌ Agent UI bridge
- ❌ Visualization / rendering
- ❌ Optional experimental engines

### Rule

> If it's not required to run a model → graph → execution → memory loop, it does not belong in CoreRuntime.

## Success Criteria

- [ ] CoreRuntime builds in < 2 minutes
- [ ] CoreRuntime-Test passes without UI deps
- [ ] Win32IDE links against CoreRuntime (no duplicates)
- [ ] No LNK2005 errors in any configuration
- [ ] Adding UI feature doesn't rebuild Core
- [ ] Symbol ownership is documented and enforced

## The Bottom Line

You just completed a transition:

### Before
> "Fix missing externals"

### After
> "Resolve conflicting definitions in an ungoverned symbol space"

That is a **much more advanced class of build system problem**.

CoreRuntime is the solution. It provides:

1. **Symbol governance** (who owns what)
2. **Build isolation** (fast iteration)
3. **Truth baseline** (Core works = system works)
4. **Architectural clarity** (forced boundaries)

## Next Action

Run the CoreRuntime build:

```bash
cd d:\rawrxd\build-ninja
cmake --build . --target RawrXD-CoreRuntime
cmake --build . --target RawrXD-CoreRuntime-Test
.\tests\core_runtime\RawrXD-CoreRuntime-Test.exe
```

If this passes, you have a **governed system**.
If this fails, you have **real work to do** (not linker noise).

That is the upgrade.
