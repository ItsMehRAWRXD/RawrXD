# RAWRXD Disaster-Recovery Backup Snapshot — 2026-10-12

**Purpose:** full insurance snapshot of `F:\rawrxd` in case this hard drive fails.
Everything that fits within GitHub's limits is on GitHub in the repo
**`ItsMehRAWRXD/everything`** (created private — flip public with
`gh repo edit ItsMehRAWRXD/everything --visibility public --accept-visibility-change-consequences`).

---

## 1. What this snapshot is

- **Repo base:** branch `tmp-rebase` at commit `3e0f05027b` ("feat(deep2): make teacher-forced comparison against llama.cpp possible"), which was 7 commits ahead of `origin/feat/gpu-quant-dot`.
- **Snapshot commit:** the commit containing **this very file** — 223,341 files,
  +26,329,812 / −557 lines versus the base tip, ~3.0 GB of raw content (pack transfer smaller).
  Run `git log --format='%H %s' -1` on `main` of the backup repo to identify it exactly.
- **Contents:** every tracked modification, every untracked-but-not-ignored file,
  the full `recovery/` exports (stash patches in `recovery/stashes/`, nested-repo history bundles
  in `recovery/nested-repos/`, the cannot-fit file list in `recovery/cannot_fit_exclusions.txt`),
  plus all 16 local branches, all tags, and all 11 stash commits pushed as `recovery/stash-*` refs.
- Documented generation tooling lives in `tools/` and `docs/` (e.g. `tools/verify_e2e_cert.py`,
  `tools/deep2_full_forward_profile.cpp`, evidence harnesses under `src/deep2/`), which is what
  produced the excluded bulk payloads below.

## 2. Pre-flight repairs applied before committing

1. **Degenerate rebase state cleared** — `.git/rebase-merge` existed (branch reported
   "currently rebasing") but contained only an `autostash` file, no todo/onto/head-name:
   an interrupted rebase whose work was already committed (tip was the final commit).
   The stale state file was removed; no commits were lost or rewritten.
2. **Dangling autostash applied** — `46eace849f` ("On ci/github-control-loop-001: autostash",
   gated `include/gguf_loader.h` to not require the full Vulkan SDK / Qt) existed nowhere in any
   worktree or stash list. Applied to the worktree and committed in the snapshot.
3. **Sibling worktrees committed** (separate checkouts, same .git):
   - `F:\rawrxd\.kilo\worktrees\thorn-measure` → branch `thorn-measure`, commit `d9c664b95b`
     (35 files, +9,428/−969 — CanonicalTokenizer, CPU-Vulkan compute stubs, ggml headers).
   - `F:\rawrxd_cert` → branch `feat/hexmag-polymorphic-repeat-tuner-masm`, commit `9d91af0237`
     (36 files, +5,296/−295 — AgentLoop/ToolRegistry headers, compression-recovery backups).
   - `F:\rawrxd-main-audit` was clean; its branch `audit/ide-authority-closure-001` carries all
     content already.

## 3. Included — top-level map of the snapshot

| Area | Role |
|---|---|
| `src/` | Engine, IDE, agentic, deep2 (DeepSeek2/K2 runtime), inference, kernels, win32app — the actual product source |
| `docs/`, `src/*.md` | ~800+ working docs, gap analyses, phase manifests, Architecture notes |
| `include/`, CMake*, `*.ps1` (root) | Build/runtime scripts and headers (hundreds: build, smoke, telemetry, gateway) |
| `tools/` | Forensic/comparison tooling (Python/C++), shader sources |
| `evidence/` | Certification receipts, E2E evidence, milestone JSON/MD (small-scale receipts kept; see §5) |
| `recovery/` | **This recovery kit** (stash patches, bundles, exclusion list) |
| `Full_Source/`, `Full Source/`, `.archive/` | Snap/copies and archives of earlier source states |
| `OrganizedPiProject/`, `itsmehrawrxd-master/`, `reconstructed/`, `3rdparty/` | Sub-projects and vendored trees (see §6) |
| `build_*`, `_e2e`, `_final_build`, `tmp_*`, `dist/`, `release(s)/` | CMake build trees, logs, packaged releases and hard evidence of builds |
| `web-test/`, `bigdaddyg-ide/` | Web/Electron companion UIs incl. node_modules |

## 4. Stashes — all 11 preserved twice

Each stash exists as (a) a pushed **ref `recovery/stash-N`** (full object: index tree +
untracked-files third parent where present) and (b) a patch file in `recovery/stashes/`
(index of both: `recovery/stashes/STASH_INDEX.md`).

Restore one: `git fetch the-remote recovery/stash-7 && git stash apply FETCH_HEAD`
(the commit ids, bases and sizes are listed in STASH_INDEX.md; stash-10 is 195.7 MB of diff and
was split as `stash-10-*.patch.part000..002`).

## 5. Nested git repositories — histories saved as bundles

Their `.git` dirs were **moved** (not deleted) to `F:\rawrxd-quarantine-nested-gits`
(each kept as `<name>.git`, e.g. `_tmp_llama-clone.git`) so their FILES could be committed as
plain files (gitlinks would otherwise render as empty folders on GitHub — content would be lost).

Bundles (full clone-able history, `recovery/nested-repos/`), restore: `git clone <file>`:

| Repo | Bundle size |
|---|---|
| `quickjs`, `quickjs_ng`, `copilot-ollama`, `cloud-hosting` | 0.6 / 0.8 / 0.1 / 0.15 MB |
| `Star5IDE` | 9.5 MB |
| `SaaSEncryptionSecurity` | 8.7 MB (also recoverable from its own GitHub; its 106 dirty files are IN this snapshot) |
| `src-asm` | 74 MB (history exists nowhere upstream) |
| `tmp_llama-clone` | 37 MB (full llama.cpp clone history; also at github.com/ggml-org/llama.cpp) |
| `itsmehrawrxd-master` | **no commits existed** (nothing to save) |

## 6. What cannot fit on GitHub — everything else is regenerable or oversized

1. **Hard limit (100 MB/file) violations — 8 untracked singles:**
   `tmp_model-00001-of-000004.safetensors` (8.2 GB), `tmp_safetensors/` (4 shards, 30 GB),
   `ipc_results.csv` (556 MB), `Full_Source/reports/todo-scan-20260126-065921.json` (262 MB),
   `.archive/.../Powershield_Audit_Report.json` (191 MB), `mul_mm.comp.cpp` ×3 (123 MB each,
   machine-generated Vulkan shader C++ in build trees `_e2e/_final_build/build_vs`).
2. **Evidence tensor-dump blobs >1 MB** inside `evidence/RAWRXD_REFERENCE_REPRODUCIBILITY_001/`
   (12.53 GB / 5,131 files) and `evidence/RAWRXD_CORE_DLL_NATIVE_E2E_001/` (7.78 GB / 3,186 files) —
   regenerable dumping runs (~2.4 MB intermediate .f32/.bin/logit dumps each; produced by the
   harness scripts under `tools/` + `src/deep2/` tests using the model files in §7).
   **All smaller receipts inside those dirs were kept** (65,137 files, 0.72 GB).
3. The exact file list of both categories is committed at **`recovery/cannot_fit_exclusions.txt`**.

## 7. Already-gitignored (never part of git) — regenerable model weights

`models/` (170 GB), root `*.gguf` (incl. `dummy_200b.gguf` 400 GB dummy, `DeepSeek-V2-Lite*`,
`llama3.2*`, `phi3*.gguf`), `model_solo/`, `bench_frag.gguf`, `*.exe/*.dll/*.pdb/*.obj/*.lib` in
build trees, `.kilo/worktrees/` (10 GB of workspace files — its real content is the pushed
branch `thorn-measure`). Weights come from public HuggingFace model repos (DeepSeek-V2-Lite-Chat,
Qwen2.5-Coder-1.5B, TinyLlama-1.1B-Chat, Phi-3-mini, Llama-3.2-3B, Gemma-3, StarCoder2-15B,
DeepSeek-Coder-V2-16B, Nemotron milestones, Kimi-K2, GPT-OSS, Codestral-22B, Ormith-1.5-35B);
`models/` and `models-mnt/` mappings are referenced in `docs/` and `src/deep2/` loader code.

## 8. Branch inventory at snapshot time (16 branches, all pushed)

```
2026-02-12-nsh4                    362d5c550e
audit/ide-authority-closure-001    a0c98e7fb1  (worktree F:/rawrxd-main-audit)
b004-validate-isolated             ed12e302e8
ci/github-control-loop-001         86869bd301  (behind origin by 9)
ci/ide-native-build-local          80dcfd1b08
feat/gpu-quant-dot                 61449fe742  (ahead 33 / behind 26 of origin)
feat/hexmag-polymorphic-repeat-tuner-masm 9d91af0237 (+backup commit today)
feat/modelgenie-executionir-mainline 78be7274c4
main                               78be7274c4  (ahead 3106 / behind 3173 of origin/main — divergent; keep both)
master                             052fbd54fe  (ahead 72 / behind 1)
pr37/ci-hygiene                    33e71d5d11
production-lazy-init               4c8b2fa537
promote/hexmag-p1-ide-product      3c92b781bd  (ahead 4176 / behind 4028)
ssm-nemotron-h                     d13897ce0e
thorn-measure                      d9c664b95b  (worktree F:/rawrxd/.kilo/worktrees/thorn-measure, +backup commit today)
tmp-rebase  <- SNAPSHOT SOURCE     3e0f05027b + snapshot commit (pushed as main of the backup repo)
```

Remotes of the original repo: `origin` = RawrXD/RawrXD, `closure-origin` =
RawrXD/RawrXD-IDE-Win32-Gui-CLI-HTML, `final` = RawrXD/RawrXD-IDE-Final.
The backup repo `ItsMehRAWRXD/everything` is registered as remote **`everything`**.

## 9. Restore runbook

1. `git clone https://github.com/ItsMehRAWRXD/everything.git` → default branch `main`
   = the full snapshot worktree (including `recovery/`).
2. Branches: `git branch -a` all 16 exist; `git checkout <branch>` for any.
3. Stashes: per §4 (`git stash apply FETCH_HEAD`).
4. Nested histories: per §5 (`git clone recovery/nested-repos/<name>.bundle`).
   The quarantined original `F:\rawrxd-quarantine-nested-gits\*.git` dirs (if the drive survived)
   just need to be moved back next to their files and named `.git`.
5. Weights / excluded dumps: re-download from HF (§7) and re-run the harness scripts (§1/§6).
6. Windows note: `git config --global core.longpaths true` is REQUIRED (paths >260 chars exist).

## 10. Known tail risks (documented for honesty)

- Unreachable/dangling git objects (never referenced by any ref/stash) were **not** audited
  (`git fsck --lost-found` was skipped for haste).
- NTFS-level metadata (timestamps, ADS streams, NTFS ACLs) is not captured by git by design.
- Excluded payloads (§6) exist ONLY on this drive + regenerable sources.
- The two sibling worktrees outside `F:\rawrxd` (`F:\rawrxd-main-audit`, `F:\rawrxd_cert`) are
  versioned via their branches; their working-tree files are not duplicated into this snapshot.

— Generated during the disaster-backup session of 2026-10-12.
