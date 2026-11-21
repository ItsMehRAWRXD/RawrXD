# Commit d701f95f47 — ownership audit — 2026-11-21

## What was intended

Four capability values in `buildBackendRegistry()` changed from `rawrxd::Support::Verified`
to `Unverified` for the Ollama row, because no adapter-level test exists:

```
ollama  ollama  unavailable  unverified  unverified  unverified  unverified  yes
```

Verified on the rebuilt CLI: `rawr.exe` SHA-256
`C8DC5DB72387DA180FC77E42E693FF324B5866C5A4C368E6AD8AC0C871A1252C`, `rawr backend status`
exit 0.

## What else the commit contains (not authored in that sprint)

The commit is 152 insertions / 25 deletions in one file, so it bundled
**pre-existing uncommitted changes** that were already in the working tree. Hunk
classification from `git show d701f95f47 -- src/rawr_cli.cpp`:

| Hunk | Content | Classification |
|---|---|---|
| `@@ -308` / `@@ -345` / `@@ -886` (`runAgentLoop`) | structural-claim detection: `kStructural`, negation handling, `claimsRepair`, `claimsExecution`, `hasOkReceipt(...)`, `ungroundedRepair`, `ungroundedExec`, `noReceipts` | Peer work — rejects ungrounded repair/execution claims |
| `@@ -1703` / `@@ -1743` / `@@ -1793` (`cmdAsk`) | single effective-backend resolution: `askBackend` parsed once; explicit `--backend=ollama` no longer discarded by re-reading the persisted preference; route derived from the same resolved value (`InferenceEndpoint{11434,"ollama",true}`) | Peer work — this is the **D5 backend-override fix** |
| `@@ -3038` (`buildBackendRegistry`) | Ollama capabilities → `Unverified` + explanatory comment | **This sprint** |

## Assessment

- The bundled changes are **not random or unrelated**: they correspond to the D5
  backend-override fix and the ungrounded-claim checks described in earlier sprints,
  i.e. intentional peer work that had not been committed when I staged the file.
- They were **not reviewed line-by-line by me**, and the combined file has only been
  validated by a successful build plus `rawr backend status` (exit 0). The `cmdAsk`
  and `runAgentLoop` paths were **not** exercised in this session.
- The commit is pushed; history was deliberately **not** rewritten.

## Follow-up required

1. The owner of the D5/`runAgentLoop` work should review what landed in
  `d701f95f47` and confirm nothing was lost or altered by the staging.
2. Before release, `cmdAsk` routing (`--backend=strata|ollama|deep2`, persisted
  preference, no silent fallback) and `runAgentLoop` claim-grounding need their own
  runtime acceptance; a green build is not evidence.
3. Staging discipline: use `git add -p`, then `git diff --cached` before every
  commit on files with multiple contributors.

## Non-claims

This audit classifies the diff by symbol and hunk. It does not certify the behaviour
of the bundled peer changes.