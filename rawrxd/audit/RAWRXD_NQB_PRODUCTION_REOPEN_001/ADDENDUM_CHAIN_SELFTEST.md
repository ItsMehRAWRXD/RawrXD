# RAWRXD_NQB_CHAIN_SELFTEST_001 — fast rehearsal of the whole certification chain

```ini
GATE=RAWRXD_NQB_CHAIN_SELFTEST_001
FAILURES=0
VERDICT=PASS
EXIT=0
```

## Why this exists

Every measurement of the real 12.85 GB artifact costs ~90 s of conversion plus
~130 s of verification and needs the model present. That is the right cost for a
real claim and the wrong cost for answering "did my edit break the chain?".

`tools/raqrxd_nqb_chain_selftest.ps1` runs the identical chain against
`src/core/test_tiny_with_vocab.gguf` — 21 tensors, 363,456 bytes — in under two
seconds, exercising every link that can silently break:

```text
converter    transactional write, provisional header, census accumulation,
             derived bitsPerWeight, codec census, vocab domain derivation,
             verdict, atomic promote
reopen gate  reverse footer chain, exact byte coverage, per-tensor digests,
             whole-file SHA-256, production F32 reader path, negative controls
comparator   name-keyed join, geometry, both digests, manifest root,
             conservation, negative controls
```

It asserts `NO_BUILDING_FILE_AFTER_PROMOTE`, so a regression that promotes a
half-written container fails the rehearsal.

```ini
SCOPE=INSTRUMENT_WIRING_ONLY
NOT_CLAIMED=ANYTHING_ABOUT_THE_REAL_12.85GB_ARTIFACT
```

21 tensors of a synthetic fixture cannot speak for 3,212,749,888 elements of
llama3.2-3b. The only claim is that the instruments are still wired to each
other and still able to fail.

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\raqrxd_nqb_chain_selftest.ps1 `
  -Bin <dir holding the built instruments>
```

## What fixing it uncovered

The rehearsal only became possible after three real fixes.

### 1. The converter refused to promote anything small

`test_tiny_with_vocab.gguf` carries **2 tokens against a 64-row embedding**:

```ini
ARCH_META vocabSize_from_metadata=0 vocabSize_from_token_array=2
TENSOR=token_embd.weight elements=4096 hidden=64   -> 64 rows
FAIL=EMBED_ROWS_VOCAB_SIZE_DISAGREE
```

`vocabSize` was taken from the token array whenever the metadata key was absent.
On a real llama model the two are equal, so that was never exercised. Here the
converter believed a 2-entry stub, wrote `vocabSize=2`, and then failed its own
consistency check. Correct outcome, wrong reasoning: it shrank the domain to
match the **less** authoritative input instead of taking the domain from the
thing that actually bounds addressable ids.

`NQB_INVARIANT_TOKEN_DOMAIN_001` runs one way only — a token id must have an
embedding row — so the embedding is the authority and the token array is a
possibly-incomplete label set over it. A shorter array is a source-data gap to
report; a longer one is the violation.

```ini
VOCAB_DOMAIN embed_rows_from_index=64 token_array=2 metadata_vocab=2
VOCAB_DOMAIN_CORRECTED from=2 to=64 source=embedding_rows
VOCAB_ARRAY_SHORTER_THAN_DOMAIN array=2 domain=64
FAILURES=0  VERDICT=PASS  PROMOTED_TO=…  TRANSACTIONAL_WRITE=1
```

The embedding shape now comes from the loader index **before** anything is
written. `archMeta` is emitted inside `open()`, so it was previously finalised
before the tensors that constrain it had been read — the same ordering defect
that let `paramCount` ship as 0.

(The writer's own domain check was already correct — `tokens.size() > vocabSize`
is the violation. I misread it as inverted and did not change it.)

### 2. The harness died before reading an exit code

`$ErrorActionPreference = 'Stop'` plus a native tool that writes receipts to
stderr makes PowerShell raise a **terminating** error on the first line of
output. The harness never reached an exit code. Native stderr is data here; the
exit code is the authority.

### 3. The harness reported FAIL on a passing comparator

```ini
COMPARATOR_SHA_ALL_MATCH  FAIL     <- FNV matched, root matched, MISMATCHES=0
```

`SHA256_MATCH` is the **last** field on the line and the pattern demanded a
trailing space, so it could never match. That is the same defect class as the
comparator's false FAIL earlier in this session: an instrument reporting failure
where the target passed. A harness that cannot be trusted to pass is not a
harness.

## State

```ini
NQB_CHAIN_SELFTEST=                    PASS
NQB_CHAIN_SELFTEST_RUNTIME=            <2s on a 363,456-byte GGUF
NQB_CONVERTER_SMALL_MODEL_PROMOTE=     PASS
NQB_VOCAB_DOMAIN_SOURCE=               EMBEDDING_ROWS
NQB_VOCAB_DOMAIN_CROSSCHECK=           REPORTED_NOT_REPAIRED

BUILD_AUTHORITY
    CMAKE_CONFIGURE=PASS
    INFERENCEENGINE_BUILD=PASS         (-j1; -j6 exhausts RAM on 63GB)
    CONVERTER_BUILD=PASS
    NQB_INSTRUMENTS_BUILD=PASS
    BUILT_BINARY_EXECUTES=PASS
```