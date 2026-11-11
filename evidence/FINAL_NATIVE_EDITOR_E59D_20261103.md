# RawrXD Native Editor Final Candidate Receipt

Date: 2026-11-03

## Candidate authority

- Executable: `F:\rawrxd\build_repair_candidate\bin\RawrXD-Win32IDE-Native.exe`
- Size: `6,057,984` bytes
- SHA-256 before and after runtime testing: `E59D63212E4B2F111EB48A8CB727BE1E5078EFD890C5942A4AB106F4F0D85D14`
- Source commit containing the repair: `57f4dd1f056959ad541db626d3684152b17fd9fb`

## Automated verification

- Native candidate build: PASS
- CTest: `28` tests discovered, `27` passed, `1` intentional hardware-dependent test skipped (`deep2_h11_prefill_parity`), exit code `0`
- `git diff --check` for the repaired source: PASS

## Real Win32 editor verification

### Unicode save/reopen

- Native input used: `café`, `東京`, `🚀`, and CRLF sentinel lines.
- File Menu → Save: PASS.
- Expected and actual byte lengths: `102` / `102`.
- Exact byte comparison: PASS.
- Saved file SHA-256: `A9A80F611454813AC7E5C228BEAD633CE1E6B6E67AEE836E822DDE116B7FAC21`.
- Same candidate reopened the file and displayed the Unicode content: PASS.

### External-change protection

- External rewrite detected and prompt displayed: PASS.
- Choosing **No** preserved the current in-memory editor buffer: PASS.
- Choosing **Yes** reloaded the external file and displayed `FINAL_YES_SENTINEL`: PASS.
- External No file SHA-256: `B80B42205A366080C7DE70B1601B76CE911A572998A4FA275D16070D112FB844`.
- External Yes file SHA-256: `7A9252BB98A14B7E8F2D3501D9BB843DFC22D214079153522208E48D411419EA`.

### GhostText

- Real native editor and local Ollama route: PASS.
- Suggestion rendered in the editor surface: PASS.
- Tab acceptance: PASS.
- File Menu → Save after acceptance: PASS (`File saved`).
- Accepted completion persisted once; the marker count was `2` total (one original source marker plus one accepted completion).
- Saved GhostText fixture SHA-256: `CE2A59F6A5C236F783E50C5276F5F3BEA5F6A7F0D624021308249430A5D52028`.

## Explicitly not claimed by this receipt

- This receipt does not certify current-candidate ChatWindow, Token64, cancellation, or stale-GhostText rejection; those require fresh same-SHA product runs.
- It does not promote or replace the active production executable.
- Generated build output, runtime ledgers, and disposable fixtures remain outside the source commit.
