# Rollback — Daily driver freeze 71D14597

## Restore frozen EXE
1. Stop all RawrXD-Win32IDE-Native processes.
2. Copy `bin\RawrXD-Win32IDE-Native.exe` from this package over:
   `F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe`
3. Verify: `Get-FileHash ... -Algorithm SHA256` == `71D1459754830B5987E2291CE2FA43E3A8B6900F27AC1997A8B4D9F7B523CE05`

## Roll back to prior candidate (18FA)
1. Prior SHA: `18FA04F9CAA2BC762279DE7C1AC30DEEBD83D357BCD0133ABFEC2F043E531E68`
2. If `*.prior_*.bak` exists under build_progression_finish25\bin, restore that file and re-hash.
3. Else rebuild historical tip from evidence seal; do not invent PASS on unverified binary.

## Law
PROMOTE=0 · CERTIFIED=0 · NOT_RUN!=PASS · FINISH_25_PASS=19 controlling untouched
