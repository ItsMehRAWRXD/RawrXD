# Current-build GhostText A/B identity

- Worktree: `F:\rawrxd`
- Executable: `F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe`
- SHA-256: `3D02CA3C01D21FFBD4392FD2A3673826D6883B31143289E31284ECA55930D704`
- Test environment: `RAWRXD_GHOSTTEXT_TEST_DELAY_A_MS=5000`, `RAWRXD_GHOSTTEXT_TEST_DELAY_B_MS=50`
- Model selected through the native UI: `Local models / Ollama / qwen3:8b`
- Cloud GhostText consent: disabled

The binary was rebuilt from the active F:\rawrxd checkout and remained stable during bounded startup and the physical UI run.

## Rebuilt repair candidate
- SHA-256: `B527091A5E073AF817C94E73B17C8FFAE3BF42B0EFED04489C1FD441208AB7BE`
- Rebuild result: PASS
- Bounded startup: PASS
- Normal close: PASS

## Subsequent source-identical rebuild
- SHA-256: `28124CD278C1E6457CD1CF47D6B777AC0B9FAFF6469E3BA04DDA8C76523894D8`
- Size: `1,731,072` bytes
- Build result: PASS
- Physical GhostText execution: NOT RUN for this hash
- Authority note: evidence from `B527091A...` is not transferred until this exact binary is physically retested.
