# Unweightless reverse-engineering boundary

The production bridge is suspended by absence and policy, not by deleting or replacing model data.

The current checkout contains no `Unweightless` encoder, serialized artifact format, reconstruction routine, or `Unweightless -> ROM` dispatch. The only weightless surface found is `HexMag::CandidateSource::W0`, which is an orphaned candidate-only control-plane source excluded from active targets and is not a tensor or ROM path.

The W0 source is not activated as part of this investigation. Deep2 GGUF loading, packed quantization, Vulkan kernels, ROM-like assets, and normal IDE inference do not depend on it.

Run the read-only inventory with:

```powershell
pwsh -File tools/unweightless_bridge_audit.ps1 -RepoRoot . -OutputPath evidence/unweightless_audit.json
```

The audit emits U1 through U6 without upgrading missing evidence into a pass. U1 is partial when weightless control-plane references are found; U2 through U6 remain blocked until an actual encoder/decoder artifact and an independent parity oracle exist.

## Evidence boundary

- Original GGUF and quantized weights are preserved.
- Production Deep2 and Vulkan dispatch remain unchanged.
- No automatic reconstruction or ROM integration is enabled.
- Candidate text is never promoted to final authority by the orphaned W0 source.
