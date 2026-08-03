# RawrXD Evidence Pipeline - Quick Reference

## 🚀 Quick Start

```powershell
# 1. Build in Release mode
cmake --build build --config Release

# 2. Verify compliance
.\scripts\Verify-SovereignCompliance.ps1

# 3. Check evidence
ls build\evidence\
```

---

## 📦 Evidence Artifacts (7 Files)

| File | Purpose | Verification Command |
|------|---------|---------------------|
| `binary_hash.txt` | SHA256 reproducibility | `Get-FileHash build\bin\RawrXD-Win32IDE.exe` |
| `compiled_sources.txt` | Source inventory | `Get-Content build\evidence\compiled_sources.txt` |
| `linked_libraries.txt` | Linker memory scan | `dumpbin /LINKERMEM:FULL build\bin\RawrXD-Win32IDE.exe` |
| `binary_imports.txt` | DLL import table | `dumpbin /IMPORTS build\bin\RawrXD-Win32IDE.exe` |
| `architecture_report.json` | PE metadata | `Get-Content build\evidence\architecture_report.json \| ConvertFrom-Json` |
| `dependency_manifest.json` | Compliance status | `(Get-Content build\evidence\dependency_manifest.json \| ConvertFrom-Json).compliance_status` |
| `benchmark_metadata.json` | Benchmark reproducibility | `(Get-Content build\evidence\benchmark_metadata.json \| ConvertFrom-Json).results.tokens_per_second` |

---

## ✅ Verification Gates (7 Checks)

| Gate | Name | Pass Condition |
|------|------|----------------|
| 1 | Binary Hash | Hash matches stored value |
| 2 | Source Inventory | No integration patterns (`_bridge`, `_adapter`) |
| 3 | Dependency Manifest | `compliance_status == "PASS"` |
| 4 | Import Table | No prohibited DLLs |
| 5 | Architecture Report | SHA256 present, size valid |
| 6 | Benchmark Metadata | Hardware/software info complete |
| 7 | Linked Libraries | No prohibited libraries |

---

## 🔍 Common Checks

### Check for Prohibited Dependencies
```powershell
$manifest = Get-Content build\evidence\dependency_manifest.json | ConvertFrom-Json
if ($manifest.prohibited_dependencies.Count -gt 0) {
    Write-Host "FAIL: $($manifest.prohibited_dependencies -join ', ')" -ForegroundColor Red
} else {
    Write-Host "PASS: Zero prohibited dependencies" -ForegroundColor Green
}
```

### Verify Binary Hash
```powershell
$stored = Get-Content build\evidence\binary_hash.txt
$computed = (Get-FileHash build\bin\RawrXD-Win32IDE.exe -Algorithm SHA256).Hash
if ($stored -eq $computed) {
    Write-Host "✓ Binary verified" -ForegroundColor Green
} else {
    Write-Host "✗ Hash mismatch!" -ForegroundColor Red
}
```

### Count Sovereign Sources
```powershell
$sources = Get-Content build\evidence\compiled_sources.txt | Where-Object { $_ -notmatch '^#' -and $_ -ne '' }
$sovereign = $sources | Where-Object { $_ -match 'sovereign_|native_|direct_|rawr_' }
Write-Host "Sovereign files: $($sovereign.Count) / $($sources.Count)"
```

### Check Benchmark Results
```powershell
$bench = Get-Content build\evidence\benchmark_metadata.json | ConvertFrom-Json
Write-Host "TPS: $($bench.results.tokens_per_second)"
Write-Host "Build: $($bench.build_info.sha256)"
```

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| Evidence directory missing | Build in **Release** mode, not Debug |
| Hash mismatch | Binary modified post-build, rebuild |
| Prohibited dependencies found | Remove llama.cpp/ggml from CMakeLists.txt |
| Benchmark shows PENDING | Run benchmark executable to populate results |
| Verification gate failed | Check specific error message, fix root cause |

---

## 📊 CI/CD Integration

### GitHub Actions
```yaml
- name: Build Release
  run: cmake --build build --config Release

- name: Verify Sovereignty
  run: .\scripts\Verify-SovereignCompliance.ps1

- name: Upload Evidence
  uses: actions/upload-artifact@v4
  with:
    name: evidence-${{ github.sha }}
    path: build/evidence/
```

### Azure DevOps
```yaml
- script: cmake --build build --config Release
  displayName: 'Build Release'

- script: powershell -ExecutionPolicy Bypass -File scripts/Verify-SovereignCompliance.ps1
  displayName: 'Verify Sovereign Compliance'

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: 'build/evidence'
    artifactName: 'sovereign-evidence'
```

---

## 🔐 Security Checklist

- [ ] Verify SHA256 hash before running binary
- [ ] Audit import table for unexpected DLLs
- [ ] Check `compliance_status == "PASS"` in dependency manifest
- [ ] Archive evidence for each production release
- [ ] Compare evidence across builds for regression detection

---

## 📈 Performance Tracking

### Track Binary Size Over Time
```powershell
$history = @()
Get-ChildItem build\evidence\architecture_report.json | ForEach-Object {
    $report = Get-Content $_.FullName | ConvertFrom-Json
    $history += [PSCustomObject]@{
        Date = $report.timestamp
        SizeMB = [math]::Round($report.size_bytes / 1MB, 2)
        Hash = $report.sha256
    }
}
$history | Sort-Object Date | Format-Table
```

### Track TPS Over Time
```powershell
$bench = Get-Content build\evidence\benchmark_metadata.json | ConvertFrom-Json
Write-Host "Current TPS: $($bench.results.tokens_per_second)"
# Compare against baseline (e.g., 241.88 TPS)
if ($bench.results.tokens_per_second -lt 220) {
    Write-Host "⚠️ Performance regression detected!" -ForegroundColor Yellow
}
```

---

## 📚 Documentation

- **Full Guide**: `docs/EVIDENCE_PIPELINE.md`
- **Spec**: `SOVEREIGN_IMPLEMENTATION_STACK.md`
- **Review**: `SOVEREIGN_SPEC_REVIEW_SUMMARY.md`
- **Script**: `scripts/Verify-SovereignCompliance.ps1`

---

## 🎯 Key Invariant

```
Claim → Artifact → Verifier
```

**Never**: `Claim → Trust`

Every sovereignty claim must be backed by:
1. **Artifact**: Build-generated evidence file
2. **Verifier**: Automated script that checks the artifact
3. **Reproducibility**: Independent parties can verify

---

*Quick Reference v1.0 • 2026-08-03*
