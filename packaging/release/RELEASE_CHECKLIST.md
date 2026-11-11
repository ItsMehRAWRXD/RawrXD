# RawrXD Sovereign Release Checklist

## Phase F.1 Batch 5/5: Production Release Checklist

### Pre-Release Verification

- [ ] All tests passing (`ctest --output-on-failure`)
- [ ] Benchmark suite runs successfully
- [ ] Security scan passes (`verify_release.ps1`)
- [ ] Documentation updated
- [ ] CHANGELOG.md updated with release notes

### Version Bump

```powershell
# Bump version (patch, minor, major, or prerelease)
.\packaging\release\version_manager.ps1 -Bump patch -CreateTag -Push

# Or for prerelease
.\packaging\release\version_manager.ps1 -Bump prerelease -PrereleaseLabel "beta1" -CreateTag
```

### Build & Package

```powershell
# Create complete release package
.\packaging\release\create_release_package.ps1 `
    -Version "1.0.1" `
    -BuildDir ".\build" `
    -OutputDir ".\releases" `
    -SignBinaries `
    -CertificateThumbprint "YOUR_THUMBPRINT" `
    -CreateInstaller `
    -GenerateReleaseNotes
```

### Sign Binaries

```powershell
# Windows signing
.\packaging\security\sign_and_verify.ps1 `
    -BinaryPath ".\releases\v1.0.1\windows-x64\rawrxd.exe" `
    -CertificateThumbprint "YOUR_THUMBPRINT" `
    -CreateChecksums

# Linux/macOS signing
export GPG_KEY_ID="your-key-id"
.\packaging\security\gpg_sign.sh sign ./releases/v1.0.1/linux-x64
```

### Verify Release

```powershell
# Complete verification
.\packaging\security\verify_release.ps1 `
    -ReleaseDir ".\releases\v1.0.1\windows-x64" `
    -ExpectedVersion "1.0.1" `
    -VerifySignatures `
    -VerifyChecksums `
    -TestInstallation `
    -GenerateReport
```

### Run Benchmarks

```powershell
# Quick validation
.\packaging\benchmark-execution\benchmark_runner.ps1 -Backend sovereign -Quick

# Full benchmark suite
.\packaging\benchmark-execution\benchmark_runner.ps1 `
    -Backend both `
    -Model "phi-3-mini-Q4" `
    -OutputDir ".\reports" `
    -GenerateDashboard `
    -ExportCSV
```

### Create GitHub Release

1. Push tag to trigger workflow:
   ```bash
   git push origin v1.0.1
   ```

2. Or manually create release with artifacts:
   ```powershell
   gh release create v1.0.1 `
       --title "RawrXD Sovereign v1.0.1" `
       --notes-file ".\releases\v1.0.1\RELEASE_NOTES.md" `
       ".\releases\v1.0.1\*.zip" `
       ".\releases\v1.0.1\*.msi" `
       ".\releases\v1.0.1\SHA256SUMS"
   ```

### Update Package Managers

- [ ] Homebrew formula updated
- [ ] Chocolatey package submitted
- [ ] winget manifest updated
- [ ] APT repository updated (Linux)
- [ ] AUR package updated (Arch Linux)

### Post-Release

- [ ] Announce on social media
- [ ] Update website download links
- [ ] Send release notification to mailing list
- [ ] Monitor for issues (first 24 hours)

### Rollback Plan

If critical issues found:

```powershell
# Rollback to previous version
.\packaging\security\secure_update_channel.ps1 -Rollback -TargetVersion "1.0.0"

# Or mark release as deprecated on GitHub
gh release edit v1.0.1 --draft  # Hide release
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Version bump | `version_manager.ps1 -Bump patch` |
| Build package | `create_release_package.ps1 -Version X.Y.Z` |
| Sign binaries | `sign_and_verify.ps1 -BinaryPath <path>` |
| Verify release | `verify_release.ps1 -ReleaseDir <path>` |
| Run benchmarks | `benchmark_runner.ps1 -Backend both` |
| Check updates | `secure_update_channel.ps1 -CheckOnly` |
