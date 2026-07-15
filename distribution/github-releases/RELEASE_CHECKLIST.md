# Release Checklist

## Phase H.2 Batch 5/5: GitHub Releases Distribution

### Pre-Release

- [ ] All tests passing (unit, integration, e2e)
- [ ] Phase G.2 validation complete
- [ ] Security scan clean
- [ ] Documentation updated
- [ ] CHANGELOG.md updated

### Build

- [ ] Windows MSI built and signed
- [ ] macOS DMG built and notarized
- [ ] Linux AppImage built and signed
- [ ] Docker images built and pushed
- [ ] Checksums generated for all artifacts

### Distribution

- [ ] GitHub Release created with artifacts
- [ ] Winget manifest updated
- [ ] Chocolatey package published
- [ ] Homebrew formula updated
- [ ] APT repository updated
- [ ] YUM repository updated

### Post-Release

- [ ] Installation tested on clean Windows VM
- [ ] Installation tested on clean macOS VM
- [ ] Installation tested on clean Linux VM
- [ ] Auto-update mechanism tested
- [ ] Rollback procedure tested
- [ ] Monitoring dashboards verified

### Emergency Contacts

- Release Manager: release@rawrxd.ai
- On-Call Engineer: oncall@rawrxd.ai
- Security: security@rawrxd.ai
