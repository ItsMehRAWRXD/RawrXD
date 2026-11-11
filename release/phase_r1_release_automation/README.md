# Phase R.1: Release Automation

## Overview

The Release Automation Manager provides comprehensive version management, changelog generation, and release orchestration for the RawrXD platform.

## Features

### Version Management
- **Semantic Versioning**: Full support for semver (x.y.z)
- **Channel Support**: stable, beta, alpha, nightly channels
- **Version Validation**: Pattern matching for each channel type
- **Auto-increment**: Calculate next version based on bump type

### Changelog Generation
- **Git Integration**: Automatically extracts commits since last release
- **Categorization**: Groups commits by type (feat, fix, docs, refactor, perf)
- **Conventional Commits**: Parses standard commit message formats
- **Release Notes**: Generates formatted markdown release notes

### Release Orchestration
- **Prepare**: Stage a release with version validation
- **Create**: Build artifacts and generate checksums
- **Publish**: Tag and publish the release
- **Rollback**: Revert a published release if needed
- **Validate**: Verify release integrity

## Usage

### Prepare a Release
```powershell
.\release_manager.ps1 -Action prepare -Version 1.0.0 -Channel stable
```

### Create Release Artifacts
```powershell
.\release_manager.ps1 -Action create -Version 1.0.0
```

### Publish Release
```powershell
.\release_manager.ps1 -Action publish -Version 1.0.0
```

### List All Releases
```powershell
.\release_manager.ps1 -Action list
```

### Rollback a Release
```powershell
.\release_manager.ps1 -Action rollback -Version 1.0.0
```

### Validate Release
```powershell
.\release_manager.ps1 -Action validate -Version 1.0.0
```

## Version Patterns

| Channel | Pattern | Example |
|---------|---------|---------|
| stable | `^\d+\.\d+\.\d+$` | 1.0.0 |
| beta | `^\d+\.\d+\.\d+-beta\.\d+$` | 1.0.0-beta.1 |
| alpha | `^\d+\.\d+\.\d+-alpha\.\d+$` | 1.0.0-alpha.1 |
| nightly | `^\d+\.\d+\.\d+-nightly\.\d{8}$` | 1.0.0-nightly.20240115 |

## Release Registry

All releases are tracked in `releases/release_registry.json`:

```json
{
  "Releases": [
    {
      "Version": "1.0.0",
      "Channel": "stable",
      "CreatedAt": "2024-01-15T10:30:00Z",
      "PublishedAt": "2024-01-15T11:00:00Z",
      "Status": "published",
      "Artifacts": [...]
    }
  ],
  "CurrentVersion": "1.0.0"
}
```

## Directory Structure

```
phase_r1_release_automation/
├── release_manager.ps1      # Main automation script
├── README.md                  # This documentation
└── releases/                  # Generated release artifacts
    ├── release_registry.json  # Release tracking
    ├── v1.0.0/               # Release artifacts
    │   ├── rawrxd-v1.0.0-windows-x64.zip
    │   ├── rawrxd-v1.0.0-linux-x64.tar.gz
    │   └── checksums.sha256
    └── v1.0.0-release-notes.md
```

## Integration

### CI/CD Pipeline
```yaml
# Example GitHub Actions workflow
- name: Prepare Release
  run: |
    .\release\phase_r1_release_automation\release_manager.ps1 `
      -Action prepare -Version ${{ github.ref_name }} -Channel stable

- name: Create Release
  run: |
    .\release\phase_r1_release_automation\release_manager.ps1 `
      -Action create -Version ${{ github.ref_name }}

- name: Publish Release
  run: |
    .\release\phase_r1_release_automation\release_manager.ps1 `
      -Action publish -Version ${{ github.ref_name }}
```

## Next Steps

Proceed to Phase R.2: Distribution Management for artifact distribution and release channels.
