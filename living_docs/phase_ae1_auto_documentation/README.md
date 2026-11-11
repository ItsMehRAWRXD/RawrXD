# Phase AE.1: Living Documentation Generator

## Overview

Automatically generates and maintains documentation that evolves with the codebase, ensuring docs never become stale or outdated.

## Features

### Automatic Scanning
- **Source Code Analysis**: Scans PowerShell, Markdown, and other files
- **Documentation Detection**: Identifies which files have/have not documentation
- **Change Tracking**: Monitors when files are modified

### Documentation Generation
- **Template Creation**: Auto-generates documentation templates
- **Structure Enforcement**: Maintains consistent documentation format
- **Missing Doc Detection**: Identifies undocumented components

### Continuous Sync
- **Scheduled Updates**: Regular documentation refresh
- **Change Triggers**: Update docs when code changes
- **Version Tracking**: Maintain doc versions aligned with code

## Usage

### Scan Source Code
```powershell
.\doc_generator.ps1 -Action scan -SourcePath .\src
```

### Generate Missing Documentation
```powershell
.\doc_generator.ps1 -Action generate
```

### Full Sync
```powershell
.\doc_generator.ps1 -Action sync
```

### Check Status
```powershell
.\doc_generator.ps1 -Action validate
```

## Integration

### CI/CD Pipeline
```yaml
- name: Update Documentation
  run: |
    .\living_docs\phase_ae1_auto_documentation\doc_generator.ps1 -Action sync
    git add docs/
    git commit -m "docs: auto-update documentation"
```

### Pre-Commit Hook
```bash
#!/bin/bash
.\doc_generator.ps1 -Action scan
```
