# RawrXD Integration Analysis Report

**Date:** 2026-07-19 09:21:35
**Root:** D:\rawrxd-ci-bootstrap
**Duration:** 10 seconds
**Status:** error

## Summary

| Metric | Value |
|--------|-------|
| Analyzers Run | 5 |
| Passed | 8 |
| With Warnings | 3 |
| With Errors | 8 |
| Total Errors | 55 |
| Total Warnings | 6429 |

## Results
### ❌ CMakeGraph

| Metric | Value |
|---|---|
| Status | error |
| Errors | 55 |
| Warnings | 5385 |
| compiled | 38 |
| orphaned | 5385 |
| targets | 57 |
| total_sources | 5419 |
| empty_targets | 55 |

**Findings:**

- ⚠️  (21 items)
- ❌  (55 items)

---

### ✅ Registration

| Metric | Value |
|---|---|
| Status | pass |
| Errors | 0 |
| Warnings | 0 |
| registrations | 0 |
| implementations | Command: 2, Provider: 62, Menu: 11, Panel: 35, Theme: 4, Keybinding: 1, Debugger: 9, Tool: 24, Dock: 26, Extension: 16 |

---

### ⚠️ SymbolGraph

| Metric | Value |
|---|---|
| Status | warning |
| Errors | 0 |
| Warnings | 1032 |
| classes | 2297 |
| functions | 9791 |
| total_lines | 417273 |
| files_scanned | 1077 |
| stub_patterns | 1032 |

**Findings:**

- ⚠️ 1032 stub/TODO patterns found across 1077 files

---

### ⚠️ RuntimeInit

| Metric | Value |
|---|---|
| Status | warning |
| Errors | 0 |
| Warnings | 4 |
| total_expected | 14 |
| services_found | 10 |
| services_missing | 4 |

**Findings:**

- ⚠️ No implementation found for WorkspaceService
- ⚠️ No implementation found for ProjectService
- ⚠️ No implementation found for Terminal
- ⚠️ No implementation found for Git

---

### ⚠️ Extension

| Metric | Value |
|---|---|
| Status | warning |
| Errors | 0 |
| Warnings | 8 |
| extension_host_files | 19 |
| extensions_loadable | 2 |
| extensions_found | 10 |
| extension_dirs | 3 |

**Findings:**

- ⚠️ Extension folder missing package.json or manifest.json
- ⚠️ Extension folder missing package.json or manifest.json
- ⚠️ Extension folder missing package.json or manifest.json
- ⚠️ Extension folder missing package.json or manifest.json
- ⚠️ Extension folder missing package.json or manifest.json
- ⚠️ Extension folder missing package.json or manifest.json
- ⚠️ Extension folder missing package.json or manifest.json
- ⚠️ Extension folder missing package.json or manifest.json

---


## Priority Actions
| Severity | Category | Message |
|---|---|---|
| ⚠️ | orphaned_source |  |
| ⚠️ | stub_patterns | 1032 stub/TODO patterns found across 1077 files |
| ⚠️ | missing_service | No implementation found for WorkspaceService |
| ⚠️ | missing_service | No implementation found for ProjectService |
| ⚠️ | missing_service | No implementation found for Terminal |
| ⚠️ | missing_service | No implementation found for Git |
| ⚠️ | unloadable_extension | Extension folder missing package.json or manifest.json |
| ⚠️ | unloadable_extension | Extension folder missing package.json or manifest.json |
| ⚠️ | unloadable_extension | Extension folder missing package.json or manifest.json |
| ⚠️ | unloadable_extension | Extension folder missing package.json or manifest.json |
| ⚠️ | unloadable_extension | Extension folder missing package.json or manifest.json |
| ⚠️ | unloadable_extension | Extension folder missing package.json or manifest.json |
| ⚠️ | unloadable_extension | Extension folder missing package.json or manifest.json |
| ⚠️ | unloadable_extension | Extension folder missing package.json or manifest.json |
| ❌ | empty_target |  |

