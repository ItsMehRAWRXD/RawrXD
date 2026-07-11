# Migration Guide
## Sovereign IDE Migration Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

Guide for migrating from other reverse engineering tools to Sovereign IDE.

---

## From IDA Pro

### Feature Mapping

| IDA Pro | Sovereign IDE |
|---------|-----------------|
| IDAPython | Python API |
| IDC | Lua API |
| Plugins | Extensions |
| Scripts | Automation |

### Migration Steps

1. Export IDA database to JSON
2. Import into Sovereign IDE
3. Convert scripts to Sovereign API
4. Validate results

---

## From Ghidra

### Feature Mapping

| Ghidra | Sovereign IDE |
|--------|-----------------|
| GhidraScript | Python/Lua API |
| Decompiler | Decompiler |
| Symbol Tree | Symbol Browser |

### Migration Steps

1. Export Ghidra project
2. Import into Sovereign IDE
3. Map Ghidra scripts
4. Test functionality

---

## From Binary Ninja

### Feature Mapping

| Binary Ninja | Sovereign IDE |
|--------------|-----------------|
| Python API | Python API |
| IL | IR |
| Plugins | Extensions |

---

## Summary

Migration Guide provides:

- ✅ **Tool comparisons**
- ✅ **Migration steps**
- ✅ **Feature mapping**
- ✅ **Validation**

**Status:** ✅ Complete
