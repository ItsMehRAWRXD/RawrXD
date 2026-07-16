# Contribution Guide
## Sovereign IDE Contributing Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

Thank you for your interest in contributing to Sovereign IDE!

### Ways to Contribute

| Type | Description |
|------|-------------|
| **Code** | Bug fixes, features |
| **Documentation** | Guides, tutorials |
| **Testing** | Bug reports, QA |
| **Community** | Support, advocacy |

---

## Getting Started

### 1. Fork the Repository

```bash
git clone https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD
```

### 2. Set Up Development Environment

```bash
# Install dependencies
./scripts/install-deps.sh

# Build
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### 3. Create Branch

```bash
git checkout -b feature/my-feature
```

---

## Development Guidelines

### Code Style

- Follow C++17 standards
- Use clang-format
- Write clear comments
- Add unit tests

### Commit Messages

```
type(scope): subject

body

footer
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Tests
- `refactor`: Code refactoring

---

## Pull Request Process

1. **Create PR** from your fork
2. **Fill template** with details
3. **Ensure CI passes**
4. **Request review**
5. **Address feedback**
6. **Merge**

---

## Summary

Contribution Guide provides:

- ✅ **Setup instructions**
- ✅ **Development guidelines**
- ✅ **PR process**
- ✅ **Code standards**

**Status:** ✅ Complete
