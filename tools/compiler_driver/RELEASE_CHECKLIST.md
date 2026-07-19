# Release Checklist

**RAWRXD Compiler Driver**

Use this checklist when preparing a new release.

---

## Pre-Release

### Code Quality
- [ ] All tests pass (`tests\smoke_test.bat`)
- [ ] No compiler warnings
- [ ] Code review completed
- [ ] Documentation updated

### Version Updates
- [ ] Update version in `include/rawrxd_compiler.h`
- [ ] Update version in `package.json`
- [ ] Update `CHANGELOG.md`
- [ ] Update version references in documentation

### Testing
- [ ] Windows build tested
- [ ] Linux build tested (if applicable)
- [ ] macOS build tested (if applicable)
- [ ] VS Code extension tested
- [ ] All examples work

---

## Release Build

### Build
- [ ] Clean build (`build.bat clean`)
- [ ] Full build (`build.bat`)
- [ ] Verify binaries exist in `bin/`
- [ ] Check file sizes are reasonable

### Package
- [ ] Create ZIP distribution
- [ ] Create installer (if applicable)
- [ ] Generate checksums
- [ ] Test installation

---

## Documentation

### Update
- [ ] `README.md` current
- [ ] `CHANGELOG.md` updated
- [ ] `FAQ.md` updated (if needed)
- [ ] API documentation current

### Review
- [ ] No broken links
- [ ] Screenshots current
- [ ] Examples work
- [ ] Installation instructions accurate

---

## GitHub Release

### Create Release
- [ ] Tag version (`git tag -a v1.0.0 -m "Release v1.0.0"`)
- [ ] Push tag (`git push origin v1.0.0`)
- [ ] Create GitHub release
- [ ] Add release notes

### Attach Assets
- [ ] Source code (zip)
- [ ] Source code (tar.gz)
- [ ] Binary distribution
- [ ] Checksums file

---

## Post-Release

### Verification
- [ ] Download and test release
- [ ] Verify checksums match
- [ ] Test on clean system
- [ ] Test VS Code extension install

### Communication
- [ ] Announce on social media (if applicable)
- [ ] Update website (if applicable)
- [ ] Notify contributors
- [ ] Close related issues

### Cleanup
- [ ] Update development branch
- [ ] Plan next version
- [ ] Archive old releases (if needed)

---

## Release Notes Template

```markdown
## What's New in vX.Y.Z

### New Features
- Feature 1
- Feature 2

### Bug Fixes
- Fix 1
- Fix 2

### Improvements
- Improvement 1
- Improvement 2

### Breaking Changes
- Change 1 (if any)

### Contributors
Thanks to @username1, @username2!

### Downloads
- [Windows Binary](link)
- [Source Code](link)
- [Checksums](link)
```

---

## Quick Commands

```batch
# Tag release
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# Build release
build.bat clean
build.bat release

# Run tests
cd tests
smoke_test.bat
```

---

*Last updated: 2026-07-19*
