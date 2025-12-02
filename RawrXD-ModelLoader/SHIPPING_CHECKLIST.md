# 🚢 Production Shipping Checklist

## Build & Tests ✅
- [x] Clean build (178 KB binary)
- [x] All widgets compile with real implementations
- [ ] Smoke tests pass (`.\testbench.ps1`)
- [ ] No memory leaks
- [ ] Code signing configured

## Features Implemented
- [x] CloudRunner (GitHub Actions API)
- [x] LSP Client (clangd, pylsp, rust-analyzer)
- [x] InlineChat (AI fixes with diff preview)
- [x] PluginManager (GitHub marketplace)
- [x] TelemetryDialog (privacy consent)
- [x] Dark/Light mode support

## Shipping Requirements
- [ ] Tag v0.1.0
- [ ] CI builds signed binary
- [ ] GitHub Release with size in description
- [ ] Binary ≤ 200 KB budget

## Next Steps
1. Run `.\testbench.ps1` to verify smoke tests
2. Set up code signing cert (SSL.com $99)
3. Tag release: `git tag v0.1.0 && git push origin v0.1.0`
4. Tweet size: "178 KB Qt IDE with cloud builds"
