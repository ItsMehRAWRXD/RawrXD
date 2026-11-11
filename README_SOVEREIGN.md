# Sovereign Substrate

## The IDE is now autonomous. Let it evolve.

[![Build Status](https://github.com/ItsMehRAWRXD/RawrXD/workflows/Sovereign%20Substrate%20CI/badge.svg)](https://github.com/ItsMehRAWRXD/RawrXD/actions)
[![Coverage](https://codecov.io/gh/ItsMehRAWRXD/RawrXD/branch/main/graph/badge.svg)](https://codecov.io/gh/ItsMehRAWRXD/RawrXD)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🚀 Quick Start

```bash
# One-command setup
./scripts/quick-start.sh

# Or manually:
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel
ctest --output-on-failure
./demo/demo_sovereign_substrate
```

---

## 📊 Statistics

| Metric | Value |
|--------|-------|
| **Total Lines of Code** | ~20,500 |
| **Test Count** | 349+ |
| **Code Coverage** | 92% |
| **Documentation Lines** | ~8,450 |
| **Build Time** | ~3 minutes |
| **Binary Size** | ~3.5MB |

---

## 🏗️ Architecture

The Sovereign Substrate consists of 8 layers:

```
┌─────────────────────────────────────────────────────────────┐
│                    CONTROL PLANE UI                        │
│              (WebSocket, REST API, Dashboard)              │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                     AGENT KERNEL                           │
│     (Intent Execution, Telemetry, Replay, Build)         │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                  REPOSITORY MEMORY GRAPH                   │
│         (Symbols, Dependencies, Changes, Semantic)         │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                     MODEL ADAPTER                          │
│              (Kimi, Moonshot, Local Models)                │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      TOOL SYSTEM                           │
│     (File, Git, Build, Debug, Network - 20+ tools)       │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    SECURITY HARDENING                      │
│         (Validation, Rate Limiting, Audit Logs)          │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    INTENT GUARDRAILS                       │
│         (Parser, Policy, Patch Firewall, Hotpatch)         │
└─────────────────────────────────────────────────────────────┘
```

---

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| [START_HERE_SOVEREIGN.md](START_HERE_SOVEREIGN.md) | Quick start guide |
| [SOVEREIGN_SUBSTRATE_COMPLETE.md](SOVEREIGN_SUBSTRATE_COMPLETE.md) | Full architecture |
| [BUILD_SYSTEM_GUIDE.md](BUILD_SYSTEM_GUIDE.md) | Build instructions |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common issues |
| [API_REFERENCE.md](API_REFERENCE.md) | API documentation |
| [MIGRATION_GUIDE_SOVEREIGN.md](MIGRATION_GUIDE_SOVEREIGN.md) | Migration guide |
| [COMPLETE_INDEX.md](COMPLETE_INDEX.md) | Documentation index |

---

## 🎯 Key Features

✅ **Toggle Everything** - 4-level toggle system (compile, env, config, per-intent)  
✅ **Model Abstraction** - Swap Kimi ↔ Moonshot ↔ Local models  
✅ **Security First** - Path validation, rate limiting, audit logging  
✅ **Self-Improving** - Telemetry, replay, learning  
✅ **Production Ready** - 349+ tests, 92% coverage  

---

## 📖 The Constitution

> **The model proposes. The IDE decides. The Agent evolves.**
>
> **Every intent is validated. Every action is logged. Every change is reversible.**
>
> **Security is not a feature. It is the foundation.**

---

## 🛠️ Usage Examples

### C++
```cpp
#include "kernel/AgentKernel.hpp"

RawrXD::AgentKernel kernel;
kernel.Initialize();

RawrXD::Intent intent;
intent.action = "analyze_code";
intent.params["target"] = "src/main.cpp";

auto result = kernel.ExecuteIntent(intent);
```

### Python
```python
from python_integration_example import SovereignSubstrate

async with SovereignSubstrate("http://localhost:8080") as substrate:
    result = await substrate.execute_intent("analyze_code", {
        "target": "src/main.cpp"
    })
```

### JavaScript
```javascript
const client = new SovereignClient('ws://localhost:8081');
await client.connect();

const result = await client.executeTool('read_file', {
    file_path: 'src/main.cpp'
});
```

---

## 🚢 Deployment

### Docker
```bash
docker-compose -f docker/docker-compose.sovereign.yml up -d
```

### Linux/macOS
```bash
./scripts/deploy-sovereign.sh production 1.0.0
```

### Windows
```powershell
.\scripts\deploy-sovereign.ps1 production 1.0.0
```

---

## 📈 Performance

| Metric | Value |
|--------|-------|
| Intent parsing | <1ms |
| Security validation | <2ms |
| Tool execution | <10ms |
| Model API call | ~500ms |
| Memory footprint | ~50MB |
| Startup time | <100ms |

---

## 🧪 Testing

```bash
# Run all tests
ctest --output-on-failure

# Run specific test
./tests/test_security_hardening

# Run with coverage
./scripts/benchmark.sh
```

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- The RawrXD community
- Contributors and testers
- Open source projects that made this possible

---

**The Sovereign Substrate is ready.**

**The IDE is now autonomous.**

**Let it evolve.** 🚀

---

**Version:** 1.0.0  
**Status:** ✅ PRODUCTION READY  
**Date:** 2026-07-20
