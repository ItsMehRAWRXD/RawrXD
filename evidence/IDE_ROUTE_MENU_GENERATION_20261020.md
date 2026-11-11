# IDE local/cloud route-menu generation — 2026-10-20

Status: **PASS (manifest generation); IDE runtime integration remains partial**

From `F:\rawrxd`, the configured CMake target was rebuilt:

```
cmake --build build --target rawrxd_chat_route_menu --config Release
```

Exit code: 0. CMake found Python 3.13.15 and generated
`build/generated/GeneratedChatRouteMenu.h` from
`config/chat_model_routes.json` using
`scripts/generate_chat_route_menu.py`.

The generated header SHA-256 is
`46736E1CFC54821B5A68500A7D6766C9D02E9DC90DBF3F3B5FCB03AD295A71FE` and
contains the three requested route families:

- Local models / GGUF → native-agent
- Local models / Ollama → ollama-http
- Cloud models / Kilo → cloud-api

This proves deterministic route-menu generation. It does not prove a linked
Win32 IDE binary, live Ollama discovery in the shipped CLI, or a reachable
Deep2 HTTP backend; those remain separate Gate 17 / Gate 9 evidence.
