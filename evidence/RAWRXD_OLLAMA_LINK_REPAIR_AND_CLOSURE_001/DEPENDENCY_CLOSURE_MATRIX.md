# Dependency closure matrix

| Dependency | Target | Evidence | Result |
|---|---|---|---|
| ExtensionHostWorker_main.cpp | `RawrXD-ExtensionHost` | clean build step 1 and final link | Linked |
| ProductExtensionRuntime sources | `RawrXD-Win32IDE` | generated graph and clean link | Included |
| Five original missing IDE units | `RawrXD-Win32IDE` | clean graph/object edges | Included |
| Win32IDE_ChatWindow.cpp | `RawrXD-Win32IDE` | clean graph/object edge | Included |
| src/ollama_client.cpp | `RawrXD-Win32IDE` | clean graph/object edge | Included |
| src/backend/ollama_client.cpp | `RawrXD-Win32IDE` | graph search | Excluded |
| ExtensionHost deployment | candidate `bin` directory | final build deployment step | Present beside IDE |

The clean link produced no unresolved external diagnostics, duplicate-definition errors, or ABI failures.
