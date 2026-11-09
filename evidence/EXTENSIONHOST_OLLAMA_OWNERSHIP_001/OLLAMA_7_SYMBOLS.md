# Seven unresolved OllamaClient symbols

Source: `G:\~dev\rawrxd\evidence\EXTENSIONHOST_IDE_LINK_REPAIR_002\BUILD_LOG.txt`, lines 30-44. All seven are unique and are referenced by `Win32IDE_ChatWindow.cpp.obj`:

| Symbol | Declaration | Matching definition |
|---|---|---|
| constructor | `src/ollama_client.h:66` | `src/ollama_client.cpp:88` |
| destructor | `src/ollama_client.h:68` | `src/ollama_client.cpp:92` |
| `testConnection()` | `src/ollama_client.h:83` | `src/ollama_client.cpp:103` |
| `listModels()` | `src/ollama_client.h:91` | `src/ollama_client.cpp:124` |
| `generateSync(...)` | `src/ollama_client.h:98` | `src/ollama_client.cpp:156` |
| `chatSync(...)` | `src/ollama_client.h:99` | `src/ollama_client.cpp:170` |
| `cancelStream()` | `src/ollama_client.h:112` | `src/ollama_client.cpp:99` |

The decorated names are `RawrXD::Backend::OllamaClient` methods with the signatures shown in the linker log. No `LNK2019` or additional unresolved class symbols were reported.
