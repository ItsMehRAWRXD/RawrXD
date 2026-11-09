# IDE caller contract

`Win32IDE_ChatWindow.cpp` is the only direct native IDE caller found for this `OllamaClient` type. It constructs the client, tests connectivity, enumerates models, sends generate/chat requests, and cancels in-flight work. The include path selects `src/ollama_client.h`.

Ghost Text and agentic callers use the separate `AgentOllamaClient` interface (`src/agentic/AgentOllamaClient.h`), not `RawrXD::Backend::OllamaClient`. Model discovery and agentic backend tools use their own contracts. Therefore the minimal repair must satisfy the ChatWindow root-header contract without changing Ghost Text or AgentOllamaClient ownership.

No runtime behavior was tested in this audit.
