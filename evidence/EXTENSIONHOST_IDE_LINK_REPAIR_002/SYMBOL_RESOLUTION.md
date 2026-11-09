# Symbol resolution

The seven `RawrXDChatWindow_*` symbols from the previous build were resolved by adding `src/win32app/Win32IDE_ChatWindow.cpp` to the IDE target.

The next link failure contains seven new unresolved `RawrXD::Backend::OllamaClient` methods referenced by `Win32IDE_ChatWindow.cpp`:

- constructor and destructor
- `testConnection`
- `listModels`
- `generateSync`
- `chatSync`
- `cancelStream`

Definitions exist in both `src/backend/ollama_client.cpp` and `src/ollama_client.cpp`, but neither file appears in the `RawrXD-Win32IDE` generated target graph. This is a new source-exists-not-linked dependency with an additional duplicate-implementation selection issue. No choice between the two implementations was made.
