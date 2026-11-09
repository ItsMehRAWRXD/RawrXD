# Implementation comparison

## Native IDE implementation

`src/win32app/Win32IDE_ChatWindow.cpp:25` includes `../ollama_client.h`, resolving to `src/ollama_client.h`. Its callers use `testConnection`, `listModels`, `generateSync`, `chatSync`, and `cancelStream` at lines 534-642 and 819-822. The header includes the `raw` request field and cancellation state used by the ChatWindow contract. `src/ollama_client.cpp` defines the complete matching class in `RawrXD::Backend`.

## Backend implementation

`src/backend/ollama_client.cpp` pairs with `src/backend/ollama_client.h`. That header has a different data contract: its `OllamaModel` lacks the root header's `id` and its request/response structures differ. It is used by `src/backend/agentic_tools*.cpp`, not by the native ChatWindow. It is not interchangeable merely because the class name and namespace match.

## Ownership conclusion

The native IDE owns the root pair `src/ollama_client.h` + `src/ollama_client.cpp`. Adding the backend pair would risk an ODR/duplicate-definition conflict and would not establish the ChatWindow's intended data contract. The root implementation is not present in the generated `RawrXD-Win32IDE` graph; the backend implementation is also not present in that graph.
