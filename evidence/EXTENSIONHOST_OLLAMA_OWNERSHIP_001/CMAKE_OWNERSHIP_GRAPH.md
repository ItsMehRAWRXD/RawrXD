# CMake ownership graph

The generated graph at `G:\~dev\rawrxd-ext-candidate-clean\build_ext_host_001\build.ninja` contains neither `src/ollama_client.cpp` nor `src/backend/ollama_client.cpp` in the `RawrXD-Win32IDE` target. The current CMake file also contains a comment at line 2290 identifying `src/ollama_client.cpp` as removed from another target, but no active IDE source-list entry.

The IDE caller object is present and the two Ollama implementation objects are absent. No owning IDE library was found that exports the required seven symbols. `AgentOllamaClient.cpp` is a different class and does not satisfy these decorated names.

This establishes a target-membership gap for the root implementation, with no evidence that the backend implementation should be linked into the IDE.
