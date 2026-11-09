# Minimal repair plan

Recommendation: **B — add the correct existing translation unit to the IDE target.**

Add exactly:

`src/ollama_client.cpp`

to the existing `RawrXD-Win32IDE` source list. Do not add `src/backend/ollama_client.cpp`, do not modify either implementation, and do not alter headers or Ghost Text/AgentOllamaClient code.

After separate authorization, regenerate the graph and verify the root implementation object is present. Then perform the controlled candidate build and check whether the seven symbols resolve. Runtime remains out of scope until both executables link and deploy.
