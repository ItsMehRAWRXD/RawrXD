# Shared State Matrix

| Resource | Classification | Basis |
|---|---|---|
| LocalAppData RawrXD IDE log | Shared mutable | `main_win32.cpp` uses a fixed RawrXD log path |
| Relative logs and trace files | Working-directory mutable | logger/PowerShell paths include relative or fixed paths |
| Ollama service and model state | Shared mutable/unknown | shared localhost service |
| IDE workspace files | Mutable by selected workspace | no complete per-instance isolation contract |
| Global mutex/IPC singleton | Not found | source audit found no IDE singleton mechanism |

Because shared mutable state is not proven isolated, any same-product native IDE process still blocks launch, even when its executable path differs.
