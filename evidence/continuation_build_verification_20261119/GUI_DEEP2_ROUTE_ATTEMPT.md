# Deep2 route attempt

- Executable SHA-256: `944AF94221770A0849148E62226805E1D730F0C65AEEC1519A35E8B0C9065C6B`
- Environment: `RAWRXD_CHAT_BACKEND=deep2`
- Input transport: `CHIN`, accepted.
- Model selector: remained `COMBO_INDEX_0`; no local TinyLlama route was selected.
- Runtime route: therefore not proven to enter `Deep2Bridge`.
- Process: exited `-1` after submission.
- GPU dispatch: not established.

This attempt confirms that setting the backend environment alone does not convert an Ollama-selected combo entry into a Deep2 route. The next implementation target is model-selector/local-GGUF discovery and explicit route selection, followed by a fresh GUI run.

```ini
CHIN_INPUT=PASS
DEEP2_ROUTE_SELECTION=FAIL
DEEP2_GUI_EXECUTION=NOT_REACHED
GPU_DISPATCH=NOT_ESTABLISHED
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
