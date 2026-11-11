# Next Gate

Use a controlled operator-assisted activation procedure: launch the isolated candidate, have the operator activate its window normally, then collect `GetForegroundWindow`/`GetGUIThreadInfo` and editor-focus evidence. Do not bypass Windows foreground policy or infer GhostText/file-I/O results from this failure.
