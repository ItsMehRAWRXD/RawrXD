# RawrXD Ollama daily-use routing fix

## Source change

The native IDE agent bridge no longer initializes against a hard-coded
`bigdaddyg-personalized-agentic:latest` model. Agent startup now resolves, in
order:

1. the selected chat model,
2. `m_ollamaModelOverride`,
3. `RAWRXD_AGENT_MODEL`,
4. visible local default `qwen3:8b`.

The model configuration dialog fallback was changed to `qwen3:8b` rather than
an implicit private model.

## Build

```ini
NATIVE_IDE_BUILD=PASS
NATIVE_IDE_EXE=F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe
NATIVE_IDE_SHA256=41C20EFEBD687D28662C6638D1BF067BE031112B60C21786FAFE58E2BC1B965C
PROMOTE=0
```

This is a source/build usability fix. Physical GUI inference, GhostText, and
agent edit certification must still be rerun against this exact executable.
