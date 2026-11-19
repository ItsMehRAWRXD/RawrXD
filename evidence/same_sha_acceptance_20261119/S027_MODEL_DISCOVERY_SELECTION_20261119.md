# S027 — Model discovery and selection

Date: 2026-11-19  
Source SHA: `baacd7d2bbc575edba5fd247f3fbce222f151007`

## Source findings

The native model catalog has separate source identities:

- Local GGUF files are discovered by bounded filesystem scanning and admitted
  only when the file has GGUF magic and tensor-bearing content.
- Ollama models are discovered from `/api/tags` when the optional local HTTP
  service is reachable.
- Selection preserves the complete `ChatModelEntry`, including source and
  identifier; local entries route to Deep2 and Ollama entries route to the
  WinHTTP Ollama implementation.
- Model selection updates the active chat session model and the Ollama
  override only for Ollama entries, avoiding cross-route ambiguity.

## Acceptance status

The source routing and discovery boundaries are present. A fresh GUI discovery
and selection run against the current source commit was not executed because
the native IDE link remains blocked by the locked executable. Real model
listing/selection therefore remains runtime OPEN.

```ini
LOCAL_GGUF_DISCOVERY=SOURCE_VERIFIED
OLLAMA_DISCOVERY=SOURCE_VERIFIED
SOURCE_PRESERVATION=SOURCE_VERIFIED
LOCAL_TO_DEEP2_ROUTING=SOURCE_VERIFIED
GUI_DISCOVERY_RUNTIME=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
