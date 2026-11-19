# S028 — Session persistence and model switching

Date: 2026-11-19  
Source SHA: `523efd270a55e741b80da32eab936d345488c766`

## Source findings

The IDE persists chat state in `ChatSessionState`, checkpoints active history
before switching/clearing, restores the selected model with the session, and
updates the active model entry when the selector changes. Clearing a chat
invalidates active inference and clears history, response buffers, and step
rows before returning the UI to its welcome state.

## Remaining correctness gap

The inspected model-selection path updates the session model, but the retained
source/evidence does not prove that an already-loaded `Deep2Bridge` unloads or
resets recurrent/KV state when the selected GGUF changes. No two-model switch
runtime receipt records old/new model identity, KV reset, and first-token
isolation.

```ini
SESSION_CHECKPOINTS=SOURCE_VERIFIED
CHAT_CLEAR_INVALIDATES_INFERENCE=SOURCE_VERIFIED
MODEL_SELECTION_PERSISTENCE=SOURCE_VERIFIED
DEEP2_KV_RESET_ON_MODEL_SWITCH=UNVERIFIED
MODEL_SWITCH_RUNTIME=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
