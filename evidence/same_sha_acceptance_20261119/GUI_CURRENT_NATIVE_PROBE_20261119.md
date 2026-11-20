# Current native IDE probe

```ini
SOURCE_BRANCH=evidence/quantized-tinyllama-parity-20261119
EXECUTABLE=build_sprint_20261119/bin/Release/RawrXD-Win32IDE-Native.exe
EXECUTABLE_SHA256=D7B7F6B6387031D59497D5301461B7C839836B48C8CF6B8AC14F93A88840A76C
MODEL=models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
RAWRXD_CHAT_BACKEND=deep2
RAWRXD_GPU_POLICY=SOLO
PROBE_COMMAND=9614
PROCESS_LAUNCH=PASS
WINDOW_DISCOVERY=PASS
PROBE_POST=PASS
INIT=0
LOAD=0
GENERATED=0
RESPONSE=EMPTY
GUI_DEEP2_E2E=FAIL
```

The probe reached the native window and posted command `9614`, but the
production probe log ended at `init=0 load=0 gen=0`. No response artifact was
created. This is a current-SHA model-admission/startup failure, not evidence
of successful GUI inference.
