# T015 model-generated tool loop receipt

## Candidate

```ini
BINARY=F:\rawrxd\build_repair_candidate\bin-msvc\rawr.exe
SIZE=5020160
SHA256=CCDBBBD061E5CEC328B08DF03B27F2D0593713EB3DA87FED4AC973775583925D
MODEL=ollama/qwen3:8b
MODE=autonomous
MOTD_SHA256=3d08b40abb22482209e7585175e76fa8cffc4d999f9edfc252910a38e1ed98de
```

## Read tool round

```ini
PROMPT=Use readFile on evidence/T015_CLI_TOOL/direct_edit_fixture.txt, then reply exactly RAWRXD_AGENT_READ_PASS
TOOL=readFile
TOOL_RESULT=PASS
FINAL_MARKER=RAWRXD_AGENT_READ_PASS
EXIT=0
PROCESS_TIMEOUT=0
```

The read result came from the real file and returned `T015_DIRECT_EDIT_NEW`.

## Mutation tool round

```ini
PROMPT=Use editFiles exactly once on evidence/T015_CLI_TOOL/agent_edit_fixture.txt, replacing AGENT_EDIT_OLD with AGENT_EDIT_NEW
TOOL=editFiles
TOOL_RESULT=PASS
FINAL_MARKER=RAWRXD_AGENT_EDIT_PASS
EXIT=0
PROCESS_TIMEOUT=0
BEFORE_SHA256=EF713CF392095F0A7C2D64F151D5DC3055FFD7E02C00DC5AE75CF3995408244E
AFTER_SHA256=73C10EA10420B8F4E00D7418411CA9509DA6C8720EA9F87C7D5B70A675970503
FINAL_FILE_CONTENT=AGENT_EDIT_NEW
```

The mutation required the explicit autonomous approval environment and was verified by a disk read after process exit. No synthetic tool result was injected.

## Disposition

```ini
T015_DIRECT_TOOL=PASS
T015_MODEL_GENERATED_READ=PASS
T015_MODEL_GENERATED_EDIT=PASS
T015_DISK_PERSISTENCE=PASS
PROMOTE=0
CERTIFIED=0
```
