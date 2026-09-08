# Rawr Copilot Markov (IDE autocomplete)

Separate product surface from Deep2. Zero network. C++17 STL only.

## Build

```bat
tools\rawr_copilot\build.bat
```

## Train (out-of-band)

```bat
rawr_copilot.exe train rawrxd.rmc G:\~dev\rawrxd --order 6 --max-edges 48
```

Skips `.git`, `node_modules`, `build`, `build-fd`, `dist`, `.vs`.

## IDE path (persistent stdio)

```text
EDITOR BUFFER → cursor context → rawr_copilot stdio <model.rmc>
  → COMPLETE <top> <tokens> <bytes>\n<context>
  → RESULT … END → ghost text
```

Do not train per keystroke. Load model once; complete = resident lookup.

## Law

`RawrCopilotMarkovLaw.hpp` · `BOUNDARY.txt` · `evidence/RAWRXD_COPILOT_MARKOV_001/`
