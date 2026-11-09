# Root cause

Classification: `SOURCE_EXISTS_NOT_LINKED`.

The final IDE link failed because five committed implementation translation units are absent from the `RawrXD-Win32IDE` source list. Their declarations and call sites are compiled, but their definitions never become object files in the target. The linker therefore reports 18 unresolved symbols, followed by aggregate `LNK1120`.

Earliest demonstrated boundary: final `RawrXD-Win32IDE.exe` link at build-log line 2175 onward. The ExtensionHost worker link passed before this boundary. No runtime behavior was tested.

The diagnosis is based on the complete existing linker log, exact source definitions, CMake source-list inspection, and generated Ninja graph inspection. No source modification or rebuild was performed during this diagnosis.
