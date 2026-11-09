# Definition provenance

All 18 symbols have concrete implementations in the committed candidate source. No implementation-missing or ABI-mismatch evidence was found.

The implementations are grouped in five translation units:

- `Win32IDE_ChatWindowUI.cpp`: chat window entry point.
- `Win32IDE_TasksDebugUI.cpp`: four task/debug UI functions.
- `Win32IDE_PathBCmdDiagSwarm.cpp`: five Path B command diagnostic functions.
- `Win32IDE_SidebarRuntime.cpp`: six sidebar runtime methods.
- `Win32IDE_CallStackSymbols.cpp`: two call-stack methods.

The generated `build.ninja` contains none of these five source filenames. In contrast, it contains the referencing objects and the already-added ExtensionHost runtime objects. This establishes `SOURCE_EXISTS_NOT_LINKED` as the common classification.

The source declarations and definitions use the expected namespaces and signatures. No compile guard was observed around the definitions that would explain their absence; the direct evidence is omission from the IDE target source graph.
