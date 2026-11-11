# RawrXD CMake Source-to-Target Audit

Scope: static parse of root CMake graph in src-level references from d:/rawrxd/CMakeLists.txt.

## Outputs
- cmake_source_target_matrix.csv
- cmake_source_target_matrix.json
- target_inventory.csv
- deep2_audit.csv
- duplicate_implementation_families.csv
- orphan_sources.csv

## High-Level Counts
- add_executable declarations: 71
- add_library declarations: 13
- targets discovered: 83
- source-target edges: 976
- unique referenced sources: 836
- duplicate implementation families: 11
- stub-risk edges (name-based): 24
- filesystem source files under src/: 6263
- source files present in tree but unreferenced in root CMake: 5486

## Deep2 Slice
- total deep2 .cpp files scanned: 114
- referenced by root CMake: 41
- cmake-orphan deep2 files: 73

## Notes
- This is root-CMake authoritative only; nested historical/reconstructed trees are intentionally out of scope.
- Conditional includes are flagged via the 'conditional' column when sources are gathered from inside if(...) scopes.
- Duplicate/stub flags are heuristic and should be reviewed before cleanup decisions.
