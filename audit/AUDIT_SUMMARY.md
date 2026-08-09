# RawrXD CMake Source-to-Target Audit

Scope: static parse of root CMake graph in d:/rawrxd/CMakeLists.txt.

## Outputs
- cmake_source_target_matrix.csv
- cmake_source_target_matrix.json
- target_inventory.csv
- deep2_audit.csv
- duplicate_implementation_families.csv
- orphan_sources.csv

## Counts
- add_executable declarations: 71
- add_library declarations: 13
- targets discovered: 83
- source-target edges: 976
- unique referenced sources: 836
- duplicate implementation families: 11
- stub-risk edges (name heuristic): 24
- filesystem source files under src/: 6256
- source files present but unreferenced in root CMake: 5479

## Deep2 Slice
- total deep2 .cpp files scanned: 114
- referenced by root CMake: 41
- cmake-orphan deep2 files: 73

## Notes
- Root CMake is treated as authoritative audit boundary.
- Conditional column is inferred from if/endif nesting in static parse.
- Duplicate and stub risk are heuristic and require review before deletion.
