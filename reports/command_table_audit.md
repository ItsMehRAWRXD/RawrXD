# COMMAND_TABLE Coverage Audit Report
Generated: 2026-08-09 18:51:39
Source root: `D:\rawrxd\src`

## Summary

| Metric | Count |
|--------|-------|
| IDM_* defines (non-zero, non-range) | 782 |
| COMMAND_TABLE entries | 493 |
| Handler declarations | 280 |
| GUI-routable (ID ≠ 0) | 467 |
| CLI-accessible (BOTH + CLI_ONLY) | 482 |
| **Coverage** | **57.8%** |
| Status | ⚠️ ISSUES FOUND |

## Categories

| Category | Commands |
|----------|----------|
| ReverseEng | 29 |
| Debug | 28 |
| CLI | 26 |
| Swarm | 24 |
| Edit | 22 |
| File | 20 |
| Router | 18 |
| View | 17 |
| Theme | 17 |
| Plugin | 17 |
| Voice | 16 |
| AIMode | 14 |
| Agent | 13 |
| LSP | 13 |
| Cosmetic | 13 |
| ASM | 12 |
| QW | 12 |
| Backend | 11 |
| Tools | 11 |
| Hotpatch | 10 |
| Transparency | 9 |
| Terminal | 9 |
| MultiResp | 9 |
| PDB | 9 |
| Hybrid | 8 |
| LSPServer | 8 |
| AIContext | 7 |
| Audit | 7 |
| Help | 6 |
| Autonomy | 6 |
| Monaco | 6 |
| Transcendence | 6 |
| Git | 5 |
| SubAgent | 5 |
| Governor | 5 |
| Editor | 5 |
| Models | 5 |
| Safety | 4 |
| Replay | 4 |
| Telemetry | 4 |
| GameEngine | 4 |
| Performance | 3 |
| Modules | 3 |
| Gauntlet | 2 |
| Disk | 2 |
| UI | 2 |
| Security | 2 |
| Confidence | 1 |
| Marketplace | 1 |
| Embedding | 1 |
| Vision | 1 |
| Prompt | 1 |

## ⚠️ IDM_* Defines Missing from COMMAND_TABLE

These Win32 GUI command IDs have no entry in COMMAND_TABLE.
To fix: add an X(...) row in `command_registry.hpp`.

| Define | Value | File | Line |
|--------|-------|------|------|
| `IDM_EDIT_MULTICURSOR_REMOVE` | 210 | ide_constants.h | 24 |
| `IDM_EDIT_TOGGLE_COMMENT` | 212 | qtapp/MainWindowSimple.h | 41 |
| `IDM_SEL_SELECT_ALL_OCCURRENCES` | 308 | qtapp/MainWindowSimple.h | 51 |
| `IDM_VIEW_EXTENSIONS` | 411 | qtapp/MainWindowSimple.h | 64 |
| `IDM_VIEW_PROBLEMS` | 412 | qtapp/MainWindowSimple.h | 65 |
| `IDM_RUN_STEP_OUT` | 507 | qtapp/MainWindowSimple.h | 79 |
| `IDM_RUN_CONTINUE` | 508 | qtapp/MainWindowSimple.h | 80 |
| `IDM_RUN_TOGGLE_BREAKPOINT` | 509 | qtapp/MainWindowSimple.h | 81 |
| `IDM_RUN_CLEAR_BREAKPOINTS` | 510 | qtapp/MainWindowSimple.h | 82 |
| `IDM_TERM_SPLIT` | 602 | qtapp/MainWindowSimple.h | 86 |
| `IDM_TERM_CLEAR` | 604 | qtapp/MainWindowSimple.h | 88 |
| `IDM_TERM_KILL` | 605 | qtapp/MainWindowSimple.h | 89 |
| `IDM_TERM_PWSH` | 606 | qtapp/MainWindowSimple.h | 90 |
| `IDM_TERM_CMD` | 607 | qtapp/MainWindowSimple.h | 91 |
| `IDM_TERM_GITBASH` | 608 | qtapp/MainWindowSimple.h | 92 |
| `IDM_TERM_RUN_FILE` | 609 | qtapp/MainWindowSimple.h | 93 |
| `IDM_HELP_WELCOME` | 701 | qtapp/MainWindowSimple.h | 96 |
| `IDM_HELP_RELEASE_NOTES` | 704 | qtapp/MainWindowSimple.h | 99 |
| `IDM_HELP_CHECK_UPDATES` | 705 | qtapp/MainWindowSimple.h | 100 |
| `IDM_HELP_REPORT_ISSUE` | 707 | qtapp/MainWindowSimple.h | 102 |
| `IDM_HELP_TIPS_TRICKS` | 708 | qtapp/MainWindowSimple.h | 103 |
| `IDM_MODEL_LOAD` | 801 | qtapp/MainWindowSimple.h | 106 |
| `IDM_MODEL_UNLOAD` | 802 | qtapp/MainWindowSimple.h | 107 |
| `IDM_MODEL_INFO` | 803 | qtapp/MainWindowSimple.h | 108 |
| `IDM_MODEL_RELOAD` | 804 | qtapp/MainWindowSimple.h | 109 |
| `IDM_MODEL_SETTINGS` | 805 | qtapp/MainWindowSimple.h | 110 |
| `IDM_EDIT_GOTO` | 1109 | ide/RawrXD_IDE_Win32.h | 95 |
| `IDM_BUILD_BUILD` | 1201 | ide/RawrXD_IDE_Win32.h | 98 |
| `IDM_BUILD_REBUILD` | 1202 | ide/RawrXD_IDE_Win32.h | 99 |
| `IDM_BUILD_RUN` | 1203 | ide/RawrXD_IDE_Win32.h | 100 |
| `IDM_BUILD_CLEAN` | 1204 | ide/RawrXD_IDE_Win32.h | 101 |
| `IDM_BUILD_STOP` | 1205 | ide/RawrXD_IDE_Win32.h | 102 |
| `IDM_DEBUG_START` | 1251 | ide/RawrXD_IDE_Win32.h | 105 |
| `IDM_DEBUG_ATTACH` | 1252 | ide/RawrXD_IDE_Win32.h | 106 |
| `IDM_DEBUG_STOP` | 1253 | ide/RawrXD_IDE_Win32.h | 107 |
| `IDM_DEBUG_BREAKPOINT` | 1254 | ide/RawrXD_IDE_Win32.h | 108 |
| `IDM_DEBUG_STEP_OVER` | 1255 | ide/RawrXD_IDE_Win32.h | 109 |
| `IDM_DEBUG_STEP_INTO` | 1256 | ide/RawrXD_IDE_Win32.h | 110 |
| `IDM_DEBUG_STEP_OUT` | 1257 | ide/RawrXD_IDE_Win32.h | 111 |
| `IDM_DEBUG_CONTINUE` | 1258 | ide/RawrXD_IDE_Win32.h | 112 |
| `IDM_DEBUG_RESTART` | 1259 | ide/RawrXD_IDE_Win32.h | 113 |
| `IDM_ERROR_NEXT` | 1261 | ide/RawrXD_IDE_Win32.h | 116 |
| `IDM_ERROR_PREV` | 1262 | ide/RawrXD_IDE_Win32.h | 117 |
| `IDM_ERROR_CLEAR` | 1263 | ide/RawrXD_IDE_Win32.h | 118 |
| `IDM_TOOLS_PE_INSPECTOR` | 1301 | ide/RawrXD_IDE_Win32.h | 121 |
| `IDM_TOOLS_INSTR_ENCODER` | 1302 | ide/RawrXD_IDE_Win32.h | 122 |
| `IDM_TOOLS_EXT_MANAGER` | 1303 | ide/RawrXD_IDE_Win32.h | 123 |
| `IDM_TOOLS_OPTIONS` | 1304 | ide/RawrXD_IDE_Win32.h | 124 |
| `IDM_TOOLS_SOVEREIGN_RUN` | 1305 | ide/RawrXD_IDE_Win32.h | 125 |
| `IDM_TOOLS_VIEW_EVIDENCE` | 1306 | ide/RawrXD_IDE_Win32.h | 126 |
| `IDM_TOOLS_DEBUG_TELEMETRY` | 1307 | ide/RawrXD_IDE_Win32.h | 127 |
| `IDM_VIEW_FILEBROWSER` | 1401 | ide/RawrXD_IDE_Win32.h | 130 |
| `IDM_VIEW_OUTPUT` | 1402 | ide/RawrXD_IDE_Win32.h | 131 |
| `IDM_VIEW_WIDGET` | 1403 | ide/RawrXD_IDE_Win32.h | 132 |
| `IDM_VIEW_FULLSCREEN` | 1404 | ide/RawrXD_IDE_Win32.h | 133 |
| `IDM_VIEW_DARK_THEME` | 1405 | ide/RawrXD_IDE_Win32.h | 134 |
| `IDM_VIEW_LIGHT_THEME` | 1406 | ide/RawrXD_IDE_Win32.h | 135 |
| `IDM_VIEW_LINE_NUMBERS` | 1407 | ide/RawrXD_IDE_Win32.h | 136 |
| `IDM_VIEW_WORD_WRAP` | 1408 | ide/RawrXD_IDE_Win32.h | 137 |
| `IDM_VIEW_FILE_EXPLORER` | 2030 | win32app/Win32IDE_Commands.h | 65 |
| `IDM_AUDIT_RUN` | 2101 | ide/RawrXD_IDE_Win32.h | 178 |
| `IDM_AUDIT_VIEW_REPORT` | 2102 | ide/RawrXD_IDE_Win32.h | 179 |
| `IDM_TELEMETRY_VIEW` | 2201 | ide/RawrXD_IDE_Win32.h | 182 |
| `IDM_TELEMETRY_EXPORT` | 2202 | ide/RawrXD_IDE_Win32.h | 183 |
| `IDM_HOTPATCH_APPLY` | 2301 | ide/RawrXD_IDE_Win32.h | 186 |
| `IDM_HOTPATCH_CREATE` | 2302 | ide/RawrXD_IDE_Win32.h | 187 |
| `IDM_HOTPATCH_STATUS` | 2303 | ide/RawrXD_IDE_Win32.h | 188 |
| `IDM_AUTONOMY_START` | 2402 | ide/RawrXD_IDE_Win32.h | 192 |
| `IDM_AUTONOMY_STOP` | 2403 | ide/RawrXD_IDE_Win32.h | 193 |
| `IDM_AUTONOMY_SET_GOAL` | 2404 | ide/RawrXD_IDE_Win32.h | 194 |
| `IDM_AUTONOMY_STATUS` | 2405 | ide/RawrXD_IDE_Win32.h | 195 |
| `IDM_AUTONOMY_MEMORY` | 2406 | ide/RawrXD_IDE_Win32.h | 196 |
| `IDM_REVENG_DISASM` | 2501 | ide/RawrXD_IDE_Win32.h | 199 |
| `IDM_REVENG_DECOMPILE` | 2502 | ide/RawrXD_IDE_Win32.h | 200 |
| `IDM_CRUCIBLE_RUN` | 2601 | ide/RawrXD_IDE_Win32.h | 203 |
| `IDM_CRUCIBLE_BENCHMARK` | 2602 | ide/RawrXD_IDE_Win32.h | 204 |
| `IDM_GAP_ANALYZE` | 2701 | ide/RawrXD_IDE_Win32.h | 207 |
| `IDM_GAP_FIX` | 2702 | ide/RawrXD_IDE_Win32.h | 208 |
| `IDM_BUILD_PROJECT` | 2801 | win32app/Win32IDE_Commands.cpp | 25 |
| `IDM_FEATURES_ENABLE` | 2801 | ide/RawrXD_IDE_Win32.h | 211 |
| `IDM_FEATURES_DISABLE` | 2802 | ide/RawrXD_IDE_Win32.h | 212 |
| `IDM_COMMANDS_PALETTE` | 2901 | ide/RawrXD_IDE_Win32.h | 215 |
| `IDM_TOOLS_GGUF_INSPECTOR` | 3014 | win32app/Win32IDE.cpp | 716 |
| `IDM_ENT_MULTI_GPU_BALANCE` | 3042 | win32app/Win32IDE_Commands.cpp | 252 |
| `IDM_ENT_DYNAMIC_BATCH` | 3043 | win32app/Win32IDE_Commands.cpp | 255 |
| `IDM_ENT_API_KEY_MGMT` | 3044 | win32app/Win32IDE_Commands.cpp | 258 |
| `IDM_ENT_AUDIT_LOGS` | 3045 | win32app/Win32IDE_Commands.cpp | 261 |
| `IDM_ENT_RAWR_TUNER` | 3046 | win32app/Win32IDE_Commands.cpp | 264 |
| `IDM_ENT_DUAL_ENGINE` | 3047 | win32app/Win32IDE_Commands.cpp | 267 |
| `IDM_VIEW_COLLABORATION` | 3060 | win32app/Win32IDE_Commands.h | 67 |
| `IDM_PLATFORM_EXT_CREATOR` | 3301 | ide/RawrXD_IDE_Win32.h | 234 |
| `IDM_PLATFORM_MODEL_CREATOR` | 3302 | ide/RawrXD_IDE_Win32.h | 235 |
| `IDM_PLATFORM_NATIVE_INTEL` | 3303 | ide/RawrXD_IDE_Win32.h | 236 |
| `IDM_PLATFORM_MASM_LEXER` | 3304 | ide/RawrXD_IDE_Win32.h | 237 |
| `IDM_PLATFORM_AST_BRIDGE` | 3305 | ide/RawrXD_IDE_Win32.h | 238 |
| `IDM_PLATFORM_RT_ENGINE` | 3306 | ide/RawrXD_IDE_Win32.h | 239 |
| `IDM_COMPILER_ASSEMBLY` | 3401 | ide/RawrXD_IDE_Win32.h | 242 |
| `IDM_COMPILER_EON` | 3402 | ide/RawrXD_IDE_Win32.h | 243 |
| `IDM_COMPILER_UNIVERSAL` | 3403 | ide/RawrXD_IDE_Win32.h | 244 |
| `IDM_COMPILER_CROSS` | 3404 | ide/RawrXD_IDE_Win32.h | 245 |
| `IDM_COMPILER_QUANTUM` | 3405 | ide/RawrXD_IDE_Win32.h | 246 |
| `IDM_COMPILER_C` | 3410 | ide/RawrXD_IDE_Win32.h | 247 |
| `IDM_COMPILER_CPP` | 3411 | ide/RawrXD_IDE_Win32.h | 248 |
| `IDM_COMPILER_RUST` | 3412 | ide/RawrXD_IDE_Win32.h | 249 |
| `IDM_COMPILER_ZIG` | 3413 | ide/RawrXD_IDE_Win32.h | 250 |
| `IDM_COMPILER_GO` | 3414 | ide/RawrXD_IDE_Win32.h | 251 |
| `IDM_COMPILER_SWIFT` | 3415 | ide/RawrXD_IDE_Win32.h | 252 |
| `IDM_COMPILER_HASKELL` | 3420 | ide/RawrXD_IDE_Win32.h | 253 |
| `IDM_COMPILER_OCAML` | 3421 | ide/RawrXD_IDE_Win32.h | 254 |
| `IDM_COMPILER_ERLANG` | 3422 | ide/RawrXD_IDE_Win32.h | 255 |
| `IDM_COMPILER_ELIXIR` | 3423 | ide/RawrXD_IDE_Win32.h | 256 |
| `IDM_COMPILER_CLOJURE` | 3424 | ide/RawrXD_IDE_Win32.h | 257 |
| `IDM_COMPILER_LISP` | 3425 | ide/RawrXD_IDE_Win32.h | 258 |
| `IDM_COMPILER_JS` | 3430 | ide/RawrXD_IDE_Win32.h | 259 |
| `IDM_COMPILER_TS` | 3431 | ide/RawrXD_IDE_Win32.h | 260 |
| `IDM_COMPILER_DART` | 3432 | ide/RawrXD_IDE_Win32.h | 261 |
| `IDM_COMPILER_WASM` | 3433 | ide/RawrXD_IDE_Win32.h | 262 |
| `IDM_COMPILER_FORTRAN` | 3440 | ide/RawrXD_IDE_Win32.h | 263 |
| `IDM_COMPILER_COBOL` | 3441 | ide/RawrXD_IDE_Win32.h | 264 |
| `IDM_COMPILER_PASCAL` | 3442 | ide/RawrXD_IDE_Win32.h | 265 |
| `IDM_COMPILER_DELPHI` | 3443 | ide/RawrXD_IDE_Win32.h | 266 |
| `IDM_COMPILER_VB` | 3444 | ide/RawrXD_IDE_Win32.h | 267 |
| `IDM_COMPILER_ADA` | 3445 | ide/RawrXD_IDE_Win32.h | 268 |
| `IDM_COMPILER_JVM` | 3450 | ide/RawrXD_IDE_Win32.h | 269 |
| `IDM_COMPILER_PYTHON` | 3451 | ide/RawrXD_IDE_Win32.h | 270 |
| `IDM_COMPILER_LUA` | 3452 | ide/RawrXD_IDE_Win32.h | 271 |
| `IDM_COMPILER_RUBY` | 3453 | ide/RawrXD_IDE_Win32.h | 272 |
| `IDM_COMPILER_PERL` | 3454 | ide/RawrXD_IDE_Win32.h | 273 |
| `IDM_COMPILER_PHP` | 3455 | ide/RawrXD_IDE_Win32.h | 274 |
| `IDM_COMPILER_POWERSHELL` | 3456 | ide/RawrXD_IDE_Win32.h | 275 |
| `IDM_COMPILER_JULIA` | 3457 | ide/RawrXD_IDE_Win32.h | 276 |
| `IDM_COMPILER_MATLAB` | 3458 | ide/RawrXD_IDE_Win32.h | 277 |
| `IDM_COMPILER_R` | 3459 | ide/RawrXD_IDE_Win32.h | 278 |
| `IDM_COMPILER_CRYSTAL` | 3460 | ide/RawrXD_IDE_Win32.h | 279 |
| `IDM_COMPILER_NIM` | 3461 | ide/RawrXD_IDE_Win32.h | 280 |
| `IDM_COMPILER_CARBON` | 3462 | ide/RawrXD_IDE_Win32.h | 281 |
| `IDM_COMPILER_JAI` | 3463 | ide/RawrXD_IDE_Win32.h | 282 |
| `IDM_COMPILER_ODIN` | 3464 | ide/RawrXD_IDE_Win32.h | 283 |
| `IDM_COMPILER_VALA` | 3465 | ide/RawrXD_IDE_Win32.h | 284 |
| `IDM_COMPILER_KOTLIN` | 3466 | ide/RawrXD_IDE_Win32.h | 285 |
| `IDM_COMPILER_SCALA` | 3467 | ide/RawrXD_IDE_Win32.h | 286 |
| `IDM_COMPILER_GROOVY` | 3468 | ide/RawrXD_IDE_Win32.h | 287 |
| `IDM_COMPILER_D` | 3469 | ide/RawrXD_IDE_Win32.h | 288 |
| `IDM_COMPILER_F` | 3470 | ide/RawrXD_IDE_Win32.h | 289 |
| `IDM_COMPILER_SOLIDITY` | 3471 | ide/RawrXD_IDE_Win32.h | 290 |
| `IDM_COMPILER_VYPER` | 3472 | ide/RawrXD_IDE_Win32.h | 291 |
| `IDM_COMPILER_MOVE` | 3473 | ide/RawrXD_IDE_Win32.h | 292 |
| `IDM_COMPILER_MOTOKO` | 3474 | ide/RawrXD_IDE_Win32.h | 293 |
| `IDM_COMPILER_BASH` | 3475 | ide/RawrXD_IDE_Win32.h | 294 |
| `IDM_COMPILER_LLVM` | 3476 | ide/RawrXD_IDE_Win32.h | 295 |
| `IDM_REVENG_DECRYPT` | 3503 | ide/RawrXD_IDE_Win32.h | 298 |
| `IDM_REVENG_ANALYZE` | 3504 | ide/RawrXD_IDE_Win32.h | 299 |
| `IDM_REVENG_RECOVER` | 3505 | ide/RawrXD_IDE_Win32.h | 300 |
| `IDM_REVENG_DUMPBIN` | 3510 | ide/RawrXD_IDE_Win32.h | 301 |
| `IDM_REVENG_OBJDUMP` | 3511 | ide/RawrXD_IDE_Win32.h | 302 |
| `IDM_REVENG_NM` | 3512 | ide/RawrXD_IDE_Win32.h | 303 |
| `IDM_REVENG_STRINGS` | 3513 | ide/RawrXD_IDE_Win32.h | 304 |
| `IDM_REVENG_HEXEDIT` | 3514 | ide/RawrXD_IDE_Win32.h | 305 |
| `IDM_REVENG_PATCH` | 3520 | ide/RawrXD_IDE_Win32.h | 306 |
| `IDM_REVENG_INJECT` | 3521 | ide/RawrXD_IDE_Win32.h | 307 |
| `IDM_REVENG_UNPACK` | 3522 | ide/RawrXD_IDE_Win32.h | 308 |
| `IDM_REVENG_DIFF` | 3523 | ide/RawrXD_IDE_Win32.h | 309 |
| `IDM_REVENG_SIGNATURE` | 3524 | ide/RawrXD_IDE_Win32.h | 310 |
| `IDM_PIPELINE_RUN` | 4160 | win32app/Win32IDE_Commands.h | 138 |
| `IDM_PIPELINE_AUTONOMY_START` | 4161 | win32app/Win32IDE_Commands.h | 139 |
| `IDM_PIPELINE_AUTONOMY_STOP` | 4162 | win32app/Win32IDE_Commands.h | 140 |
| `IDM_AGENT_AUTONOMOUS_COMMUNICATOR` | 4163 | win32app/Win32IDE.cpp | 739 |
| `IDM_TELEMETRY_UNIFIED_CORE` | 4164 | win32app/Win32IDE.cpp | 740 |
| `IDM_GGUF_TREE` | 4204 | win32app/resource.h | 90 |
| `IDM_AI_MODE_SWARM` | 4204 | win32app/Win32IDE_Commands.h | 147 |
| `IDM_GGUF_DETAILS` | 4205 | win32app/resource.h | 91 |
| `IDM_AI_LOAD_SWARM_DIR` | 4205 | win32app/Win32IDE_Commands.h | 148 |
| `IDM_AI_CONTEXT_UNLIMITED` | 4217 | win32app/Win32IDE_Commands.h | 158 |
| `IDM_AI_AGENT_CYCLES_SET` | 4217 | win32app/Win32IDE_Commands.h | 159 |
| `IDM_AI_AGENT_MULTI_ENABLE` | 4218 | win32app/Win32IDE_Commands.h | 160 |
| `IDM_AI_AGENT_MULTI_DISABLE` | 4219 | win32app/Win32IDE_Commands.h | 161 |
| `IDM_ENGINE_UNLOCK_800B` | 4220 | win32app/Win32IDE_Commands.h | 164 |
| `IDM_ENGINE_LOAD_800B` | 4221 | win32app/Win32IDE_Commands.h | 165 |
| `IDM_TITAN_TOGGLE` | 4230 | win32app/Win32IDE_Commands.h | 166 |
| `IDM_AI_AGENT_MULTI_STATUS` | 4240 | win32app/Win32IDE_Commands.h | 170 |
| `IDM_AI_TITAN_TOGGLE` | 4241 | win32app/Win32IDE_Commands.h | 171 |
| `IDM_AI_800B_STATUS` | 4242 | win32app/Win32IDE_Commands.h | 172 |
| `IDM_OMEGA_START` | 4243 | win32app/Win32IDE_Commands.h | 176 |
| `IDM_OMEGA_STOP` | 4244 | win32app/Win32IDE_Commands.h | 177 |
| `IDM_OMEGA_SUBMIT_TASK` | 4245 | win32app/Win32IDE_Commands.h | 178 |
| `IDM_OMEGA_RUN_CYCLE` | 4246 | win32app/Win32IDE_Commands.h | 179 |
| `IDM_OMEGA_SHOW_STATUS` | 4247 | win32app/Win32IDE_Commands.h | 180 |
| `IDM_OMEGA_VIEW_PIPELINE` | 4248 | win32app/Win32IDE_Commands.h | 181 |
| `IDM_OMEGA_SET_QUALITY_AUTO` | 4250 | win32app/Win32IDE_Commands.h | 183 |
| `IDM_OMEGA_SET_QUALITY_BALANCE` | 4251 | win32app/Win32IDE_Commands.h | 184 |
| `IDM_OMEGA_WORLD_MODEL` | 4254 | win32app/Win32IDE_Commands.h | 187 |
| `IDM_OMEGA_EXPORT_STATS` | 4255 | win32app/Win32IDE_Commands.h | 188 |
| `IDM_OMEGA_DIAGNOSTICS` | 4256 | win32app/Win32IDE_Commands.h | 189 |
| `IDM_OMEGA_VERSION` | 4257 | win32app/Win32IDE_Commands.h | 190 |
| `IDM_OMEGA_HELP` | 4258 | win32app/Win32IDE_Commands.h | 191 |
| `IDM_OMEGA_ADVANCED_SETTINGS` | 4259 | win32app/Win32IDE_Commands.h | 192 |
| `IDM_OMEGA_SHELL_INTEGRATION` | 4260 | win32app/Win32IDE_Commands.h | 193 |
| `IDM_PLANNING_START` | 4261 | win32app/Win32IDE_Commands.h | 197 |
| `IDM_PLANNING_SHOW_QUEUE` | 4262 | win32app/Win32IDE_Commands.h | 198 |
| `IDM_PLANNING_APPROVE_STEP` | 4263 | win32app/Win32IDE_Commands.h | 199 |
| `IDM_PLANNING_REJECT_STEP` | 4264 | win32app/Win32IDE_Commands.h | 200 |
| `IDM_PLANNING_EXECUTE_STEP` | 4265 | win32app/Win32IDE_Commands.h | 201 |
| `IDM_PLANNING_EXECUTE_ALL` | 4266 | win32app/Win32IDE_Commands.h | 202 |
| `IDM_PLANNING_ROLLBACK` | 4267 | win32app/Win32IDE_Commands.h | 203 |
| `IDM_PLANNING_SET_POLICY` | 4268 | win32app/Win32IDE_Commands.h | 204 |
| `IDM_PLANNING_VIEW_STATUS` | 4269 | win32app/Win32IDE_Commands.h | 205 |
| `IDM_PLANNING_DIAGNOSTICS` | 4270 | win32app/Win32IDE_Commands.h | 206 |
| `IDM_KNOWLEDGE_INIT` | 4271 | win32app/Win32IDE_Commands.h | 210 |
| `IDM_KNOWLEDGE_RECORD` | 4272 | win32app/Win32IDE_Commands.h | 211 |
| `IDM_KNOWLEDGE_SEARCH` | 4273 | win32app/Win32IDE_Commands.h | 212 |
| `IDM_KNOWLEDGE_DECISIONS` | 4274 | win32app/Win32IDE_Commands.h | 213 |
| `IDM_KNOWLEDGE_PREFERENCES` | 4275 | win32app/Win32IDE_Commands.h | 214 |
| `IDM_KNOWLEDGE_ARCHAEOLOGY` | 4276 | win32app/Win32IDE_Commands.h | 215 |
| `IDM_KNOWLEDGE_GRAPH` | 4277 | win32app/Win32IDE_Commands.h | 216 |
| `IDM_KNOWLEDGE_EXPORT` | 4278 | win32app/Win32IDE_Commands.h | 217 |
| `IDM_KNOWLEDGE_STATS` | 4279 | win32app/Win32IDE_Commands.h | 218 |
| `IDM_KNOWLEDGE_FLUSH` | 4280 | win32app/Win32IDE_Commands.h | 219 |
| `IDM_FAILURE_DETECT` | 4281 | win32app/Win32IDE_Commands.h | 223 |
| `IDM_FAILURE_ANALYZE` | 4282 | win32app/Win32IDE_Commands.h | 224 |
| `IDM_FAILURE_SHOW_QUEUE` | 4283 | win32app/Win32IDE_Commands.h | 225 |
| `IDM_FAILURE_SHOW_HISTORY` | 4284 | win32app/Win32IDE_Commands.h | 226 |
| `IDM_FAILURE_GENERATE_RECOVERY` | 4285 | win32app/Win32IDE_Commands.h | 227 |
| `IDM_FAILURE_EXECUTE_RECOVERY` | 4286 | win32app/Win32IDE_Commands.h | 228 |
| `IDM_FAILURE_AUTONOMOUS_HEAL` | 4287 | win32app/Win32IDE_Commands.h | 229 |
| `IDM_FAILURE_VIEW_PATTERNS` | 4288 | win32app/Win32IDE_Commands.h | 230 |
| `IDM_FAILURE_LEARN_PATTERN` | 4289 | win32app/Win32IDE_Commands.h | 231 |
| `IDM_FAILURE_STATS` | 4290 | win32app/Win32IDE_Commands.h | 232 |
| `IDM_FAILURE_SET_POLICY` | 4291 | win32app/Win32IDE_Commands.h | 233 |
| `IDM_FAILURE_SHOW_HEALTH` | 4292 | win32app/Win32IDE_Commands.h | 234 |
| `IDM_FAILURE_EXPORT_ANALYSIS` | 4293 | win32app/Win32IDE_Commands.h | 235 |
| `IDM_FAILURE_CLEAR_HISTORY` | 4294 | win32app/Win32IDE_Commands.h | 236 |
| `IDM_FAILURE_DIAGNOSTICS` | 4295 | win32app/Win32IDE_Commands.h | 237 |
| `IDM_REVENG_SET_BINARY_FROM_ACTIVE` | 4320 | win32app/Win32IDE_Commands.h | 277 |
| `IDM_REVENG_SET_BINARY_FROM_DEBUG_TARGET` | 4321 | win32app/Win32IDE_Commands.h | 278 |
| `IDM_REVENG_SET_BINARY_FROM_BUILD_OUTPUT` | 4322 | win32app/Win32IDE_Commands.h | 279 |
| `IDM_REVENG_DISASM_AT_RIP` | 4323 | win32app/Win32IDE_Commands.h | 280 |
| `IDM_IMPACT_ANALYZE_STAGED` | 4350 | win32app/Win32IDE_Commands.h | 244 |
| `IDM_IMPACT_ANALYZE_UNSTAGED` | 4351 | win32app/Win32IDE_Commands.h | 245 |
| `IDM_IMPACT_ANALYZE_FILE` | 4352 | win32app/Win32IDE_Commands.h | 246 |
| `IDM_IMPACT_SHOW_REPORT` | 4353 | win32app/Win32IDE_Commands.h | 247 |
| `IDM_IMPACT_SHOW_ZONES` | 4354 | win32app/Win32IDE_Commands.h | 248 |
| `IDM_IMPACT_RISK_SCORE` | 4355 | win32app/Win32IDE_Commands.h | 249 |
| `IDM_IMPACT_CHECK_COMMIT` | 4356 | win32app/Win32IDE_Commands.h | 250 |
| `IDM_IMPACT_SET_CONFIG` | 4357 | win32app/Win32IDE_Commands.h | 251 |
| `IDM_IMPACT_HISTORY` | 4358 | win32app/Win32IDE_Commands.h | 252 |
| `IDM_IMPACT_DIAGNOSTICS` | 4359 | win32app/Win32IDE_Commands.h | 253 |
| `IDM_IMPACT_EXPORT_JSON` | 4360 | win32app/Win32IDE_Commands.h | 254 |
| `IDM_ROUTER_ENSEMBLE_ENABLE` | 5076 | win32app/Win32IDE_Commands.h | 340 |
| `IDM_ROUTER_ENSEMBLE_DISABLE` | 5077 | win32app/Win32IDE_Commands.h | 341 |
| `IDM_ROUTER_ENSEMBLE_STATUS` | 5078 | win32app/Win32IDE_Commands.h | 342 |
| `IDM_HYBRID_EXPLAIN_SYMBOL` | 5101 | win32app/Win32IDE.h | 3763 |
| `IDM_HYBRID_STREAM_ANALYZE` | 5103 | win32app/Win32IDE.h | 3765 |
| `IDM_HYBRID_SEMANTIC_PREFETCH` | 5104 | win32app/Win32IDE.h | 3766 |
| `IDM_HYBRID_CORRECTION_LOOP` | 5105 | win32app/Win32IDE.h | 3767 |
| `IDM_MULTI_RESP_SELECT_PREFERRED` | 5108 | win32app/Win32IDE.h | 3916 |
| `IDM_MULTI_RESP_TOGGLE_TEMPLATE` | 5112 | win32app/Win32IDE.h | 3920 |
| `IDM_MULTI_RESP_APPLY_PREFERRED` | 5117 | win32app/Win32IDE.h | 3925 |
| `IDM_CONFIDENCE_SET_POLICY` | 5131 | win32app/Win32IDE.h | 3976 |
| `IDM_SWARM_WORKER_DISCONNECT` | 5155 | win32app/Win32IDE.h | 4008 |
| `IDM_AI_MODEL_REGISTRY` | 5300 | win32app/Win32IDE_Commands.h | 359 |
| `IDM_AI_CHECKPOINT_MGR` | 5301 | win32app/Win32IDE_Commands.h | 360 |
| `IDM_AI_INTERPRET_PANEL` | 5302 | win32app/Win32IDE_Commands.h | 361 |
| `IDM_AI_CICD_SETTINGS` | 5303 | win32app/Win32IDE_Commands.h | 362 |
| `IDM_AI_MULTI_FILE_SEARCH` | 5304 | win32app/Win32IDE_Commands.h | 363 |
| `IDM_AI_BENCHMARK_MENU` | 5305 | win32app/Win32IDE_Commands.h | 364 |
| `IDM_VIEW_MONACO_SETTINGS` | 5310 | win32app/Win32IDE_Commands.h | 365 |
| `IDM_VIEW_THERMAL_DASHBOARD` | 5311 | win32app/Win32IDE_Commands.h | 366 |
| `IDM_AGENT_SMOKE_TEST` | 5320 | win32app/Win32IDE_Commands.h | 367 |
| `IDM_AGENT_SET_CYCLE_AGENT_COUNTER` | 5321 | win32app/Win32IDE_Commands.h | 368 |
| `IDM_AGENTIC_TOGGLE` | 6001 | agentic/Win32IDE_AgenticIntegration.h | 36 |
| `IDM_AGENTIC_PASSIVE` | 6002 | agentic/Win32IDE_AgenticIntegration.h | 37 |
| `IDM_AGENTIC_SUGGESTIVE` | 6003 | agentic/Win32IDE_AgenticIntegration.h | 38 |
| `IDM_AGENTIC_AUTONOMOUS` | 6004 | agentic/Win32IDE_AgenticIntegration.h | 39 |
| `IDM_SHOW_SUGGESTIONS` | 6005 | agentic/Win32IDE_AgenticIntegration.h | 40 |
| `IDM_APPROVE_ACTION` | 6006 | agentic/Win32IDE_AgenticIntegration.h | 41 |
| `IDM_REJECT_ACTION` | 6007 | agentic/Win32IDE_AgenticIntegration.h | 42 |
| `IDM_VIEW_AGENT_PANEL` | 7057 | win32app/Win32IDE_Commands.h | 69 |
| `IDM_HOTPATCH_BYTE_SEARCH` | 9005 | win32app/Win32IDE.h | 4264 |
| `IDM_HOTPATCH_SERVER_REMOVE` | 9007 | win32app/Win32IDE.h | 4266 |
| `IDM_HOTPATCH_PROXY_REWRITE` | 9009 | win32app/Win32IDE.h | 4268 |
| `IDM_HOTPATCH_PROXY_TERMINATE` | 9010 | win32app/Win32IDE.h | 4269 |
| `IDM_HOTPATCH_PROXY_VALIDATE` | 9011 | win32app/Win32IDE.h | 4270 |
| `IDM_HOTPATCH_RESET_STATS` | 9015 | win32app/Win32IDE.h | 4274 |
| `IDM_HOTPATCH_SHOW_PROXY_STATS` | 9017 | win32app/Win32IDE.h | 4276 |
| `IDM_HOTPATCH_SET_TARGET_TPS` | 9018 | win32app/Win32IDE.h | 4277 |
| `IDM_LSP_SERVER_EXPORT_SYMBOLS` | 9207 | win32app/Win32IDE.h | 4299 |
| `IDM_SECURITY_SCAN_SECRETS` | 9550 | win32app/Win32IDE_Commands.h | 406 |
| `IDM_SECURITY_SCAN_SAST` | 9551 | win32app/Win32IDE_Commands.h | 407 |
| `IDM_SECURITY_SCAN_DEPENDENCIES` | 9552 | win32app/Win32IDE_Commands.h | 408 |
| `IDM_SECURITY_DASHBOARD` | 9553 | win32app/Win32IDE_Commands.h | 409 |
| `IDM_SECURITY_EXPORT_SBOM` | 9554 | win32app/Win32IDE_Commands.h | 410 |
| `IDM_VOICE_MODE_CONTINUOUS` | 9708 | win32app/Win32IDE.h | 4369 |
| `IDM_TELEMETRY_EXPORT_JSON` | 9901 | win32app/Win32IDE.h | 4330 |
| `IDM_TELEMETRY_EXPORT_CSV` | 9902 | win32app/Win32IDE.h | 4331 |
| `IDM_TELEMETRY_SHOW_DASHBOARD` | 9903 | win32app/Win32IDE.h | 4332 |
| `IDM_VSCEXT_API_LIST_PROVIDERS` | 10003 | modules/vscode_extension_api.h | 1905 |
| `IDM_VSCEXT_API_DEACTIVATE_ALL` | 10008 | modules/vscode_extension_api.h | 1910 |
| `IDM_EDITOR_GOTO_WORKSPACE_SYMBOL` | 10207 | win32app/Win32IDE_Commands.h | 420 |
| `IDM_EDITOR_PEEK_DEFINITION` | 10208 | win32app/Win32IDE_Commands.h | 421 |
| `IDM_EDITOR_PEEK_REFERENCES` | 10209 | win32app/Win32IDE_Commands.h | 422 |
| `IDM_VIEW_TOGGLE_BOTTOM_PANEL` | 10250 | win32app/Win32IDE_Commands.h | 433 |
| `IDM_FILE_QUICK_OPEN` | 10251 | win32app/Win32IDE_Commands.h | 434 |
| `IDM_VOICE_TOGGLE_LISTENING` | 10300 | voice_automation.h | 276 |
| `IDM_VOICE_TOGGLE_TTS` | 10301 | voice_automation.h | 277 |
| `IDM_VOICE_SETTINGS` | 10302 | voice_automation.h | 278 |
| `IDM_VOICE_TTS_TEST` | 10303 | voice_automation.h | 279 |
| `IDM_BUILD_SOLUTION` | 10400 | win32app/Win32IDE_Commands.h | 438 |
| `IDM_DEBUG_TOGGLE_BREAKPOINT` | 10506 | win32app/Win32IDE_Commands.h | 450 |
| `IDM_DEBUG_SHOW_CALLSTACK` | 10507 | win32app/Win32IDE_Commands.h | 451 |
| `IDM_DEBUG_SHOW_VARIABLES` | 10508 | win32app/Win32IDE_Commands.h | 452 |
| `IDM_DEBUG_SHOW_WATCH` | 10509 | win32app/Win32IDE_Commands.h | 453 |
| `IDM_DEBUG_DETACH` | 10511 | win32app/Win32IDE_Commands.h | 455 |
| `IDM_ENT_MODEL_COMPARE` | 12330 | win32app/Win32IDE_Commands.cpp | 210 |
| `IDM_ENT_BATCH_PROCESS` | 12331 | win32app/Win32IDE_Commands.cpp | 213 |
| `IDM_ENT_CUSTOM_STOP_SEQ` | 12332 | win32app/Win32IDE_Commands.cpp | 216 |
| `IDM_ENT_GRAMMAR_CONSTRAINTS` | 12333 | win32app/Win32IDE_Commands.cpp | 219 |
| `IDM_ENT_LORA_ADAPTER` | 12334 | win32app/Win32IDE_Commands.cpp | 222 |
| `IDM_ENT_RESPONSE_CACHE` | 12335 | win32app/Win32IDE_Commands.cpp | 225 |
| `IDM_ENT_PROMPT_LIBRARY` | 12336 | win32app/Win32IDE_Commands.cpp | 228 |
| `IDM_ENT_SESSION_EXPORT_IMPORT` | 12337 | win32app/Win32IDE_Commands.cpp | 231 |
| `IDM_ENT_MODEL_SHARDING` | 12338 | win32app/Win32IDE_Commands.cpp | 234 |
| `IDM_ENT_TENSOR_PARALLEL` | 12339 | win32app/Win32IDE_Commands.cpp | 237 |
| `IDM_ENT_PIPELINE_PARALLEL` | 12340 | win32app/Win32IDE_Commands.cpp | 240 |
| `IDM_ENT_CUSTOM_QUANT` | 12341 | win32app/Win32IDE_Commands.cpp | 243 |
| `IDM_OMEGA_START_AUTONOMOUS` | 12400 | win32app/Win32IDE_Commands.cpp | 274 |
| `IDM_OMEGA_SET_GOAL` | 12401 | win32app/Win32IDE_Commands.cpp | 277 |
| `IDM_OMEGA_OBSERVE_PIPELINE` | 12402 | win32app/Win32IDE_Commands.cpp | 280 |
| `IDM_OMEGA_CANCEL_TASK` | 12403 | win32app/Win32IDE_Commands.cpp | 283 |
| `IDM_OMEGA_SPAWN_AGENT` | 12404 | win32app/Win32IDE_Commands.cpp | 286 |
| `IDM_OMEGA_GET_STATS` | 12405 | win32app/Win32IDE_Commands.cpp | 289 |

## ℹ️ Declared Handlers Not in COMMAND_TABLE

These handlers exist in `feature_handlers.h` but aren't
referenced by any COMMAND_TABLE entry. They may be called
directly or are waiting to be wired up.

- `handleAgentGoal`
- `handleBackendList`
- `handleBackendSelect`
- `handleBackendStatus`
- `handleBreakpointAdd`
- `handleBreakpointList`
- `handleBreakpointRemove`
- `handleConfidence`
- `handleConfidenceSetPolicy`
- `handleDebugContinue`
- `handleDebugStart`
- `handleDebugStep`
- `handleDebugStop`
- `handleExplain`
- `handleGovernor`
- `handleGovernorSetPowerLevel`
- `handleHistory`
- `handleHybridCorrectionLoop`
- `handleHybridExplainSymbol`
- `handleHybridSemanticPrefetch`
- `handleHybridStreamAnalyze`
- `handleMarketplaceInstall`
- `handleMultiRespApplyPreferred`
- `handleMultiRespSelectPreferred`
- `handleMultiRespToggleTemplate`
- `handleMultiResponse`
- `handlePolicy`
- `handleReplay`
- `handleRouterEnsembleDisable`
- `handleRouterEnsembleEnable`
- `handleRouterEnsembleStatus`
- `handleSafety`
- `handleSwarmDistribute`
- `handleSwarmRebalance`
- `handleTools`
