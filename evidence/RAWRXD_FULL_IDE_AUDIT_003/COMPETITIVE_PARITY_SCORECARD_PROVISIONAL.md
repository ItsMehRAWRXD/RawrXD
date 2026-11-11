# RawrXD IDE — Competitive Parity Scorecard (PROVISIONAL)

ASOF_UTC=2026-11-02T12:20:00Z  
PROVISIONAL_PLANNING_ESTIMATE=1  
MEASURED=0  
CERTIFIED=0  
COMPOSITE_OVERALL=61%  
PROMOTE=0  
TIP_CLIMB=HOLD  

**Law:** These percentages are engineering planning estimates only. They are **not** independently benchmarked completion scores. They must **not** be treated as PASS, CERTIFIED, or promotion evidence.  
`RAWRXD_FULL_IDE_AUDIT_003` file-by-file + sealed runtime reconciliation will replace or refute them.  
`SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS`

Authority commit: `a5ae60efecac790598e2e46d9e499eb8ac7287af`  
Workspace: `F:\rawrxd`

## Composite

Estimated overall IDE parity: **61%** provisional (~39 pp remaining).

## Subsystem table (planning %)

| # | Subsystem | Parity % |
|---|-----------|----------|
| 1 | Native Win32 IDE architecture | 85 |
| 2 | Main window and layout system | 85 |
| 3 | Code editor fundamentals | 78 |
| 4 | Syntax highlighting | 75 |
| 5 | Multi-tab document editing | 82 |
| 6 | File explorer and navigation | 80 |
| 7 | Project/workspace management | 72 |
| 8 | File search and global search | 70 |
| 9 | Command palette and commands | 65 |
| 10 | Keyboard shortcuts and bindings | 68 |
| 11 | Themes and UI customization | 75 |
| 12 | Settings and persistence | 72 |
| 13 | Integrated terminal | 72 |
| 14 | Git/source control integration | 58 |
| 15 | Debugging and breakpoints | 45 |
| 16 | Language intelligence/LSP | 55 |
| 17 | Diagnostics and error navigation | 62 |
| 18 | Refactoring/code actions | 48 |
| 19 | Extensions/plugins | 38 |
| 20 | AI chat interface | 78 |
| 21 | Multiple chat sessions | 75 |
| 22 | AI streaming responses | 75 |
| 23 | Local model selection/routing | 80 |
| 24 | GhostText inline completion | 62 |
| 25 | GhostText cancellation/races | 55 |
| 26 | Agentic tool calling | 72 |
| 27 | Autonomous coding workflows | 65 |
| 28 | Multi-agent orchestration | 48 |
| 29 | File edits and change tracking | 72 |
| 30 | Agent rollback and recovery | 58 |
| 31 | Context management | 60 |
| 32 | Local inference integration | 78 |
| 33 | GGUF/model compatibility | 65 |
| 34 | Vulkan inference execution | 50 |
| 35 | GPU numerical correctness | 38 |
| 36 | Multi-GPU orchestration | 28 |
| 37 | MoE streaming/large models | 45 |
| 38 | REAP runtime controls | 72 |
| 39 | Performance and responsiveness | 48 |
| 40 | Stability/crash recovery | 40 |
| 41 | Security and permissions | 55 |
| 42 | Build and test infrastructure | 78 |
| 43 | Installer/distribution | 42 |
| 44 | Documentation/onboarding | 48 |
| 45 | Production certification | 25 |

## Competitor-relative (planning only)

| Competitor | RawrXD estimated parity |
|------------|-------------------------|
| VS Code | 65% |
| Cursor | 61% |
| Windsurf | 60% |
| GitHub Copilot | 66% |
| Visual Studio | 48% |
| JetBrains | 45% |
| LM Studio (local AI) | 68% |
| Ollama (local models) | 72% |

## Audit priority order (from scorecard)

**P0:** GPU numerical correctness · Production certification · Stability/crash recovery · GhostText races/routing  
**P1:** Multi-agent orchestration · Multi-GPU · Debugging · Agent rollback  
**P2:** LSP · Extensions · Installer/onboarding  

## Qwen3.6 GPU note (non-promotion)

Latest Qwen3.6 GPU trace (1,412 GPU calls, 0 CPU fallback) improves *execution-path* assessment only. Internal diagnostic failure + missing independent reference ⇒ **no** equivalent lift to GPU numerical-correctness parity or PROMOTE.
