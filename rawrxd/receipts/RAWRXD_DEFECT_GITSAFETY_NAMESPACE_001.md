# RAWRXD_DEFECT_GITSAFETY_NAMESPACE_001

Status: **OPEN — blocking all IDE builds**
Date: 2026-10-01
Severity: build-breaking, shared header
Blocks: every `RawrXD-Win32IDE` build since ~21:10 local

## Symptom

```ini
GitSafetyAuthorityIdeSurface.cpp:218  error C2065: 'd': undeclared identifier
GitSafetyAuthorityIdeSurface.cpp:225  error C2039: 'ToolRequest' is not a member of
                                         'rawrxd::agentic::RawrXD::Agentic'
GitSafetyAuthorityIdeSurface.cpp:226  error C2039: 'ToolResult'  is not a member of
                                         'rawrxd::agentic::RawrXD::Agentic'
GitSafetyAuthorityIdeSurface.cpp:271  error C2027: use of undefined type
                                         'rawrxd::agentic::RawrXD::Agentic::AgentToolRegistry'
GitSafetyAuthorityTools.h:119-120     same namespace resolution failure
```

Observed identically across **three** builds spanning roughly 50 minutes, with no
intervening change to either file. That constancy is what distinguishes this from a
mid-edit transient.

## Root cause — established by inspection, not inference

`src/agentic/GitSafetyAuthorityTools.h`:

```cpp
18: namespace rawrxd {
19: namespace agentic {
...
106: namespace RawrXD { namespace Agentic { class AgentToolRegistry; } }
...
122: } // namespace agentic
123: } // namespace rawrxd
```

Line 106 sits **inside** `namespace rawrxd { namespace agentic {`. It therefore
declares

```cpp
::rawrxd::agentic::RawrXD::Agentic::AgentToolRegistry
```

The evident intent was a forward declaration of the **global**
`::RawrXD::Agentic::AgentToolRegistry`, which is the namespace `AgentCore` and the
tool registry actually use. Because the declaration is lexically nested, it
creates a parallel namespace tree that nothing else uses.

Then, in `src/agentic/GitSafetyAuthorityIdeSurface.cpp`:

```cpp
32: namespace rawrxd {
33: namespace agentic {
...
217: RawrXD::Agentic::ToolDescriptor d;
225: const RawrXD::Agentic::ToolRequest& req,
226:       RawrXD::Agentic::ToolContext&) -> RawrXD::Agentic::ToolResult
271: RawrXD::Agentic::AgentToolRegistry& registry
```

Name lookup for `RawrXD` from inside `rawrxd::agentic` finds the nested
`rawrXD` declared at `Tools.h:106` **before** it reaches the global namespace, so
every one of those references resolves to `rawrxd::agentic::RawrXD::Agentic::*` and
fails. The compiler names that exact scope in the diagnostic, which is what
confirms the mechanism rather than a guess.

Note `GitSafetyAuthorityIdeSurface.cpp:34` opens `namespace {` (anonymous), closed
by the bare `} // namespace` at line 148. That is balanced and is **not** part of
the fault; the brace depth of both files is zero at EOF.

## Correct form

The forward declaration must not be lexically nested. Either:

```cpp
// outside namespace rawrxd
namespace RawrXD { namespace Agentic { class AgentToolRegistry; } }
```

or, if it must stay in this header, close the enclosing namespaces first, or use
the global-scope operator explicitly:

```cpp
::namespace RawrXD { ::namespace Agentic { class AgentToolRegistry; } }
```

## Why this is a separate defect and not repaired here

1. It is **not in the P0 CPU/K-quant work.** Folding an unrelated namespace fix
   into that change set would make the P0 receipt cite a repair it did not make.
2. The file is **another agent's work.** It has been broken, unchanged, for
   roughly 50 minutes across three build attempts, which suggests it was
   abandoned mid-edit rather than actively maintained. Editing it risks
   colliding with whoever resumes it.
3. The user-visible consequence is confined to the IDE target. It does **not**
   affect the CPU-path gates, which build and run independently.

## Impact

```ini
IDE_TARGET_BUILD=BLOCKED
IDE_RUNTIME_CERT_RE_EXECUTION=BLOCKED
CPU_KQUANT_PARITY_GATES=UNAFFECTED   # build independently of the IDE target
```

Consequence for the certification state: the IDE gate has **one** valid executed
receipt (`9 PASS / 1 FAIL / 5 NOT_IMPLEMENTED / 1 BLOCKED`). The three gate
corrections — the `EditorEngine_SetText` fix, the non-empty-payload guard, and the
`--ide-cert-receipt=PATH` parsing fix — remain correctly classified
`IMPLEMENTED_NOT_REBUILT` until this defect is resolved and the gate re-run.
