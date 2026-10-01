# RawrXD Beyond-Parity Implementation Manifest

Generated requirements are not proof of implementation.

A gate remains PENDING until runtime/source evidence proves every required property.

## FOUNDATION

Gate: `RAWRXD_FOUNDATION_001`

- [ ] Local model loading by GGUF path
- [ ] Ollama manifest -> blob resolution without relocation
- [ ] Streaming token generation
- [ ] Cancellation
- [ ] Deterministic error propagation
- [ ] No fake-success fallback
- [ ] Runtime telemetry

## RESPONSE_AGENT

Gate: `RAWRXD_RESPONSE_CODED_AGENT_001`

- [ ] USER -> MODEL
- [ ] MODEL -> optional structured TOOL request
- [ ] Tool request validated by authority
- [ ] Real tool execution
- [ ] Observation returned to model
- [ ] MODEL -> FINAL RESPONSE
- [ ] STOP after response
- [ ] No autonomous background execution

## SESSION

Gate: `RAWRXD_SESSION_AUTHORITY_001`

- [ ] Persistent conversation history
- [ ] System/user/assistant/tool roles
- [ ] Context-window accounting
- [ ] Token-budget management
- [ ] Conversation truncation/summarization
- [ ] Tool observations retained
- [ ] Cancellation-safe session state

## TOOL_AUTHORITY

Gate: `RAWRXD_TOOL_AUTHORITY_001`

- [ ] Named tool registry
- [ ] Structured arguments
- [ ] Per-tool authorization
- [ ] Read/write distinction
- [ ] Workspace boundary enforcement
- [ ] No arbitrary shell by default
- [ ] Exit-code capture
- [ ] stdout/stderr capture
- [ ] Timeout
- [ ] Cancellation
- [ ] Audit receipt

## FILESYSTEM

Gate: `RAWRXD_FILESYSTEM_AGENT_001`

- [ ] List files
- [ ] Read file
- [ ] Read range
- [ ] Search text
- [ ] Search regex
- [ ] Find files
- [ ] Workspace-relative canonical paths
- [ ] Write file with authority
- [ ] Patch exact ranges
- [ ] Create file
- [ ] Delete only with explicit authority

## CODE_INDEX

Gate: `RAWRXD_CODE_INDEX_001`

- [ ] Repository enumeration
- [ ] Language detection
- [ ] Symbol extraction
- [ ] Definition lookup
- [ ] Reference lookup
- [ ] Incremental invalidation
- [ ] Relevant-context retrieval
- [ ] No mandatory cloud dependency

## EDIT_ENGINE

Gate: `RAWRXD_EDIT_AUTHORITY_001`

- [ ] Exact patch application
- [ ] Multi-file transaction
- [ ] Preimage verification
- [ ] Reject stale patch
- [ ] Diff preview
- [ ] Rollback
- [ ] Concurrent-writer detection
- [ ] Do not absorb unrelated worktree changes

## TERMINAL

Gate: `RAWRXD_TERMINAL_AUTHORITY_001`

- [ ] Explicit command authority
- [ ] Working-directory control
- [ ] Environment control
- [ ] stdout/stderr streaming
- [ ] Exit status
- [ ] Timeout
- [ ] Cancellation
- [ ] Process-tree termination
- [ ] No implicit unrestricted shell

## BUILD

Gate: `RAWRXD_BUILD_AGENT_001`

- [ ] Discover configured build system
- [ ] Invoke real compiler/build
- [ ] Capture diagnostics
- [ ] Associate errors with files/lines
- [ ] Return diagnostics to model
- [ ] Rebuild after authorized edit
- [ ] Never convert build failure into PASS

## TEST

Gate: `RAWRXD_TEST_AGENT_001`

- [ ] Discover tests
- [ ] Run selected test
- [ ] Run relevant tests
- [ ] Capture failure output
- [ ] Return failures to model
- [ ] Re-run after repair
- [ ] Receipt uses actual process result

## DIAGNOSTICS

Gate: `RAWRXD_DIAGNOSTICS_001`

- [ ] Compiler diagnostics
- [ ] Runtime failure capture
- [ ] Crash/exit-code reporting
- [ ] Model runtime diagnostics
- [ ] Tool failure diagnostics
- [ ] Source-location linking

## GIT

Gate: `RAWRXD_GIT_AGENT_001`

- [ ] status
- [ ] diff
- [ ] log
- [ ] show
- [ ] branch inspection
- [ ] Concurrent-writer protection
- [ ] Explicit authority before mutation
- [ ] No automatic commit/push without authority

## PLAN

Gate: `RAWRXD_PLAN_AGENT_001`

- [ ] Convert request into bounded steps
- [ ] Identify required evidence
- [ ] Select tools
- [ ] Track completed/pending steps
- [ ] Re-plan from real observations
- [ ] Stop when requested objective is satisfied
- [ ] No invented completion

## CODE_AGENT

Gate: `RAWRXD_CODE_AGENT_001`

- [ ] Understand request
- [ ] Retrieve relevant code
- [ ] Form implementation plan
- [ ] Produce authorized edits
- [ ] Build
- [ ] Inspect diagnostics
- [ ] Repair
- [ ] Test
- [ ] Report actual state

## DEBUG_AGENT

Gate: `RAWRXD_DEBUG_AGENT_001`

- [ ] Reproduce failure
- [ ] Collect evidence
- [ ] Form hypothesis
- [ ] Inspect relevant implementation
- [ ] Apply authorized repair
- [ ] Re-run reproduction
- [ ] Reject repair if evidence does not improve

## ASK_AGENT

Gate: `RAWRXD_ASK_AGENT_001`

- [ ] Read-only
- [ ] Repository-aware
- [ ] Can retrieve definitions/references
- [ ] Can inspect Git history
- [ ] Cannot mutate workspace
- [ ] Answers grounded in retrieved evidence

## ORCHESTRATION

Gate: `RAWRXD_ORCHESTRATION_001`

- [ ] Bounded task decomposition
- [ ] Independent worker contexts
- [ ] Tool authority inherited, never expanded
- [ ] Result aggregation
- [ ] Conflict detection
- [ ] No duplicate writers to same path
- [ ] Final verifier

## IDE_CHAT

Gate: `RAWRXD_IDE_CHAT_001`

- [ ] Prompt entry
- [ ] Streaming response
- [ ] Cancel generation
- [ ] Conversation history
- [ ] Tool-call visualization
- [ ] Tool result visualization
- [ ] File references
- [ ] Diagnostic references
- [ ] Apply/reject edits
- [ ] No GUI-only fake chat

## INLINE_CODE

Gate: `RAWRXD_INLINE_CODE_001`

- [ ] Selection -> model
- [ ] Current file context
- [ ] Generate replacement
- [ ] Preview diff
- [ ] Accept/reject
- [ ] Undo

## COMPLETION

Gate: `RAWRXD_COMPLETION_001`

- [ ] Cursor-position context
- [ ] Prefix/suffix context
- [ ] Low-latency generation
- [ ] Cancellation on edit
- [ ] Accept partial/full suggestion
- [ ] Local model provider

## CONTEXT_ENGINE

Gate: `RAWRXD_CONTEXT_ENGINE_001`

- [ ] Current file
- [ ] Selection
- [ ] Open files
- [ ] Diagnostics
- [ ] Git diff
- [ ] Relevant repository symbols
- [ ] Explicit attached files
- [ ] Token-budget prioritization

## MODEL_ROUTER

Gate: `RAWRXD_MODEL_ROUTER_001`

- [ ] GGUF path
- [ ] Ollama reference
- [ ] Deep2 local runtime
- [ ] Per-task model selection
- [ ] Capability metadata
- [ ] Context limits
- [ ] No required external service

## LONG_TASK

Gate: `RAWRXD_LONG_TASK_AGENT_001`

- [ ] Explicit user-started task only
- [ ] Persistent task state
- [ ] Checkpoint after tool operations
- [ ] Bounded iteration budget
- [ ] Cancellation
- [ ] Failure state
- [ ] No fake completion
- [ ] Final evidence summary

## AUTHORITY

Gate: `RAWRXD_AGENT_AUTHORITY_001`

- [ ] READ authority
- [ ] WRITE authority
- [ ] BUILD authority
- [ ] TEST authority
- [ ] GIT mutation authority
- [ ] PROCESS authority
- [ ] NETWORK authority
- [ ] Per-task capability set
- [ ] Default deny

## RECEIPTS

Gate: `RAWRXD_AGENT_RECEIPTS_001`

- [ ] Model identity
- [ ] Resolved model path
- [ ] Prompt turn count
- [ ] Tool requests
- [ ] Authority decisions
- [ ] Real tool outputs
- [ ] Files changed
- [ ] Build result
- [ ] Test result
- [ ] Fallback count
- [ ] Final verdict

## BEYOND_PARITY

Gate: `RAWRXD_BEYOND_PARITY_001`

- [ ] Local inference works
- [ ] Response agent works
- [ ] Repository context works
- [ ] Read tools work
- [ ] Authorized edits work
- [ ] Build/test repair works
- [ ] IDE chat uses same agent core
- [ ] Completion works
- [ ] Debug mode works
- [ ] Ask mode is read-only
- [ ] Code mode performs verified work
- [ ] Long task is bounded/cancellable
- [ ] No required cloud inference
- [ ] No stub fallback
- [ ] No fake receipts

