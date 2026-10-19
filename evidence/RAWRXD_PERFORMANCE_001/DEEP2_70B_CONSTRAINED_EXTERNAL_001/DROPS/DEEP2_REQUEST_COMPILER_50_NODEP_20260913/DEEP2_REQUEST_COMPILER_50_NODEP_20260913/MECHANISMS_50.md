# 50 Reverse-Engineered De-complexing Mechanisms

1. **Goal Canonicalization** — Collapse equivalent wording into one stable objective representation.
2. **Constraint Lifting** — Hoist repeated global rules once and inherit them across affected nodes.
3. **Requirement Atomization** — Split compound instructions until each node has one observable done condition.
4. **Dependency Compression** — Merge equivalent prerequisite chains so downstream work shares upstream computation.
5. **Transitive-Prerequisite Elimination** — Remove edges already implied by longer dependency paths.
6. **Critical-Cut Detection** — Find the smallest unresolved cut whose completion unlocks the largest graph region.
7. **Information Bottleneck Search** — Resolve the uncertainty with the highest downstream ambiguity reduction first.
8. **Constraint-Satisfiability Prepass** — Detect contradictions before spending execution effort.
9. **Dominance Pruning** — Discard work strictly subsumed by stronger already-scheduled work.
10. **Proof-Carrying Nodes** — Attach evidence and authority directly to every completion transition.
11. **Evidence Transitivity** — Reuse sufficiently strong upstream proof instead of re-verifying identical claims.
12. **Authority Partitioning** — Keep UNKNOWN, PROJECTED, DERIVED and MEASURED results explicitly separate.
13. **State Snapshot Hashing** — Hash relevant plan state so unchanged regions are not recomputed.
14. **Incremental Replanning** — Recompute only the graph region affected by a state transition.
15. **Failure-Surface Localization** — Bind failures to the smallest responsible node/subsystem boundary.
16. **Negative-Knowledge Caching** — Remember proven dead ends so they are not rediscovered.
17. **Side-Effect Segregation** — Separate read-only, reversible, side-effecting and destructive execution lanes.
18. **Reversibility Ordering** — Prefer cheaper and easier-to-undo actions before irreversible ones.
19. **Speculation Budgeting** — Limit parallel hypotheses by expected information gain.
20. **Join-Late Execution** — Keep independent branches independent until a real join is required.
21. **Result Normalization** — Normalize heterogeneous results into status, authority, evidence and scope.
22. **Semantic Cache Keys** — Cache work by normalized meaning rather than raw prompt text.
23. **Completion Fixed-Point** — Repeat ready→execute→recompute until no newly actionable nodes remain.
24. **Minimum-Sufficient Response** — Emit only proven conclusions, blockers and next actions needed by the caller.
25. **Complexity Conservation Breaker** — Make runtime cost track irreducible graph work instead of prompt verbosity.
26. **Subgoal Fusion** — Fuse compatible sibling goals into one execution whose output satisfies all consumers.
27. **Dependency Fan-In Hoisting** — Move common prerequisites above branch points so they execute once.
28. **Dependency Fan-Out Sharing** — Broadcast one proven result to every compatible consumer instead of cloning work.
29. **Late Binding of Executors** — Compile work before choosing the tool/executor, enabling cheaper capability substitution.
30. **Capability Cost Ranking** — Rank eligible executors by correctness, latency, side effects and authority yield.
31. **Proof Obligation Minimization** — Request only the weakest proof sufficient to satisfy the downstream authority contract.
32. **Counterexample-First Validation** — Test the cheapest likely falsifier before performing exhaustive validation.
33. **Contradiction Frontier Isolation** — Confine incompatible requirements to a frontier instead of poisoning the entire plan.
34. **Monotonic State Advancement** — Prevent PASS nodes from silently regressing without an explicit invalidating state change.
35. **Idempotent Action Folding** — Collapse repeated safe actions whose repeated execution cannot improve the state.
36. **Checkpointed Re-entry** — Resume from sealed node state after interruption instead of replaying completed work.
37. **Hot-Path Requirement Promotion** — Promote prerequisites that block many high-priority consumers.
38. **Cold-Path Deferral** — Defer low-impact optional work until the critical path has cleared.
39. **Work-Conserving Scheduler** — Never leave an executor idle while an eligible independent node is ready.
40. **Uncertainty-Weighted Priority** — Prioritize nodes whose resolution removes the most uncertainty from downstream planning.
41. **Cut-Set Retry** — On failure, retry the minimum responsible cut rather than replaying the whole graph.
42. **Failure Memoization** — Cache failure signatures with state hashes so unchanged failures are not re-triggered.
43. **Boundary Contract Synthesis** — Derive explicit input/output/proof contracts where independently executed graph regions meet.
44. **Scope Firewalling** — Prevent local requirements from leaking into unrelated branches.
45. **Progressive Precision** — Start with the cheapest sufficient representation and refine only where decisions require it.
46. **Budget-Aware Degradation** — When resources tighten, preserve critical invariants while degrading optional precision/work.
47. **Output Schema Locking** — Fix result structure early so downstream consumers never re-interpret free-form outputs.
48. **Deterministic Tie-Breaking** — Resolve equal-priority choices with stable IDs/hashes for reproducible plans.
49. **Plan Hash Sealing** — Seal graph structure and state into a reproducible hash for receipts and invalidation.
50. **Closure Certificate** — Declare completion only when every required node is PASS/SKIPPED or explicitly bounded by HOLD/FAIL.

## Execution law

```text
RAW_REQUEST
 -> NORMALIZE
 -> ATOMIZE
 -> DEDUP
 -> CONTRADICTION_FRONTIER
 -> DEPENDENCY_GRAPH
 -> TRANSITIVE_REDUCTION
 -> DOMINANCE/FUSION
 -> RISK + UNCERTAINTY PRIORITY
 -> READY CUT
 -> LATE-BOUND EXECUTOR
 -> PROOF-CARRYING RESULT
 -> INCREMENTAL RECOMPUTE
 -> FIXED POINT
 -> CLOSURE CERTIFICATE
```

The drop implements the graph/state machinery directly and exposes integration seams for executor-specific policies such as capability cost ranking, counterexample execution, and budget control. It does not fabricate executor results.
