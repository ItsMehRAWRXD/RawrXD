# Sovereign IDE - Architecture Decision Records
## Internal Engineering Guide

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** ✅ Complete

---

## Table of Contents

1. [Overview](#overview)
2. [ADR-001: MASM Kernel](#adr-001-masm-kernel)
3. [ADR-002: SEG Execution Model](#adr-002-seg-execution-model)
4. [ADR-003: MoE Routing](#adr-003-moe-routing)
5. [ADR-004: Batch Architecture](#adr-004-batch-architecture)
6. [ADR-005: Agentic Surfaces](#adr-005-agentic-surfaces)
7. [ADR-006: SDK Design](#adr-006-sdk-design)
8. [ADR-007: Build System](#adr-007-build-system)
9. [ADR-008: Memory Model](#adr-008-memory-model)
10. [ADR-009: Testing Strategy](#adr-009-testing-strategy)
11. [ADR-010: Documentation Strategy](#adr-010-documentation-strategy)

---

## Overview

This document records the architectural decisions made during the development of the Sovereign IDE.

### ADR Format

Each ADR follows this structure:
- **Status:** Proposed, Accepted, Deprecated, Superseded
- **Context:** Forces at play and constraints
- **Decision:** The response to forces
- **Consequences:** What becomes easier or harder

---

## ADR-001: MASM Kernel

**Status:** ✅ Accepted

### Context

The Sovereign IDE requires a deterministic, high-performance foundation. We needed to choose between:

1. **Pure C/C++** - Portable, familiar, but less control over execution
2. **MASM Assembly** - Maximum control, deterministic, but harder to maintain
3. **Hybrid** - Critical paths in assembly, rest in C++

### Decision

We chose a **hybrid approach** with the kernel in MASM and higher layers in C++.

**Rationale:**
- Kernel requires cycle-accurate control for deterministic execution
- MASM allows precise register and memory management
- C++ provides productivity for complex logic
- Clear ABI boundary between layers

### Consequences

**Positive:**
- Deterministic execution guarantees
- Maximum performance in hot paths
- Clear separation of concerns

**Negative:**
- Steeper learning curve for contributors
- Platform-specific (x64 only)
- More complex build process

---

## ADR-002: SEG Execution Model

**Status:** ✅ Accepted

### Context

We needed an execution model that supports:
- Deterministic scheduling
- Parallel execution
- Dependency management
- Rollback capability

Options considered:
1. **Thread pools** - Simple, but non-deterministic scheduling
2. **Actor model** - Good isolation, complex message passing
3. **DAG execution** - Deterministic, dependency-aware

### Decision

We chose a **DAG-based execution graph (SEG)**.

**Rationale:**
- DAGs naturally express dependencies
- Topological sort provides deterministic ordering
- Nodes can execute in parallel when dependencies satisfied
- Easy to visualize and debug

### Consequences

**Positive:**
- Deterministic execution order
- Natural parallelism
- Clear dependency visualization
- Easy rollback (reverse topological order)

**Negative:**
- Static graph structure (dynamic modifications complex)
- Memory overhead for graph representation
- Requires careful cycle detection

---

## ADR-003: MoE Routing

**Status:** ✅ Accepted

### Context

The IDE needs intelligent routing of tasks to specialized components. Options:

1. **Static dispatch** - Fast, but inflexible
2. **Virtual functions** - Flexible, but vtable overhead
3. **MoE (Mixture of Experts)** - Dynamic, confidence-based routing

### Decision

We chose **MoE routing with confidence scoring**.

**Rationale:**
- Dynamic selection based on task characteristics
- Confidence scores enable fallback chains
- Supports 128 specialized experts
- Runtime optimization can adjust weights

### Consequences

**Positive:**
- Flexible, adaptive routing
- Expert specialization improves quality
- Confidence scores enable transparency
- Can add experts without recompilation

**Negative:**
- Routing overhead (mitigated by caching)
- Requires training/Calibration for confidence scores
- More complex debugging

---

## ADR-004: Batch Architecture

**Status:** ✅ Accepted

### Context

We needed to organize 49 subsystems into a coherent structure. Options:

1. **Monolithic** - Simple, but hard to maintain
2. **Microservices** - Flexible, but IPC overhead
3. **Batched modules** - Balance of cohesion and modularity

### Decision

We chose **49 batches organized by function**.

**Rationale:**
- Batches 1-10: Core runtime
- Batches 11-20: AI and agents
- Batches 21-30: Binary analysis
- Batches 31-40: Advanced analysis
- Batches 41-49: Agentic expansion

### Consequences

**Positive:**
- Clear functional grouping
- Incremental development possible
- Dependencies flow forward (no cycles)
- Easy to locate functionality

**Negative:**
- Fixed structure (hard to reorganize)
- Some artificial boundaries
- Batch 49 is a "god batch" (unifies everything)

---

## ADR-005: Agentic Surfaces

**Status:** ✅ Accepted

### Context

We needed a unified interface for agentic capabilities. Options:

1. **Multiple APIs** - One per subsystem, but fragmented
2. **Plugin system** - Dynamic loading, complex lifecycle
3. **Unified agentic surface** - Single interface for all capabilities

### Decision

We chose a **unified agentic surface (Batch 49)**.

**Rationale:**
- All 487 capabilities exposed through one interface
- Agents can discover and invoke any capability
- Consistent parameter passing
- Enables agent composition

### Consequences

**Positive:**
- Single interface for all capabilities
- Agents can orchestrate across subsystems
- Easy to add new capabilities
- Consistent error handling

**Negative:**
- Batch 49 is complex (depends on all other batches)
- Potential performance overhead (mitigated by caching)
- Single point of failure

---

## ADR-006: SDK Design

**Status:** ✅ Accepted

### Context

We needed an SDK for external developers. Options:

1. **C-only** - Maximum compatibility, but verbose
2. **C++ only** - Modern, but ABI issues
3. **C ABI with C++ wrapper** - Best of both

### Decision

We chose **C ABI with optional C++ wrapper**.

**Rationale:**
- C ABI is stable across compilers
- Can be wrapped by any language
- C++ wrapper provides modern interface
- Clear ownership semantics

### Consequences

**Positive:**
- Language-agnostic (C, C++, Python, Rust, etc.)
- Stable ABI across versions
- Easy to generate bindings

**Negative:**
- C ABI is verbose
- Manual memory management in C
- Wrapper maintenance overhead

---

## ADR-007: Build System

**Status:** ✅ Accepted

### Context

We needed a build system for 49 batches across 3 platforms. Options:

1. **Make** - Simple, but limited on Windows
2. **MSBuild** - Windows-native, but not portable
3. **CMake** - Portable, industry standard

### Decision

We chose **CMake with platform-specific scripts**.

**Rationale:**
- CMake generates native build files
- Platform scripts handle edge cases
- Ninja for fast builds
- PowerShell/Bash for automation

### Consequences

**Positive:**
- Portable across platforms
- Fast builds with Ninja
- IDE integration (VS, VS Code, CLion)
- Dependency tracking

**Negative:**
- CMake syntax is complex
- Build files can become verbose
- Debugging build issues is hard

---

## ADR-008: Memory Model

**Status:** ✅ Accepted

### Context

We needed a memory model for deterministic execution. Options:

1. **Standard allocators** - Simple, but non-deterministic
2. **Custom pool allocators** - Deterministic, but complex
3. **Region-based allocation** - Fast, but limited lifetime

### Decision

We chose **custom pool allocators with region support**.

**Rationale:**
- Pool allocators provide deterministic allocation times
- Regions enable bulk deallocation
- Separate pools per subsystem
- Telemetry tracks all allocations

### Consequences

**Positive:**
- Deterministic allocation
- No fragmentation
- Fast bulk deallocation
- Full allocation tracking

**Negative:**
- Custom allocator complexity
- Memory overhead for pools
- Requires explicit region management

---

## ADR-009: Testing Strategy

**Status:** ✅ Accepted

### Context

We needed comprehensive testing for 49 batches. Options:

1. **Manual testing** - Flexible, but not scalable
2. **Unit tests only** - Fast, but miss integration issues
3. **Full pyramid** - Unit, integration, system, performance

### Decision

We chose **full test pyramid with automation**.

**Rationale:**
- Unit tests for individual components
- Integration tests for batch interactions
- System tests for end-to-end workflows
- Performance tests for benchmarks

### Consequences

**Positive:**
- Comprehensive coverage
- CI/CD integration
- Regression detection
- Performance tracking

**Negative:**
- Test maintenance overhead
- CI infrastructure cost
- Test execution time

---

## ADR-010: Documentation Strategy

**Status:** ✅ Accepted

### Context

We needed documentation for a complex system. Options:

1. **Code comments only** - Easy, but hard to navigate
2. **External wiki** - Flexible, but can become stale
3. **In-repo documentation** - Versioned, accessible

### Decision

We chose **in-repo Markdown documentation with generated API docs**.

**Rationale:**
- Documentation versioned with code
- Markdown is readable in any editor
- Doxygen for API reference
- 100+ documents organized by topic

### Consequences

**Positive:**
- Documentation always matches code
- Easy to update with PRs
- Multiple formats (web, PDF, IDE)
- Searchable

**Negative:**
- Repository size increases
- Documentation review overhead
- Generation complexity

---

## Summary

Architecture decisions recorded:

- ✅ **ADR-001:** MASM Kernel (Hybrid approach)
- ✅ **ADR-002:** SEG Execution Model (DAG-based)
- ✅ **ADR-003:** MoE Routing (Confidence-based)
- ✅ **ADR-004:** Batch Architecture (49 functional batches)
- ✅ **ADR-005:** Agentic Surfaces (Unified interface)
- ✅ **ADR-006:** SDK Design (C ABI + C++ wrapper)
- ✅ **ADR-007:** Build System (CMake + scripts)
- ✅ **ADR-008:** Memory Model (Pool allocators)
- ✅ **ADR-009:** Testing Strategy (Full pyramid)
- ✅ **ADR-010:** Documentation Strategy (In-repo Markdown)

**Status:** ✅ Complete

---

*End of Architecture Decision Records*
