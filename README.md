# RawrXD v3.0

## Native Agentic AI Development Environment

> **Native Win32** • **Local-First AI** • **Deep2 Inference Runtime** • **Autonomous Coding Agents** • **Multi-GPU Compute** • **No Qt Runtime**

[![Build Status](https://github.com/ItsMehRAWRXD/RawrXD/actions/workflows/build.yml/badge.svg)](https://github.com/ItsMehRAWRXD/RawrXD/actions/workflows/build.yml)
![Platform](https://img.shields.io/badge/platform-Windows%20x64-lightgrey)
![Language](https://img.shields.io/badge/C%2B%2B-20-blue)
![License](https://img.shields.io/badge/license-MIT-blue)
![Inference](https://img.shields.io/badge/inference-Deep2-purple)
![Architecture](https://img.shields.io/badge/UI-Native%20Win32-success)

---

# Build. Run. Reason. Repair. Locally.

**RawrXD** is a native Windows AI development environment built around autonomous software engineering and local model execution.

It combines:

* a native **C++20 / Win32 IDE**
* an autonomous **agentic coding engine**
* the **Deep2 native inference runtime**
* local **GGUF model execution**
* native **Vulkan GPU acceleration**
* heterogeneous **multi-GPU scheduling**
* project-wide source research
* autonomous editing and patching
* terminal, build, test, and process control
* Git-aware engineering workflows
* local API serving
* self-correcting execution loops

All inside one native application stack.

No Electron shell.

No mandatory Qt runtime.

No required cloud inference service.

No requirement to route local models through Ollama.

---

# What RawrXD Is

RawrXD is not designed as another chat window attached to an editor.

It is being built as a **local autonomous software-engineering environment**.

The goal is straightforward:

```text
Give RawrXD a development objective.

RawrXD should be able to:

Understand the repository
        ↓
Research the relevant source
        ↓
Construct a plan
        ↓
Execute tools
        ↓
Modify code
        ↓
Build the project
        ↓
Run tests
        ↓
Inspect failures
        ↓
Correct the implementation
        ↓
Verify the result
```

The model is only one part of the system.

RawrXD supplies the execution environment around it.

---

# One Native AI Stack

```text
┌──────────────────────────────────────────────────────────────┐
│                         RawrXD IDE                            │
│                    Native C++20 / Win32                       │
├──────────────────────────────────────────────────────────────┤
│                    AIIntegrationHub                           │
├───────────────────────┬──────────────────────────────────────┤
│    Agentic Engine     │          Tool Authority              │
│                       │                                      │
│ Planning              │ Files                                │
│ Research              │ Search                               │
│ Verification          │ Terminal                             │
│ Self-Correction       │ Processes                            │
│ Code Surgery          │ Build / Test                         │
│ Task Execution        │ Git                                  │
│                       │ Diagnostics                          │
├───────────────────────┴──────────────────────────────────────┤
│                         Deep2                                │
│                Native Local Inference Runtime                │
├──────────────────┬──────────────────┬────────────────────────┤
│ CPU Kernels      │ Vulkan Compute   │ Multi-GPU Scheduler    │
│ AVX2 / AVX-512   │ GPU Execution    │ Residency / Admission  │
├──────────────────┴──────────────────┴────────────────────────┤
│                    Local GGUF Models                         │
└──────────────────────────────────────────────────────────────┘
```

---

# Major v3 Capabilities

## Native Agentic Engineering

RawrXD contains a native agent execution system designed for multi-step software-development tasks.

The agent can:

* analyze repositories
* inspect source trees
* gather context across files
* locate incomplete implementations
* identify suspicious or broken paths
* modify source
* execute builds
* launch tests
* inspect compiler failures
* inspect runtime failures
* perform corrective edits
* continue iterating
* produce a verified result

The objective is not simply code generation.

The objective is **closed-loop engineering**.

---

# Autonomous Planning

RawrXD agents can break larger objectives into smaller executable tasks.

```text
User Objective
      ↓
Task Decomposition
      ↓
Repository Research
      ↓
Execution Plan
      ↓
Tool Calls
      ↓
Observations
      ↓
Verification
      ↓
Correction
      ↓
Next Action
```

This allows development tasks to continue beyond a single model response.

---

# Deep Project Research

RawrXD can research a codebase directly instead of relying only on whatever source fits inside an initial prompt.

Project research can include:

```text
Directory traversal
Source inspection
Symbol searches
Configuration discovery
Build-system inspection
Dependency mapping
Implementation tracing
Stub detection
Error-path analysis
Cross-file context gathering
```

This allows the agent to build context dynamically as the task progresses.

---

# Self-Correcting Engineering Loop

Generated code is not assumed to be correct.

RawrXD is designed around an iterative loop:

```text
Generate
   ↓
Compile
   ↓
Test
   ↓
Observe
   ↓
Diagnose
   ↓
Repair
   ↓
Rebuild
   ↓
Verify
```

Compiler output, runtime diagnostics, test failures, and tool results become new observations for the agent.

---

# Agent Tool Authority

Autonomous actions are routed through a native authority layer.

```text
                       Model
                         │
                         ▼
                  Agent Planner
                         │
                         ▼
               Tool Authority Registry
                         │
          ┌──────────────┼───────────────┐
          │              │               │
          ▼              ▼               ▼
       Files          Terminal          Git
          │              │               │
          ├──── Search   ├──── Build     ├──── Status
          ├──── Read     ├──── Test      ├──── Diff
          ├──── Write    ├──── Launch    ├──── Commit
          └──── Patch    └──── Inspect   └──── Workflow
                         │
                         ▼
                     Observation
                         │
                         ▼
                    Verification
                         │
                         ▼
                     Next Step
```

The authority layer provides a common execution boundary for:

* IDE agents
* CLI agents
* autonomous loops
* headless workflows
* code repair systems

---

# Code Surgery

RawrXD includes targeted source-repair functionality through its native agent and patching infrastructure.

Typical workflows include:

```text
Locate implementation
      ↓
Inspect surrounding source
      ↓
Determine minimal change
      ↓
Patch
      ↓
Compile
      ↓
Verify
```

The intent is to prefer focused, verifiable changes over uncontrolled repository-wide rewrites.

---

# Deep2 Native Inference Runtime

RawrXD includes its own local inference runtime: **Deep2**.

Deep2 is designed to load and execute supported models directly instead of requiring an external inference server.

```text
GGUF
 │
 ▼
Deep2 Loader
 │
 ├── Architecture Metadata
 ├── Tensor Metadata
 ├── Quantization Metadata
 └── Runtime Configuration
 │
 ▼
Execution Planner
 │
 ├── CPU
 ├── Vulkan GPU
 └── Multi-GPU
 │
 ▼
Decode
 │
 ▼
Streaming Tokens
 │
 ├── IDE
 ├── CLI
 ├── API
 └── Agent
```

---

# Native GGUF Execution

Deep2 supports direct loading of supported GGUF models.

The native loader can inspect model information such as:

```text
Architecture
Layer Count
Hidden Size
Feed-Forward Size
Attention Heads
KV Heads
Vocabulary
Tensor Shapes
Quantization Types
RoPE Metadata
Model Metadata
```

GGUF execution remains local to the RawrXD runtime.

---

# CPU Acceleration

Deep2 contains hardware-aware native CPU execution paths.

Acceleration work includes:

* AVX2
* AVX-512
* FMA
* F16C
* VNNI-aware paths
* quantized GEMV
* quantized tensor execution
* architecture-specific dispatch
* runtime CPU capability detection

RawrXD selects appropriate execution paths according to the host CPU and available runtime implementations.

---

# Native Quantized Kernels

Deep2 contains native execution paths for GGUF quantization families including current work around:

```text
Q2_K
Q4_0
Q4_K
Q5_K
Q8_0
```

Exact availability depends on model architecture and execution backend.

RawrXD's runtime is designed so quantized execution does not require delegating inference to another local model server.

---

# Vulkan GPU Compute

Deep2 includes native Vulkan compute infrastructure.

Current architecture includes work around:

* Vulkan device enumeration
* queue-family selection
* native compute queues
* Vulkan buffers
* device-local memory
* memory-type selection
* command buffers
* fences
* query infrastructure
* GPU quantized kernels
* persistent resources
* asynchronous submission
* weight residency
* live heap-budget inspection
* GPU decode telemetry

---

# Live Memory-Budget Awareness

Deep2 can integrate Vulkan memory-budget information into runtime scheduling.

Rather than assuming GPU memory availability is static, the runtime can reason about live memory state.

```text
Physical GPU
     ↓
Vulkan Heap
     ↓
Live Budget
     ↓
Current Usage
     ↓
Safety Reserve
     ↓
Admission Decision
```

This provides the foundation for safe GPU weight admission and residency management.

---

# Progressive GPU Residency

Deep2's multi-GPU architecture is moving beyond simple whole-model or whole-tensor placement.

The runtime architecture supports progressively resident execution concepts such as:

```text
Tensor
 ├── Resident GPU Rows
 │        ↓
 │     GPU Compute
 │
 └── Nonresident Tail
          ↓
     Alternate Execution
```

As additional data becomes resident, the GPU execution range can grow without requiring the entire weight to become available at once.

This is particularly valuable on mixed-memory and heterogeneous GPU systems.

---

# Heterogeneous Multi-GPU Compute

RawrXD is designed to use **different GPU models cooperatively**.

The scheduler does not assume that every accelerator has:

* the same VRAM
* the same compute rate
* the same memory bandwidth
* the same architecture
* the same optimal workload share

Instead, Deep2 contains infrastructure for device-aware scheduling.

```text
                     Decode Work
                         │
                 Adaptive Scheduler
                         │
               ┌─────────┴─────────┐
               │                   │
               ▼                   ▼
             GPU 0               GPU 1
        Larger / Faster      Smaller / Slower
               │                   │
               └─────────┬─────────┘
                         ▼
                    Combined Result
```

Runtime work includes:

* device-specific lanes
* workload splitting
* residency-aware execution
* live admission decisions
* adaptive device ratios
* GPU timing telemetry
* fallback detection
* strict GPU validation
* cross-device scheduling

---

# Local-First by Design

RawrXD is designed so the core development loop can operate locally.

```text
Your Repository
      +
Your Local Model
      +
Your Hardware
      ↓
RawrXD
      ↓
Research
      ↓
Reason
      ↓
Modify
      ↓
Compile
      ↓
Test
      ↓
Repair
```

A remote inference API is not required for the native local workflow.

---

# No Mandatory Ollama Runtime

RawrXD can load supported models through its own native runtime.

This allows the product to operate without requiring:

```text
RawrXD
  ↓
External Model Server
  ↓
Model
```

Instead:

```text
RawrXD
  ↓
Deep2
  ↓
Model
```

Ollama-compatible workflows may still be supported at API boundaries where useful, but Deep2 is intended to remain an independent inference runtime.

---

# Native Win32 IDE

RawrXD v3 moves the product toward a native Windows application architecture.

Primary technologies include:

```text
C++20
Win32
Windows Native APIs
Winsock
WinHTTP
Vulkan
Native Threads
Native Process Management
Native File I/O
Native Memory Management
```

The v3 native product architecture does not require Qt as its primary UI/runtime layer.

---

# Why Native?

RawrXD is built around direct control of the machine.

A native architecture provides access to:

* Windows process control
* native filesystem APIs
* explicit memory management
* GPU device discovery
* Vulkan resource ownership
* low-level telemetry
* native terminal integration
* hardware-specific inference
* direct executable management
* local model memory mapping

That control matters when the IDE and the inference runtime are part of the same product.

---

# AIIntegrationHub

`AIIntegrationHub` acts as the integration layer between product subsystems.

```text
                      RawrXD IDE
                          │
                          ▼
                 AIIntegrationHub
                          │
       ┌──────────────────┼──────────────────┐
       │                  │                  │
       ▼                  ▼                  ▼
 Agentic Engine       Deep2 Runtime     Tool Authority
       │                  │                  │
       ▼                  ▼                  ▼
 Planning            Local Models       Files
 Research            CPU Compute        Terminal
 Verification        Vulkan Compute     Build
 Correction          Streaming          Git
```

The integration layer keeps model execution, agent reasoning, and tool execution connected through native product paths.

---

# Native Interactive CLI

RawrXD includes a native interactive command-line interface:

```text
rawrxd_cli.exe
```

It exposes model, agent, patching, and diagnostic functionality directly.

---

## Load a Model

```text
/load <path>
```

Example:

```text
/load F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf
```

---

## Run an Agent Task

```text
/agent <query>
```

Example:

```text
/agent audit this repository for unfinished implementations
```

---

## Patch a Target

```text
/patch <target>
```

Used for targeted source and code-surgery workflows.

---

## Generate Diagnostics

```text
/bugreport
```

Used to launch native security, correctness, and optimization analysis workflows.

---

# CLI Hotkeys

| Key | Function                             |
| --- | ------------------------------------ |
| `x` | Analyze file                         |
| `t` | Generate test stubs                  |
| `g` | Toggle performance governor          |
| `p` | Show thermal / power / system status |

---

# Rawr Agent Workflow

A key target workflow is:

```powershell
rawr run qwen2.5-coder audit my IDE codebase for any stubs
```

Conceptually, RawrXD can execute:

```text
1. Resolve the local model
2. Load the model through Deep2
3. Open the requested repository
4. Enumerate project source
5. Search for stubs and placeholders
6. Inspect suspicious implementations
7. Gather cross-file context
8. Rank defects
9. Plan repairs
10. Modify source
11. Build affected targets
12. Run tests
13. Inspect compiler/runtime output
14. Repair failures
15. Rebuild
16. Verify
17. Report the final result
```

This is the execution model RawrXD is being designed around.

---

# Native Local API

RawrXD includes native networking infrastructure for serving local AI functionality.

The local server architecture uses native Windows networking rather than requiring an external web framework.

Potential client surfaces include:

* RawrXD IDE
* RawrXD CLI
* local scripts
* local automation
* OpenAI-style clients
* Ollama-style clients
* third-party development tools

---

# API Architecture

```text
Client
  │
  ▼
Native HTTP Interface
  │
  ▼
AIIntegrationHub
  │
  ├── Agent Request
  │
  └── Inference Request
          │
          ▼
        Deep2
          │
          ▼
      Local Model
```

---

# Runtime Telemetry

Deep2 exposes detailed runtime instrumentation for development and certification.

Telemetry can include:

```text
Decode TPS
Prompt Processing
Token Latency
GPU Compute Time
GPU Idle Time
Device Work Split
Heap Budget
Heap Usage
Memory Headroom
Weight Residency
Admission Failures
Cache Statistics
GPU Fallbacks
CPU Fallbacks
Strict GPU Violations
Queue Activity
Decode Synchronization
```

RawrXD treats performance telemetry as part of runtime correctness rather than purely a benchmarking feature.

---

# Performance Philosophy

RawrXD does not treat a synthetic kernel benchmark as equivalent to full-model inference.

Performance certification should distinguish between:

```text
Kernel Throughput
Primitive Throughput
Abbreviated Execution
Full Model Decode
Real Token Streaming
Agentic Product Execution
```

The project's goal is reproducible end-to-end performance with real models.

---

# Authority-Based Verification

RawrXD uses explicit certification gates for critical product paths.

Examples include:

```text
MODEL_LOAD=PASS
TOKEN_DECODE=PASS
STREAMING=PASS
STRICT_GPU_VIOLATIONS=0
UNPLANNED_FALLBACKS=0
TOOL_AUTHORITY=PASS
AGENT_LOOP=PASS
BUILD_EXECUTION=PASS
TEST_EXECUTION=PASS
PRODUCT_PATH=PASS
```

This approach helps separate:

* "the code compiled"
* "the test harness worked"
* "the subsystem worked"
* "the actual product path worked"

---

# Native Model Loader

RawrXD currently includes model-loading infrastructure for:

## GGUF

Native loading and metadata discovery for supported GGUF architectures.

## RawrBlob

Experimental native tensor/model format intended for direct runtime experiments.

---

# RawrXD Is More Than a Model Runner

A model runner normally looks like:

```text
Prompt
  ↓
Model
  ↓
Tokens
```

RawrXD's target architecture is:

```text
User Objective
      ↓
Agent
      ↓
Research
      ↓
Planning
      ↓
Local Model
      ↓
Tool Execution
      ↓
Code Changes
      ↓
Build
      ↓
Test
      ↓
Observation
      ↓
Self-Correction
      ↓
Verified Result
```

Inference exists to power the engineering system.

The engineering system is the product.

---

# Project Architecture

```text
RawrXD/
│
├── Native Win32 IDE
│
├── AIIntegrationHub
│
├── Agentic Engine
│   ├── Planner
│   ├── Research
│   ├── Self-Correction
│   ├── Tool Selection
│   └── Code Surgery
│
├── Tool Authority
│   ├── File Operations
│   ├── Search
│   ├── Terminal
│   ├── Process Control
│   ├── Build
│   ├── Test
│   ├── Git
│   └── Diagnostics
│
├── Deep2 Runtime
│   ├── GGUF Loader
│   ├── CPU Kernels
│   ├── AVX2
│   ├── AVX-512
│   ├── Vulkan Compute
│   ├── Quantized Kernels
│   ├── Residency Manager
│   ├── Memory Admission
│   ├── Multi-GPU Scheduler
│   └── Streaming Decode
│
├── Native CLI
│
└── Native API Server
```

---

# Build

## Requirements

Recommended development environment:

* Windows 11 x64
* Visual Studio 2022
* MSVC with C++20 support
* Windows SDK
* CMake 3.20+
* Vulkan SDK for Vulkan-enabled builds
* AVX2-capable processor
* AVX-512-capable processor for supported accelerated CPU paths
* Vulkan-capable GPU for GPU acceleration

---

## Clone

```powershell
git clone https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD
```

---

## Configure

```powershell
mkdir build_native
cd build_native

cmake .. `
    -DENABLE_QT=OFF `
    -DUSE_AVX512=ON `
    -DRAWRXD_BUILD_CLI=ON
```

---

## Build Release

```powershell
cmake --build . --config Release
```

---

# Run

## Native IDE

```powershell
.\Release\rawrxd.exe
```

## Native CLI

```powershell
.\Release\rawrxd_cli.exe
```

---

# Example Local Workflow

Load a coding model:

```text
/load F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf
```

Run a repository audit:

```text
/agent audit my IDE codebase for any stubs
```

Then allow the agent to:

```text
Search
Inspect
Reason
Patch
Build
Test
Repair
Verify
```

---

# v2 → v3

RawrXD v3 represents the transition toward a unified native architecture.

## Native UI

Legacy Qt-oriented application paths are deprecated in favor of the native Win32 application.

## Native Agent Execution

Legacy simulation-style agent paths are being replaced with actual native execution and tool-authority routing.

## Native Model Runtime

Deep2 moves local inference into the RawrXD stack itself.

## Native Tooling

File, terminal, process, build, test, and Git execution can be controlled by the agent through native product infrastructure.

---

# Development Principles

RawrXD development follows several core principles.

## Local First

The core model and agent workflow should remain capable of operating locally.

## Native First

Prefer direct platform APIs and source-controlled implementations over unnecessary runtime frameworks.

## Evidence First

Do not promote an optimization or subsystem based only on a successful build.

Verify the actual execution path.

## Real Models

Model-runtime work should ultimately be validated with complete model execution.

## No Silent Fallbacks

Fallback behavior should be observable.

## Authority Before Autonomy

An autonomous coding agent must have a controlled, testable tool execution boundary.

## Correctness Before Benchmark Claims

A fast broken path is not a performance win.

---

# Current v3 Engineering Status

RawrXD v3 is under active end-to-end hardening and certification.

Major architecture is operational across:

* native Win32 application infrastructure
* local inference
* model loading
* CPU execution
* Vulkan compute
* streaming decode
* agent execution
* tool routing
* repository research
* source modification
* build/test automation
* runtime diagnostics

Current engineering work continues around:

* Deep2 multi-GPU hardening
* progressive GPU residency
* memory-admission behavior
* quantized kernel verification
* decode-path optimization
* agent tool-authority consolidation
* full IDE/CLI/headless path parity
* autonomous end-to-end certification

The project favors measurable, reproducible evidence over unsupported completion or performance claims.

---

# Vision

The long-term objective is a development environment where this:

```text
rawr run modelname audit my IDE codebase for any stubs
```

can become a complete autonomous engineering operation:

```text
Understand
   ↓
Research
   ↓
Plan
   ↓
Modify
   ↓
Compile
   ↓
Test
   ↓
Diagnose
   ↓
Repair
   ↓
Verify
   ↓
Deliver
```

Powered entirely by local models if desired.

---

# Why RawrXD

Most AI development tools sit on top of somebody else's inference service.

Most local model runners stop at token generation.

Most IDE assistants stop at suggestions.

RawrXD is being built to connect all three layers:

```text
Development Environment
          +
Autonomous Engineering
          +
Native Local Inference
```

into one system.

---

# The RawrXD Stack

```text
┌──────────────────────────────────────────────┐
│                RawrXD IDE                    │
│           Native C++20 / Win32               │
├──────────────────────────────────────────────┤
│          Autonomous Agent Engine             │
├──────────────────────────────────────────────┤
│             Tool Authority                   │
├──────────────────────────────────────────────┤
│                 Deep2                        │
│       Native Local Inference Runtime         │
├──────────────────────────────────────────────┤
│      AVX2 │ AVX-512 │ Vulkan │ Multi-GPU    │
├──────────────────────────────────────────────┤
│               Local Models                   │
└──────────────────────────────────────────────┘
```

---

# Built for Local AI Engineering

RawrXD is for developers who want direct control over:

* their source
* their models
* their hardware
* their inference runtime
* their agent execution
* their tooling
* their data
* their development workflow

without making cloud inference the architectural center of the system.

---

# Contributing

Contributions, testing, benchmarking, bug reports, and architecture discussions are welcome.

When reporting inference or performance issues, include where possible:

```text
Model
Quantization
CPU
GPU(s)
RAM
Runtime Configuration
Token Count
Relevant Telemetry
Reproduction Steps
```

For correctness issues, reproducible evidence is preferred over isolated screenshots or synthetic benchmark results.

---

# License

RawrXD is distributed under the **MIT License**.

See `LICENSE` for details.

---

# RawrXD v3.0

## Native AI Development Without Giving Up Control.

**Local Models. Native Inference. Autonomous Engineering. One Stack.**
