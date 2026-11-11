# Batch 11 - CFG Reconstruction
## Sovereign IDE Subsystem Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

The CFG Reconstruction subsystem reconstructs control-flow graphs (CFGs) from binary code, enabling higher-level analysis and decompilation.

### Key Characteristics

| Attribute | Value |
|-----------|-------|
| **Language** | C++17 |
| **Lines of Code** | ~6,800 |
| **Supported Architectures** | x86, x64, ARM, ARM64 |
| **Max CFG Depth** | 1024 |
| **SEG Nodes** | 2 |
| **MoE Experts** | 1 |

---

## Responsibilities

1. **Basic Block Identification** - Identify basic blocks in code
2. **Edge Reconstruction** - Build control flow edges
3. **Loop Detection** - Identify loops in CFG
4. **Dominator Tree Construction** - Build dominator relationships
5. **Control-Flow Normalization** - Normalize CFG structure

---

## Architecture

```
┌─────────────────────────────────────────────┐
│         CFG Reconstruction                  │
├─────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   Basic      │  │   Edge           │    │
│  │   Block      │  │   Builder        │    │
│  │   Identifier │  │                  │    │
│  └──────────────┘  └──────────────────┘    │
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   Loop       │  │   Dominator      │    │
│  │   Detector   │  │   Tree           │    │
│  └──────────────┘  └──────────────────┘    │
└─────────────────────────────────────────────┘
```

---

## ABI Surfaces

```cpp
// CFG initialization
SOVEREIGN_API CFGResult CFG_Initialize();
SOVEREIGN_API void CFG_Shutdown();

// CFG building
SOVEREIGN_API CFGHandle CFG_Build(const Instruction* instructions, size_t count);
SOVEREIGN_API CFGHandle CFG_BuildFromBinary(BinaryHandle binary, uint64_t address);
SOVEREIGN_API void CFG_Destroy(CFGHandle cfg);

// Analysis
SOVEREIGN_API size_t CFG_GetBlockCount(CFGHandle cfg);
SOVEREIGN_API BlockHandle CFG_GetBlock(CFGHandle cfg, size_t index);
SOVEREIGN_API size_t CFG_GetEdgeCount(CFGHandle cfg);
SOVEREIGN_API LoopInfo* CFG_GetLoops(CFGHandle cfg);
SOVEREIGN_API DominatorTree* CFG_GetDominatorTree(CFGHandle cfg);

// Normalization
SOVEREIGN_API CFGResult CFG_Normalize(CFGHandle cfg);
```

---

## SEG Nodes

| Node ID | Name | Type | Description |
|---------|------|------|-------------|
| 0x000E | `SEGNode_CFGBuild` | Analysis | Build CFG from instructions |
| 0x000F | `SEGNode_CFGNormalize` | Transformation | Normalize CFG structure |

---

## MoE Experts

| Expert Name | Domain | Description |
|-------------|--------|-------------|
| `Expert_CFGInference` | cfg | Infer CFG patterns and optimize reconstruction |

---

## Implementation Details

### Basic Block Identification

```cpp
class BasicBlockIdentifier {
public:
    std::vector<BasicBlock> Identify(const std::vector<Instruction>& instructions) {
        std::vector<BasicBlock> blocks;
        std::set<uint64_t> leaders;
        
        // First instruction is a leader
        if (!instructions.empty()) {
            leaders.insert(instructions[0].address);
        }
        
        // Find leaders
        for (size_t i = 0; i < instructions.size(); ++i) {
            const auto& inst = instructions[i];
            
            // Branch targets are leaders
            if (IsBranch(inst)) {
                auto target = GetBranchTarget(inst);
                if (target) {
                    leaders.insert(*target);
                }
                // Instruction after branch is leader
                if (i + 1 < instructions.size()) {
                    leaders.insert(instructions[i + 1].address);
                }
            }
        }
        
        // Build blocks from leaders
        BasicBlock currentBlock;
        for (const auto& inst : instructions) {
            if (leaders.count(inst.address) && !currentBlock.instructions.empty()) {
                blocks.push_back(currentBlock);
                currentBlock = BasicBlock();
            }
            currentBlock.instructions.push_back(inst);
        }
        
        if (!currentBlock.instructions.empty()) {
            blocks.push_back(currentBlock);
        }
        
        return blocks;
    }
};
```

### Edge Building

```cpp
class EdgeBuilder {
public:
    void BuildEdges(CFG& cfg, const std::vector<BasicBlock>& blocks) {
        for (size_t i = 0; i < blocks.size(); ++i) {
            const auto& block = blocks[i];
            const auto& lastInst = block.instructions.back();
            
            if (IsUnconditionalBranch(lastInst)) {
                // Single edge to target
                auto target = GetBranchTarget(lastInst);
                if (target) {
                    auto targetIdx = FindBlockIndex(blocks, *target);
                    cfg.AddEdge(i, targetIdx, EdgeType::Branch);
                }
            } else if (IsConditionalBranch(lastInst)) {
                // Two edges: taken and not taken
                auto target = GetBranchTarget(lastInst);
                if (target) {
                    auto targetIdx = FindBlockIndex(blocks, *target);
                    cfg.AddEdge(i, targetIdx, EdgeType::Taken);
                }
                // Fall-through
                if (i + 1 < blocks.size()) {
                    cfg.AddEdge(i, i + 1, EdgeType::FallThrough);
                }
            } else if (!IsReturn(lastInst) && i + 1 < blocks.size()) {
                // Fall-through edge
                cfg.AddEdge(i, i + 1, EdgeType::FallThrough);
            }
        }
    }
};
```

---

## Testing

```cpp
TEST(CFGReconstruction, BuildCFG) {
    CFG_Initialize();
    
    // Create test instructions
    std::vector<Instruction> instructions = {
        {0x1000, "push", "rbp"},
        {0x1001, "mov", "rbp, rsp"},
        {0x1003, "cmp", "eax, 0"},
        {0x1005, "je", "0x1010"},
        {0x1007, "mov", "eax, 1"},
        {0x1009, "jmp", "0x1012"},
        {0x1010, "mov", "eax, 2"},
        {0x1012, "pop", "rbp"},
        {0x1013, "ret", ""}
    };
    
    // Build CFG
    auto cfg = CFG_Build(instructions.data(), instructions.size());
    EXPECT_NE(cfg, nullptr);
    
    // Verify blocks
    EXPECT_EQ(CFG_GetBlockCount(cfg), 4);
    
    // Verify edges
    EXPECT_EQ(CFG_GetEdgeCount(cfg), 5);
    
    CFG_Destroy(cfg);
    CFG_Shutdown();
}
```

---

## Summary

Batch 11 - CFG Reconstruction provides:

- ✅ **Basic block identification**
- ✅ **Edge reconstruction**
- ✅ **Loop detection**
- ✅ **Dominator tree construction**
- ✅ **CFG normalization**

**Status:** ✅ Complete
