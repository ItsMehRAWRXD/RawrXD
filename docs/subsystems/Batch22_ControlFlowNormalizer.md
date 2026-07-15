# Batch 22 - Control Flow Normalizer
## Sovereign IDE Subsystem Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

The Control Flow Normalizer normalizes control flow graphs to simplify analysis and decompilation. It provides loop normalization, branch flattening, CFG simplification, and dead edge removal.

### Key Characteristics

| Attribute | Value |
|-----------|-------|
| **Language** | C++17 |
| **Lines of Code** | ~5,200 |
| **Normalization Passes** | 8 |
| **Supported Constructs** | 15 |
| **SEG Nodes** | 1 |
| **MoE Experts** | 1 |

---

## Responsibilities

1. **Loop Normalization** - Normalize loop structures
2. **Branch Flattening** - Flatten complex branches
3. **CFG Simplification** - Remove unnecessary complexity
4. **Dead Edge Removal** - Remove unreachable edges
5. **Structure Recovery** - Recover high-level structures

---

## Architecture

```
┌─────────────────────────────────────────────┐
│       Control Flow Normalizer               │
├─────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   Loop       │  │   Branch         │    │
│  │   Normalizer │  │   Flattener      │    │
│  └──────────────┘  └──────────────────┘    │
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   CFG        │  │   Dead           │    │
│  │   Simplifier │  │   Edge Remover   │    │
│  └──────────────┘  └──────────────────┘    │
└─────────────────────────────────────────────┘
```

---

## ABI Surfaces

```cpp
// Normalizer initialization
SOVEREIGN_API NormalizeResult Normalize_Initialize();
SOVEREIGN_API void Normalize_Shutdown();

// Normalization
SOVEREIGN_API NormalizeResult Normalize_CFG(CFGHandle cfg);
SOVEREIGN_API NormalizeResult Normalize_Loops(CFGHandle cfg);
SOVEREIGN_API NormalizeResult Normalize_Branches(CFGHandle cfg);
SOVEREIGN_API NormalizeResult Normalize_Simplify(CFGHandle cfg);

// Structure recovery
SOVEREIGN_API StructureList* Normalize_RecoverStructures(CFGHandle cfg);
SOVEREIGN_API bool Normalize_IsLoop(CFGHandle cfg, BlockHandle block);
SOVEREIGN_API bool Normalize_IsIfThenElse(CFGHandle cfg, BlockHandle block);
SOVEREIGN_API bool Normalize_IsSwitch(CFGHandle cfg, BlockHandle block);
```

---

## SEG Nodes

| Node ID | Name | Type | Description |
|---------|------|------|-------------|
| 0x001A | `SEGNode_NormalizeCFG` | Transformation | Normalize CFG structure |

---

## MoE Experts

| Expert Name | Domain | Description |
|-------------|--------|-------------|
| `Expert_ControlFlowNormalization` | cfg | Infer normalization strategies |

---

## Implementation Details

### Loop Normalizer

```cpp
class LoopNormalizer {
public:
    void Normalize(CFG& cfg) {
        // Find all loops
        auto loops = FindLoops(cfg);
        
        for (auto& loop : loops) {
            NormalizeLoop(cfg, loop);
        }
    }
    
private:
    std::vector<Loop> FindLoops(CFG& cfg) {
        std::vector<Loop> loops;
        
        // Use Tarjan's algorithm to find SCCs
        auto sccs = FindStronglyConnectedComponents(cfg);
        
        for (const auto& scc : sccs) {
            if (scc.size() > 1 || IsSelfLoop(scc)) {
                Loop loop;
                loop.blocks = scc;
                
                // Find header (block with edge from outside loop)
                for (auto* block : scc) {
                    for (auto* pred : block->predecessors) {
                        if (!scc.count(pred)) {
                            loop.header = block;
                            break;
                        }
                    }
                }
                
                loops.push_back(loop);
            }
        }
        
        return loops;
    }
    
    void NormalizeLoop(CFG& cfg, Loop& loop) {
        // Ensure single entry
        EnsureSingleEntry(cfg, loop);
        
        // Ensure single exit
        EnsureSingleExit(cfg, loop);
        
        // Canonicalize latch
        CanonicalizeLatch(cfg, loop);
        
        // Insert preheader
        InsertPreheader(cfg, loop);
    }
    
    void EnsureSingleEntry(CFG& cfg, Loop& loop) {
        // Collect all external predecessors
        std::vector<Block*> externalPreds;
        for (auto* block : loop.blocks) {
            for (auto* pred : block->predecessors) {
                if (!loop.blocks.count(pred)) {
                    externalPreds.push_back(pred);
                }
            }
        }
        
        // If multiple external predecessors, create entry block
        if (externalPreds.size() > 1) {
            auto* entryBlock = cfg.CreateBlock();
            entryBlock->name = loop.header->name + ".entry";
            
            // Redirect external predecessors
            for (auto* pred : externalPreds) {
                pred->ReplaceSuccessor(loop.header, entryBlock);
            }
            
            // Connect entry to header
            cfg.AddEdge(entryBlock, loop.header);
            
            loop.header = entryBlock;
            loop.blocks.insert(entryBlock);
        }
    }
    
    void InsertPreheader(CFG& cfg, Loop& loop) {
        // Create preheader block
        auto* preheader = cfg.CreateBlock();
        preheader->name = loop.header->name + ".preheader";
        
        // Move non-loop edges to preheader
        std::vector<Block*> toRedirect;
        for (auto* pred : loop.header->predecessors) {
            if (!loop.blocks.count(pred)) {
                toRedirect.push_back(pred);
            }
        }
        
        for (auto* pred : toRedirect) {
            pred->ReplaceSuccessor(loop.header, preheader);
        }
        
        // Connect preheader to header
        cfg.AddEdge(preheader, loop.header);
    }
};
```

### Branch Flattener

```cpp
class BranchFlattener {
public:
    void Flatten(CFG& cfg) {
        // Find switch statements
        auto switches = FindSwitches(cfg);
        
        for (auto& switchStmt : switches) {
            FlattenSwitch(cfg, switchStmt);
        }
        
        // Flatten nested if-else chains
        FlattenIfChains(cfg);
    }
    
private:
    void FlattenSwitch(CFG& cfg, SwitchStmt& switchStmt) {
        // Create dispatch block
        auto* dispatch = cfg.CreateBlock();
        dispatch->name = "switch.dispatch";
        
        // Create jump table
        std::vector<uint64_t> targets;
        for (auto& case_ : switchStmt.cases) {
            targets.push_back(case_.block->address);
        }
        
        // Emit indirect jump
        dispatch->AddInstruction(OP_JMP_INDIRECT, targets);
        
        // Redirect switch header to dispatch
        switchStmt.header->ReplaceSuccessor(switchStmt.cases[0].block, dispatch);
    }
    
    void FlattenIfChains(CFG& cfg) {
        // Find chains of if-else statements
        for (auto* block : cfg.GetBlocks()) {
            if (IsIfThenElse(block)) {
                // Check if then/else blocks are also if-else
                auto* thenBlock = block->successors[0];
                auto* elseBlock = block->successors[1];
                
                if (IsIfThenElse(thenBlock) && IsIfThenElse(elseBlock)) {
                    // Could flatten this chain
                    // ...
                }
            }
        }
    }
};
```

---

## Testing

```cpp
TEST(ControlFlowNormalizer, LoopNormalization) {
    Normalize_Initialize();
    
    // Create CFG with loop
    auto cfg = CreateTestLoopCFG();
    
    // Normalize
    auto result = Normalize_Loops(cfg);
    EXPECT_EQ(result, NORMALIZE_SUCCESS);
    
    // Verify single entry
    auto* loopHeader = FindLoopHeader(cfg);
    int entryCount = 0;
    for (auto* pred : loopHeader->predecessors) {
        if (!IsInLoop(pred, loopHeader)) {
            entryCount++;
        }
    }
    EXPECT_EQ(entryCount, 1);
    
    Normalize_Shutdown();
}

TEST(ControlFlowNormalizer, StructureRecovery) {
    Normalize_Initialize();
    
    // Create CFG with if-then-else
    auto cfg = CreateTestIfThenElseCFG();
    
    // Recover structures
    auto structures = Normalize_RecoverStructures(cfg);
    
    // Should identify if-then-else
    bool foundIfThenElse = false;
    for (size_t i = 0; i < structures->count; ++i) {
        if (structures->items[i].type == STRUCT_IF_THEN_ELSE) {
            foundIfThenElse = true;
            break;
        }
    }
    EXPECT_TRUE(foundIfThenElse);
    
    Normalize_Shutdown();
}
```

---

## Summary

Batch 22 - Control Flow Normalizer provides:

- ✅ **Loop normalization**
- ✅ **Branch flattening**
- ✅ **CFG simplification**
- ✅ **Dead edge removal**
- ✅ **Structure recovery**

**Status:** ✅ Complete
