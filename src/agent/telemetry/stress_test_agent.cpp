// stress_test_agent.cpp — Minimal 24h soak test with MASM telemetry
// Build: cl /O2 /EHsc /std:c++20 /Fe:stress_agent.exe stress_test_agent.cpp AgentTelemetry.obj
// Run:  stress_agent.exe --duration 86400 --checkpoint 3600

#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <ctime>
#include <string>
#include <vector>
#include <random>
#include <cstdint>

// ============================================================================
// MASM TELEMETRY EXTERN DECLARATIONS
// ============================================================================
extern "C" {
    void AgentTelemetry_RecordAllocation(uint64_t size);
    void AgentTelemetry_RecordFree(uint64_t size);
    uint64_t AgentTelemetry_GetArenaUsed(void);
    void AgentTelemetry_Reset(void);
    void AgentTelemetry_RecordProposalGenerated(void);
    void AgentTelemetry_RecordProposalApplied(void);
    void AgentTelemetry_RecordLoopIteration(void);
    void AgentTelemetry_RecordSwarmLatency(uint64_t microseconds);
    void AgentTelemetry_UpdateStateChecksum(uint64_t checksum);
    
    // Global telemetry structure exported from ASM
    extern uint64_t g_AgentTelemetry_arenaUsedBytes;
    extern uint64_t g_AgentTelemetry_vramUsedBytes;
    extern uint32_t g_AgentTelemetry_proposalsGenerated;
    extern uint32_t g_AgentTelemetry_proposalsApplied;
    extern uint64_t g_AgentTelemetry_totalSwarmLatencyUs;
    extern uint32_t g_AgentTelemetry_loopCount;
    extern uint64_t g_AgentTelemetry_stateChecksum;
}

// ============================================================================
// SOVEREIGN ARENA ALLOCATOR (minimal implementation for stress test)
// ============================================================================
struct ArenaBlock {
    void* memory;
    size_t used;
    size_t capacity;
    ArenaBlock* next;
};

class SovereignArena {
    ArenaBlock* head = nullptr;
    size_t totalAllocated = 0;
    size_t totalUsed = 0;
    size_t blockCount = 0;
    
public:
    void* allocate(size_t size) {
        // Align to 8 bytes
        size = (size + 7) & ~7;
        
        // Record allocation in MASM telemetry BEFORE actual alloc
        AgentTelemetry_RecordAllocation(size);
        
        // Try to fit in existing block
        ArenaBlock* block = head;
        while (block) {
            if (block->capacity - block->used >= size) {
                void* ptr = (char*)block->memory + block->used;
                block->used += size;
                totalUsed += size;
                return ptr;
            }
            block = block->next;
        }
        
        // Allocate new block (double strategy)
        size_t blockSize = size < 65536 ? 65536 : size * 2;
        void* mem = VirtualAlloc(NULL, blockSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!mem) {
            // Rollback telemetry on failure
            AgentTelemetry_RecordFree(size);
            return nullptr;
        }
        
        ArenaBlock* newBlock = (ArenaBlock*)malloc(sizeof(ArenaBlock));
        newBlock->memory = mem;
        newBlock->used = size;
        newBlock->capacity = blockSize;
        newBlock->next = head;
        head = newBlock;
        
        totalAllocated += blockSize;
        totalUsed += size;
        blockCount++;
        
        return mem;
    }
    
    void reset() {
        // Calculate freed bytes
        size_t freed = totalUsed;
        
        ArenaBlock* block = head;
        while (block) {
            block->used = 0;
            block = block->next;
        }
        totalUsed = 0;
        
        // Record free in telemetry
        AgentTelemetry_RecordFree(freed);
    }
    
    void destroy() {
        ArenaBlock* block = head;
        while (block) {
            VirtualFree(block->memory, 0, MEM_RELEASE);
            ArenaBlock* next = block->next;
            free(block);
            block = next;
        }
        head = nullptr;
        totalAllocated = 0;
        totalUsed = 0;
        blockCount = 0;
    }
    
    size_t getTotalAllocated() const { return totalAllocated; }
    size_t getTotalUsed() const { return totalUsed; }
    size_t getBlockCount() const { return blockCount; }
};

// ============================================================================
// TELEMETRY LOGGER — Reads from MASM AgentTelemetry.asm globals
// ============================================================================
class TelemetryLogger {
    FILE* csvFile = nullptr;
    
public:
    bool init(const char* filename) {
        fopen_s(&csvFile, filename, "w");
        if (!csvFile) return false;
        fprintf(csvFile, "Timestamp,ArenaUsedBytes,ArenaAllocatedBytes,ProposalsGenerated,ProposalsApplied,TotalSwarmLatencyUs,LoopCount,StateChecksum\n");
        fflush(csvFile);
        
        // Reset MASM telemetry at start
        AgentTelemetry_Reset();
        
        return true;
    }
    
    void log(const SovereignArena& arena, uint64_t checksum) {
        // Update MASM checksum
        AgentTelemetry_UpdateStateChecksum(checksum);
        
        // Read values from MASM globals
        uint64_t arenaUsed = AgentTelemetry_GetArenaUsed();
        uint64_t arenaAllocated = arena.getTotalAllocated();
        uint32_t proposalsGen = g_AgentTelemetry_proposalsGenerated;
        uint32_t proposalsApp = g_AgentTelemetry_proposalsApplied;
        uint64_t totalLatency = g_AgentTelemetry_totalSwarmLatencyUs;
        uint32_t loops = g_AgentTelemetry_loopCount;
        uint64_t stateHash = g_AgentTelemetry_stateChecksum;
        
        // Write to CSV
        SYSTEMTIME st;
        GetSystemTime(&st);
        fprintf(csvFile, "%04d-%02d-%02d %02d:%02d:%02d,%llu,%llu,%u,%u,%llu,%u,0x%016llX\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
            arenaUsed, arenaAllocated, proposalsGen, proposalsApp, totalLatency, loops, stateHash);
        fflush(csvFile);
    }
    
    void recordProposal(bool applied, uint64_t latencyUs) {
        AgentTelemetry_RecordProposalGenerated();
        if (applied) AgentTelemetry_RecordProposalApplied();
        AgentTelemetry_RecordSwarmLatency(latencyUs);
    }
    
    void incrementLoop() { AgentTelemetry_RecordLoopIteration(); }
    
    void close() {
        if (csvFile) { fclose(csvFile); csvFile = nullptr; }
    }
};

// ============================================================================
// STRESS TEST WORKLOADS
// ============================================================================
class StressWorkload {
    std::mt19937_64 rng;
    std::uniform_int_distribution<int> dist;
    
public:
    StressWorkload(uint64_t seed = 0xDEADBEEFCAFEBABE) : rng(seed), dist(0, 99) {}
    
    // Simulate agent proposal generation (allocates strings, AST nodes, etc.)
    void generateProposal(SovereignArena& arena, int complexity) {
        // Allocate proposal text
        size_t textSize = 64 + (complexity * 128);
        char* text = (char*)arena.allocate(textSize);
        if (text) {
            memset(text, 'A' + (dist(rng) % 26), textSize - 1);
            text[textSize - 1] = 0;
        }
        
        // Allocate AST node
        struct FakeASTNode {
            int type;
            int line;
            int col;
            void* children[4];
            char padding[64];
        };
        FakeASTNode* node = (FakeASTNode*)arena.allocate(sizeof(FakeASTNode));
        if (node) {
            node->type = dist(rng);
            node->line = dist(rng);
            node->col = dist(rng);
        }
        
        // Allocate symbol table entry
        struct FakeSymbol {
            char name[32];
            int kind;
            void* type;
            void* scope;
        };
        FakeSymbol* sym = (FakeSymbol*)arena.allocate(sizeof(FakeSymbol));
        if (sym) {
            snprintf(sym->name, 32, "sym_%d_%d", dist(rng), dist(rng));
            sym->kind = dist(rng) % 5;
        }
    }
    
    // Simulate file ingestion (large allocations)
    void ingestFile(SovereignArena& arena, size_t fileSize) {
        char* content = (char*)arena.allocate(fileSize);
        if (content) {
            // Simulate file content
            for (size_t i = 0; i < fileSize; i += 1024) {
                size_t chunk = (fileSize - i < 1024) ? (fileSize - i) : 1024;
                memset(content + i, '0' + (dist(rng) % 10), chunk);
            }
        }
    }
    
    // Simulate swarm coordination (many small allocations)
    void swarmCoordination(SovereignArena& arena, int agentCount) {
        struct AgentMessage {
            int fromAgent;
            int toAgent;
            int msgType;
            char payload[256];
        };
        
        for (int i = 0; i < agentCount; ++i) {
            AgentMessage* msg = (AgentMessage*)arena.allocate(sizeof(AgentMessage));
            if (msg) {
                msg->fromAgent = dist(rng) % 16;
                msg->toAgent = dist(rng) % 16;
                msg->msgType = dist(rng) % 8;
                snprintf(msg->payload, 256, "coord_%d_%llu", i, GetTickCount64());
            }
        }
    }
};

// ============================================================================
// STATE CHECKSUM (FNV-1a 64-bit)
// ============================================================================
uint64_t computeChecksum(const SovereignArena& arena, uint64_t loopCount) {
    uint64_t hash = 0xCBF29CE484222325; // FNV offset basis
    const uint64_t prime = 0x100000001B3;
    
    // Hash arena state
    uint64_t state[] = {
        arena.getTotalAllocated(),
        arena.getTotalUsed(),
        arena.getBlockCount(),
        loopCount,
        GetTickCount64()
    };
    
    for (int i = 0; i < 5; ++i) {
        uint64_t val = state[i];
        for (int b = 0; b < 8; ++b) {
            hash ^= (val >> (b * 8)) & 0xFF;
            hash *= prime;
        }
    }
    
    return hash;
}

// ============================================================================
// MAIN STRESS TEST LOOP
// ============================================================================
int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    
    // Parse args
    int durationSeconds = 3600;      // Default 1 hour
    int checkpointSeconds = 300;     // Default 5 min checkpoints
    int swarmSize = 16;              // Default 16 agents
    
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            durationSeconds = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--checkpoint") == 0 && i + 1 < argc) {
            checkpointSeconds = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--swarm") == 0 && i + 1 < argc) {
            swarmSize = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: stress_agent.exe [options]\n");
            printf("Options:\n");
            printf("  --duration N     Run for N seconds (default: 3600)\n");
            printf("  --checkpoint N   Log every N seconds (default: 300)\n");
            printf("  --swarm N        Number of agents (default: 16)\n");
            printf("  --help           Show this help\n");
            return 0;
        }
    }
    
    printf("=================================================================\n");
    printf("  RawrXD Agent Stress Test — 24h Soak\n");
    printf("=================================================================\n");
    printf("  Duration:    %d seconds (%.1f hours)\n", durationSeconds, durationSeconds / 3600.0);
    printf("  Checkpoint:  Every %d seconds\n", checkpointSeconds);
    printf("  Swarm size:  %d agents\n", swarmSize);
    printf("=================================================================\n\n");
    
    // Initialize
    SovereignArena arena;
    TelemetryLogger telemetry;
    StressWorkload workload;
    
    if (!telemetry.init("stress_test_log.csv")) {
        printf("FATAL: Failed to open telemetry log\n");
        return 1;
    }
    
    DWORD startTime = GetTickCount();
    DWORD nextCheckpoint = startTime + (checkpointSeconds * 1000);
    DWORD endTime = startTime + (durationSeconds * 1000);
    
    uint64_t loopCount = 0;
    int phase = 0; // 0=ingestion, 1=mapping, 2=healthy, 3=cleanup
    
    printf("Starting stress test...\n");
    printf("Phase 0: Ingestion (0-5 min)\n");
    
    while (GetTickCount() < endTime) {
        DWORD now = GetTickCount();
        int elapsedSec = (now - startTime) / 1000;
        
        // Phase transitions
        if (phase == 0 && elapsedSec > 300) {
            phase = 1;
            printf("Phase 1: Mapping (5-60 min)\n");
        } else if (phase == 1 && elapsedSec > 3600) {
            phase = 2;
            printf("Phase 2: Healthy (>60 min)\n");
        }
        
        // === WORKLOAD ===
        switch (phase) {
            case 0: // Ingestion — heavy file loading (throttled)
                // Only ingest every 100ms to simulate realistic file I/O
                if (loopCount % 100 == 0) {
                    workload.ingestFile(arena, 1024 * 1024); // 1MB file
                }
                break;
                
            case 1: // Mapping — proposal generation
                for (int i = 0; i < swarmSize * 4; ++i) {
                    workload.generateProposal(arena, 1 + (i % 5));
                }
                break;
                
            case 2: // Healthy — mixed workload with periodic cleanup
                for (int i = 0; i < swarmSize; ++i) {
                    workload.generateProposal(arena, 1 + (i % 3));
                }
                workload.swarmCoordination(arena, swarmSize);
                
                // Periodic arena reset (simulates GC cycle)
                if (loopCount % 1000 == 0) {
                    arena.reset();
                }
                break;
        }
        
        // === TELEMETRY ===
        if (now >= nextCheckpoint) {
            uint64_t checksum = computeChecksum(arena, loopCount);
            telemetry.log(arena, checksum);
            telemetry.incrementLoop();
            
            // Print checkpoint
            SYSTEMTIME st;
            GetSystemTime(&st);
            printf("[%02d:%02d:%02d] Loop=%llu | Arena=%.2f MB / %.2f MB | Blocks=%llu | Checksum=0x%016llX\n",
                st.wHour, st.wMinute, st.wSecond,
                loopCount,
                arena.getTotalUsed() / (1024.0 * 1024.0),
                arena.getTotalAllocated() / (1024.0 * 1024.0),
                arena.getBlockCount(),
                checksum);
            
            nextCheckpoint = now + (checkpointSeconds * 1000);
        }
        
        // === PROPOSAL TRACKING ===
        // Simulate proposal generation latency
        LARGE_INTEGER freq, start, end;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        
        // Simulate work
        volatile int dummy = 0;
        for (int i = 0; i < 1000; ++i) dummy += i;
        
        QueryPerformanceCounter(&end);
        uint64_t latencyUs = ((end.QuadPart - start.QuadPart) * 1000000) / freq.QuadPart;
        
        bool applied = (dummy % 3 == 0); // 33% acceptance rate
        telemetry.recordProposal(applied, latencyUs);
        
        loopCount++;
        
        // Yield to prevent CPU starvation
        Sleep(1);
    }
    
    // === FINAL REPORT ===
    printf("\n=================================================================\n");
    printf("  STRESS TEST COMPLETE\n");
    printf("=================================================================\n");
    printf("  Duration:      %d seconds\n", durationSeconds);
    printf("  Total loops:   %llu\n", loopCount);
    printf("  Final arena:   %.2f MB used / %.2f MB allocated\n",
        arena.getTotalUsed() / (1024.0 * 1024.0),
        arena.getTotalAllocated() / (1024.0 * 1024.0));
    printf("  Log file:      stress_test_log.csv\n");
    printf("=================================================================\n");
    
    // Cleanup
    arena.destroy();
    telemetry.close();
    
    return 0;
}
