// ============================================================================
// RawrXD Command Router - Phase 2 Implementation
// Flat hash table with open addressing for O(1) command dispatch
// ============================================================================

#include "CommandRouter.hpp"
#include <cstdio>
#include <intrin.h>

namespace RawrXD {

// Global router instance
CommandRouter g_CommandRouter;

CommandRouter::CommandRouter() {
    // Zero-initialize table
    for (size_t i = 0; i < TABLE_SIZE; ++i) {
        m_table[i].occupied = false;
        m_table[i].commandHash = 0;
        m_table[i].handler = nullptr;
    }
    InterlockedExchange(&m_commandCount, 0);
}

bool CommandRouter::Register(uint32_t hash, CommandHandler handler) {
    if (!handler || hash == 0) {
        printf("[CommandRouter] ERROR: Invalid registration (hash=0x%08X, handler=%p)\n", 
               hash, handler);
        return false;
    }
    
    // Check if already at capacity
    long currentCount = InterlockedCompareExchange(&m_commandCount, 0, 0);
    if (currentCount >= static_cast<long>(MAX_COMMANDS)) {
        printf("[CommandRouter] ERROR: Command table full (%ld/%zu)\n", 
               currentCount, MAX_COMMANDS);
        return false;
    }
    
    // Find insert slot
    size_t slot = FindInsertSlot(hash);
    if (slot >= TABLE_SIZE) {
        printf("[CommandRouter] ERROR: No free slot for hash 0x%08X\n", hash);
        return false;
    }
    
    // Check for collision (same hash already registered)
    if (m_table[slot].occupied && m_table[slot].commandHash == hash) {
        printf("[CommandRouter] WARNING: Overwriting handler for hash 0x%08X\n", hash);
    }
    
    // Register command (atomic not needed - registration is single-threaded at init)
    m_table[slot].commandHash = hash;
    m_table[slot].handler = handler;
    m_table[slot].occupied = true;
    
    InterlockedIncrement(&m_commandCount);
    
    printf("[CommandRouter] Registered hash 0x%08X at slot %zu\n", hash, slot);
    return true;
}

void CommandRouter::Route(uint32_t hash, const CommandContext& ctx) const {
    if (hash == 0) {
        printf("[CommandRouter] ERROR: Cannot route hash 0\n");
        return;
    }
    
    size_t slot = FindSlot(hash);
    if (slot < TABLE_SIZE && m_table[slot].occupied) {
        // Found handler - dispatch
        CommandHandler handler = m_table[slot].handler;
        if (handler) {
            handler(ctx);
            return;
        }
    }
    
    // No handler found - log unhandled command
    printf("[CommandRouter] WARNING: No handler for hash 0x%08X (eventId=%u)\n", 
           hash, ctx.eventId);
}

void CommandRouter::RouteEvent(const SharedEventFrame& frame) const {
    CommandContext ctx;
    ctx.eventId = frame.eventType;
    ctx.payload = frame.payload;
    ctx.payloadLen = frame.payloadLength;
    ctx.timestamp = frame.sequence; // Using sequence as proxy for timestamp
    ctx.sourceComponent = 0; // Could extract from payload
    
    Route(frame.eventType, ctx);
}

CommandHandler CommandRouter::GetHandler(uint32_t hash) const {
    size_t slot = FindSlot(hash);
    if (slot < TABLE_SIZE && m_table[slot].occupied) {
        return m_table[slot].handler;
    }
    return nullptr;
}

size_t CommandRouter::FindSlot(uint32_t hash) const {
    for (size_t attempt = 0; attempt < TABLE_SIZE; ++attempt) {
        size_t slot = ProbeSequence(hash, attempt);
        
        if (!m_table[slot].occupied) {
            // Empty slot - hash not found
            return TABLE_SIZE; // Not found
        }
        
        if (m_table[slot].commandHash == hash) {
            // Found matching hash
            return slot;
        }
        
        // Collision - continue probing
    }
    
    // Table full, hash not found
    return TABLE_SIZE;
}

size_t CommandRouter::FindInsertSlot(uint32_t hash) {
    for (size_t attempt = 0; attempt < TABLE_SIZE; ++attempt) {
        size_t slot = ProbeSequence(hash, attempt);
        
        if (!m_table[slot].occupied) {
            // Empty slot found
            return slot;
        }
        
        if (m_table[slot].commandHash == hash) {
            // Same hash - overwrite slot
            return slot;
        }
        
        // Collision - continue probing
    }
    
    // Table full
    return TABLE_SIZE;
}

} } // namespace RawrXD
