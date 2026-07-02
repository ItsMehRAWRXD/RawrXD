/* RawrXD_Ring_Attention.h
 * Phase 23B: Distributed Ring Attention Interface
 * Zero-copy KV-cache transfers for massive context windows
 */

#ifndef RAWRXD_RING_ATTENTION_H
#define RAWRXD_RING_ATTENTION_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =============================================================================
 * Constants
 * ============================================================================= */
#define RING_MAX_NODES          32
#define RING_MAX_KV_SIZE        (256 * 1024 * 1024)  /* 256MB */
#define RING_TOKEN_SIZE         64
#define RING_TIMEOUT_MS         30000

/* Message types */
#define MSG_TYPE_KV_CACHE       1
#define MSG_TYPE_ATTENTION      2
#define MSG_TYPE_TOKEN          3
#define MSG_TYPE_HEARTBEAT      4
#define MSG_TYPE_RECOVERY       5

/* =============================================================================
 * Structures
 * ============================================================================= */

/* Ring protocol header (24 bytes) */
typedef struct {
    uint32_t magic;          /* RING_MAGIC (0x52414721) */
    uint32_t version;        /* RING_VERSION (1) */
    uint32_t msg_type;       /* Message type */
    uint32_t node_id;        /* Source node ID */
    uint32_t seq_num;        /* Sequence number */
    uint32_t payload_len;    /* Payload length */
} RingHeader;

/* KV-cache chunk descriptor (32 bytes) */
typedef struct {
    uint32_t layer_id;       /* Layer being processed */
    uint32_t head_id;        /* Attention head */
    uint32_t seq_start;      /* Start sequence position */
    uint32_t seq_len;        /* Sequence length */
    uint32_t data_size;      /* Size of KV data */
    uint32_t checksum;       /* CRC32 checksum */
    uint32_t flags;          /* Flags (e.g., LAST_CHUNK) */
    uint32_t reserved;       /* Reserved */
} KVChunkDesc;

/* Ring attention statistics (64 bytes) */
typedef struct {
    uint64_t kv_chunks_sent;         /* KV chunks sent */
    uint64_t kv_chunks_received;     /* KV chunks received */
    uint64_t attention_computed;     /* Attention computations done */
    uint64_t ring_rotations;         /* Full ring cycles completed */
    uint64_t recovery_events;        /* Recovery events triggered */
    uint32_t node_count;             /* Total nodes in ring */
    uint32_t local_node_id;          /* This node's ID */
    uint8_t  is_token_holder;        /* Currently holding ring token */
    uint8_t  ring_active;            /* Ring is active */
    uint8_t  reserved[14];           /* Padding */
} RingStats;

/* =============================================================================
 * API Functions
 * ============================================================================= */

/**
 * Initialize ring attention system
 * @param node_count Total nodes in ring
 * @param local_node_id This node's ID (0-indexed)
 * @param layer_count Total layers to distribute
 * @return 1 on success, 0 on failure
 */
int RingAttention_Init(int node_count, int local_node_id, int layer_count);

/**
 * Join the ring topology
 * @param node_addresses Array of "tcp://host:port" strings
 * @return 1 on success, 0 on failure
 */
int RingAttention_JoinRing(const char** node_addresses);

/**
 * Process attention for assigned layers
 * @param input_tokens Input token embeddings
 * @param output_logits Output logits
 * @param token_count Number of tokens
 * @return 1 on success, 0 on failure
 */
int RingAttention_ProcessLayer(void* input_tokens, void* output_logits, int token_count);

/**
 * Send KV-cache to next node
 * @param layer_id Layer being sent
 * @return 1 on success, 0 on failure
 */
int RingAttention_SendKVCache(int layer_id);

/**
 * Receive KV-cache from previous node
 * @return 1 on success, 0 on failure
 */
int RingAttention_ReceiveKVCache(void);

/**
 * Gracefully leave the ring
 */
void RingAttention_LeaveRing(void);

/**
 * Get ring attention statistics
 * @param stats Pointer to stats structure to fill
 */
void RingAttention_GetStats(RingStats* stats);

/**
 * Check if this node holds the ring token
 * @return true if token holder
 */
bool RingAttention_IsTokenHolder(void);

/**
 * Wait for ring token (blocking)
 * @return 1 on success, 0 on timeout/failure
 */
int RingAttention_WaitForToken(void);

/* =============================================================================
 * Convenience Macros
 * ============================================================================= */

/* Initialize ring with error checking */
#define RING_INIT(nodes, id, layers) \
    RingAttention_Init(nodes, id, layers)

/* Join ring with error checking */
#define RING_JOIN(addresses) \
    RingAttention_JoinRing(addresses)

/* Process layer with automatic retry */
#define RING_PROCESS(input, output, count) \
    RingAttention_ProcessLayer(input, output, count)

/* Leave ring gracefully */
#define RING_LEAVE() \
    RingAttention_LeaveRing()

/* Get stats */
#define RING_STATS(stats_ptr) \
    RingAttention_GetStats(stats_ptr)

#ifdef __cplusplus
}
#endif

#endif /* RAWRXD_RING_ATTENTION_H */
