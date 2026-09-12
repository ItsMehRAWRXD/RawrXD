/* ss_model_plan.h — GGUF metadata → runtime plan; no family table */
#ifndef SS_MODEL_PLAN_H
#define SS_MODEL_PLAN_H
#include <stdint.h>
#define SS_MAX_BLOCKS 256
#define SS_MAX_EXPERTS 512
#define SS_MAX_SHARDS 32
#define SS_ARCH_NAME_MAX 64
#define SS_SHARD_PATH_MAX 512
typedef enum SsCodec {
    SS_CODEC_UNKNOWN = 0,
    SS_CODEC_F32,
    SS_CODEC_F16,
    SS_CODEC_Q4_K,
    SS_CODEC_Q5_K,
    SS_CODEC_Q6_K
} SsCodec;
typedef struct SsTensorRef {
    uint64_t fileOffset;
    uint64_t bytes;
    uint64_t dims[4];
    uint32_t nDims;
    uint32_t codec;
    uint32_t shardId;
    uint64_t identity;
    int present;
} SsTensorRef;
typedef struct SsBlockPlan {
    uint32_t blockIndex;
    SsTensorRef attnNorm;
    SsTensorRef qA, qB, kvA, kvB, attnOut;
    SsTensorRef qANorm, kvANorm;
    SsTensorRef ffnNorm;
    SsTensorRef router;
    SsTensorRef expertGate, expertUp, expertDown;
    SsTensorRef sharedGate, sharedUp, sharedDown;
    SsTensorRef denseGate, denseUp, denseDown;
    uint32_t requiredTensorCount;
    uint32_t resolvedTensorCount;
    uint32_t rolesBound;
    uint32_t isMoe;
    uint32_t complete;
} SsBlockPlan;
typedef struct SsModelPlan {
    char architecture[SS_ARCH_NAME_MAX];
    char shardPaths[SS_MAX_SHARDS][SS_SHARD_PATH_MAX];
    uint32_t shardCount;
    uint32_t embeddingLength;
    uint32_t vocabSize;
    uint32_t blockCount;
    uint32_t blocksPresent;
    uint32_t inventoredBlockCount;
    uint32_t attentionHeads;
    uint32_t kvHeads;
    uint32_t qLoraRank;
    uint32_t kvLoraRank;
    uint32_t expertCount;
    uint32_t expertTopK;
    uint32_t expertSharedCount;
    uint32_t leadingDenseBlocks;
    uint32_t ropeDim;
    float ropeFreqBase;
    SsTensorRef tokenEmbedding;
    SsTensorRef outputNorm;
    SsTensorRef outputWeight;
    SsBlockPlan blocks[SS_MAX_BLOCKS];
    uint32_t metaReal;
    uint32_t planReal;
    uint32_t missingRequiredBlocks;
    uint32_t duplicateBlockOwners;
    uint32_t ambiguousTensorRoles;
    uint32_t unresolvedRequiredTensors;
    uint32_t multiShardInventoryPass;
    uint32_t familyTableUsed;
} SsModelPlan;
int ss_model_plan_build(const char *shard_path, SsModelPlan *out);
int ss_model_plan_build_multi(const char *any_shard_path, SsModelPlan *out);
void ss_model_plan_print(const SsModelPlan *p);
void ss_model_plan_print_inventory(const SsModelPlan *p);
#endif
