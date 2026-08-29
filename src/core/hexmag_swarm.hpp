// ============================================================================
// hexmag_swarm.hpp — MASM HexMag control plane (no Python)
// ============================================================================
// Mirrors RawrXD_HexMag_Swarm.asm layouts and exports.
// HexMag = weightless question-conditioned response search / orchestration.
//   HEXMAG_WEIGHTED_MODEL=FALSE  HEXMAG_GENERATE_ON_CONTACT=TRUE
//   HEXMAG_POLYMORPHIC_GEN=TRUE   HEXMAG_REPEAT_TUNER=TRUE (MASM)
//   Workers are ephemeral responders; each spawn mints an unused agent/model id.
// Deep2 / GGUF remain separate inference tracks.
// ============================================================================
#ifndef RAWRXD_HEXMAG_SWARM_HPP
#define RAWRXD_HEXMAG_SWARM_HPP

#include <cstdint>

constexpr uint32_t HX_ROLE_ARCHITECT    = 0;
constexpr uint32_t HX_ROLE_CODEGEN      = 1;
constexpr uint32_t HX_ROLE_VERIFICATION = 2;
constexpr uint32_t HX_ROLE_COUNT        = 3;

constexpr uint32_t HX_EVT_NONE            = 0;
constexpr uint32_t HX_EVT_GOAL_REQUESTED  = 1;
constexpr uint32_t HX_EVT_PARTIAL         = 2;
constexpr uint32_t HX_EVT_HANDOFF         = 3;
constexpr uint32_t HX_EVT_ROLE_REQUESTED  = 4;
constexpr uint32_t HX_EVT_ANSWER          = 5;
constexpr uint32_t HX_EVT_GOAL_SATISFIED  = 6;
constexpr uint32_t HX_EVT_FAILED          = 7;
constexpr uint32_t HX_EVT_CONTACT         = 8;
constexpr uint32_t HX_EVT_PLAN            = 9;
constexpr uint32_t HX_EVT_RESPONDER_SPAWN = 10;
constexpr uint32_t HX_EVT_ANSWER_CANDIDATE= 11;
constexpr uint32_t HX_EVT_REVERSE         = 12;
constexpr uint32_t HX_EVT_CRITIQUE        = 13;
constexpr uint32_t HX_EVT_NEED_INPUT      = 14;
constexpr uint32_t HX_EVT_VERIFY          = 15;
constexpr uint32_t HX_EVT_ANSWER_FINAL    = 16;
constexpr uint32_t HX_EVT_DEFLATE         = 17;
constexpr uint32_t HX_EVT_TUNER_ADJUST    = 18;
constexpr uint32_t HX_EVT_COUNT           = 19;

constexpr uint64_t HX_OK              = 0;
constexpr uint64_t HX_ERR_ALLOC       = 1;
constexpr uint64_t HX_ERR_NOT_INIT    = 2;
constexpr uint64_t HX_ERR_ALREADY_INIT= 3;
constexpr uint64_t HX_ERR_BAD_ARG     = 4;
constexpr uint64_t HX_ERR_DEPTH       = 5;
constexpr uint64_t HX_ERR_REPEAT      = 6;
constexpr uint64_t HX_ERR_QUEUE_FULL  = 7;
constexpr uint64_t HX_ERR_IDLE_FAIL   = 8;
constexpr uint64_t HX_ERR_TIMEOUT     = 9;

constexpr uint32_t HX_MAX_HANDOFF_DEPTH = 16;
constexpr uint32_t HX_MAX_SIGNATURES    = 32;
constexpr uint32_t HX_EVENT_SIZE        = 512;
constexpr uint32_t HX_EVENT_CAPACITY    = 256;
constexpr uint32_t HX_WORK_CAPACITY     = 64;
constexpr uint32_t HX_GOAL_BYTES        = 1024;

#pragma pack(push, 1)
struct HxEvent {
    uint32_t kind;
    uint32_t role;
    uint32_t target_role;
    uint32_t depth;
    uint64_t goal_id;
    uint32_t payload_len;
    uint32_t _pad0;
    char     payload[480];
};
#pragma pack(pop)
static_assert(sizeof(HxEvent) == 512, "HxEvent must be 512 bytes");

#ifdef RAWR_HAS_MASM
extern "C" {
    uint64_t HexMag_Init();
    uint64_t HexMag_Shutdown();
    void*    HexMag_GetState();
    uint64_t HexMag_SubmitGoal(const char* goal, uint32_t length);
    uint32_t HexMag_Step();
    uint32_t HexMag_PollEvent(HxEvent* out_event);
    uint64_t HexMag_RunToSatisfied(uint32_t max_steps);
    uint32_t HexMag_BotCount();
    uint64_t HexMag_AgentsSpawned();
    uint64_t HexMag_LastAgentId();
    uint32_t HexMag_TunerAttempt();
    uint32_t HexMag_IsInitialized();
    uint32_t HexMag_Feedback(uint32_t fail_kind_or_zero);
    uint32_t HexMag_SetParallelAgents(uint32_t count);
    uint32_t HexMag_GetParallelAgents();
}
#endif

inline const char* HxEventKindName(uint32_t kind) {
    switch (kind) {
        case HX_EVT_GOAL_REQUESTED:   return "goal.requested";
        case HX_EVT_PARTIAL:          return "partial";
        case HX_EVT_HANDOFF:          return "handoff";
        case HX_EVT_ROLE_REQUESTED:   return "role.requested";
        case HX_EVT_ANSWER:           return "answer";
        case HX_EVT_GOAL_SATISFIED:   return "goal.satisfied";
        case HX_EVT_FAILED:           return "failed";
        case HX_EVT_CONTACT:          return "contact";
        case HX_EVT_PLAN:             return "plan";
        case HX_EVT_RESPONDER_SPAWN:  return "responder.spawn";
        case HX_EVT_ANSWER_CANDIDATE: return "answer.candidate";
        case HX_EVT_REVERSE:          return "reverse";
        case HX_EVT_CRITIQUE:         return "critique";
        case HX_EVT_NEED_INPUT:       return "need_input";
        case HX_EVT_VERIFY:           return "verify";
        case HX_EVT_ANSWER_FINAL:     return "answer.final";
        case HX_EVT_DEFLATE:          return "deflate";
        case HX_EVT_TUNER_ADJUST:     return "tuner.adjust";
        default:                      return "none";
    }
}

inline const char* HxRoleName(uint32_t role) {
    switch (role) {
        case HX_ROLE_ARCHITECT:     return "architect";
        case HX_ROLE_CODEGEN:       return "code_generation";
        case HX_ROLE_VERIFICATION:  return "verification";
        default:                    return "unknown";
    }
}

#endif // RAWRXD_HEXMAG_SWARM_HPP
