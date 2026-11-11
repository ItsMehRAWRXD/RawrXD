#pragma once
// RuntimeManifest — executable / evidence-derived truth (no doc claims set state).
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace RawrXD::Self {

enum class ComponentState {
    Active,
    PresentNotActive,
    Disabled,
    Fallback,
    Missing,
    Broken,
    Uncertified,
    Closed,   // cert ladder: frozen PASS
    Open,     // not yet run
    Blocked,  // waiting on prior rung
};

enum class TodoPriority { P0, P1, P2 };

struct SourceSite {
    std::string file;
    std::string function;
    std::uint32_t line = 0;
};

struct LadderRung {
    std::string id;
    std::string title;
    ComponentState state = ComponentState::Open;
    std::string evidence;   // GATE.txt / batch dir
    std::string note;
};

struct OrderedTodo {
    int ordinal = 0;
    TodoPriority priority = TodoPriority::P0;
    std::string id;
    std::string title;
    std::string reason;
    std::vector<std::string> blockedBy;
    std::string evidenceHint;
};

struct RuntimeManifestSnapshot {
    std::string generatedAt;
    std::string authorityRule =
        "DOC CLAIMS DO NOT SET STATE. compiled+registered+active+cert = state.";
    std::vector<LadderRung> ladder;
    std::vector<OrderedTodo> nextTodos; // ordered: do these next
    std::string firstOpen;
    std::string firstGenuineFail; // "NONE" if clear through closed prefix
};

const char* toString(ComponentState s);
const char* toString(TodoPriority p);

// Build ladder + ordered next-todos from evidence GATE files under probe root.
RuntimeManifestSnapshot buildCertLadderManifest(
    const std::string& evidenceRoot =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001)");

// JSON (minimal, no deps).
std::string snapshotToJson(const RuntimeManifestSnapshot& s);

// Human "what's next" board.
std::string snapshotToTodoBoard(const RuntimeManifestSnapshot& s);

} // namespace RawrXD::Self
