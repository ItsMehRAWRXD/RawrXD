#pragma once
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace idea_loop {
enum class Phase { Imagined, Conceived };
struct State {
    Phase phase = Phase::Imagined;
    std::uint64_t iteration = 0;
    std::string content;
};

// Purely informational cycle: no external-world action is implied.
// Transforms are caller-defined; no randomness, network, or model dependency.
class Loop {
public:
    using Transform = std::function<std::string(std::string_view)>;
    Loop(std::string seed, Transform conceive, Transform imagine)
        : state_{Phase::Imagined, 0, std::move(seed)},
          conceive_(std::move(conceive)), imagine_(std::move(imagine)) {}

    const State& state() const noexcept { return state_; }
    // Returns false when the 64-bit iteration counter is exhausted.
    bool step() {
        if (state_.iteration == UINT64_MAX) return false;
        const bool to_conceived = state_.phase == Phase::Imagined;
        std::string next = to_conceived ? conceive_(state_.content)
                                        : imagine_(state_.content);
        state_.content = std::move(next);
        state_.phase = to_conceived ? Phase::Conceived : Phase::Imagined;
        ++state_.iteration;
        return true;
    }
    template<class Observer>
    std::uint64_t run(std::uint64_t max_steps, Observer&& observe) {
        std::uint64_t done = 0;
        while (done < max_steps && step()) {
            observe(state_);
            ++done;
        }
        return done;
    }
private:
    State state_;
    Transform conceive_;
    Transform imagine_;
};
inline const char* phase_name(Phase p) noexcept {
    return p == Phase::Imagined ? "Imagined" : "Conceived";
}
} // namespace idea_loop
