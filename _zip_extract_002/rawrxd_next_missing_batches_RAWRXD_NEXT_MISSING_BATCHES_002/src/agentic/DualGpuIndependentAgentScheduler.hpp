#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace RawrXD::Agentic {

struct AgentDevice final {
    std::uint32_t ordinal{};
    std::uint32_t vendorId{};
    std::uint32_t deviceId{};
    std::string name{};
    bool available{};
};

enum class AgentRole : std::uint8_t {
    PrimaryCoder,
    SecondaryReviewer
};

struct AgentBinding final {
    std::uint64_t agentId{};
    AgentRole role{AgentRole::PrimaryCoder};
    std::string model{};
    AgentDevice device{};
    void* context{};
};

struct AgentMessage final {
    std::uint64_t fromAgent{};
    std::uint64_t toAgent{};
    std::string kind{};
    std::string payload{};
};

struct AgentRunResult final {
    bool ok{};
    std::string text{};
    std::string error{};
};

struct AgentContextCallbacks final {
    void* user{};
    void* (*create)(void* user, const AgentDevice&, std::string_view model){};
    void (*destroy)(void* user, void* context){};
    AgentRunResult (*run)(void* user, void* context, std::string_view prompt){};
};

struct DualGpuSchedulerConfig final {
    std::uint32_t preferredPrimaryOrdinal{};
    std::uint32_t preferredSecondaryOrdinal{1};
    bool requireSecondary{true};
    bool requireDistinctDevices{true};
    void* sharedToolAuthority{};
};

struct DualGpuSchedulerReceipt final {
    bool primaryBound{};
    bool secondaryBound{};
    bool independentContexts{};
    bool distinctDevices{};
    bool sharedToolAuthority{};
    bool secondaryUnavailableHandled{};
    std::uint64_t messagesExchanged{};
    std::uint64_t primaryRuns{};
    std::uint64_t secondaryRuns{};
    std::uint64_t failures{};

    [[nodiscard]] bool pass(bool secondaryRequired = true) const noexcept;
    [[nodiscard]] std::string text(bool secondaryRequired = true) const;
};

class DualGpuIndependentAgentScheduler final {
public:
    DualGpuIndependentAgentScheduler(
        DualGpuSchedulerConfig config,
        AgentContextCallbacks callbacks);
    ~DualGpuIndependentAgentScheduler();

    DualGpuIndependentAgentScheduler(const DualGpuIndependentAgentScheduler&) = delete;
    DualGpuIndependentAgentScheduler& operator=(const DualGpuIndependentAgentScheduler&) = delete;

    bool bind(
        const std::vector<AgentDevice>& devices,
        std::string primaryModel,
        std::string secondaryModel,
        std::string* why = nullptr);

    [[nodiscard]] AgentRunResult runPrimary(std::string_view prompt);
    [[nodiscard]] AgentRunResult runSecondary(std::string_view prompt);

    bool send(AgentMessage message);
    [[nodiscard]] std::optional<AgentMessage> receive(std::uint64_t agentId);

    [[nodiscard]] const std::optional<AgentBinding>& primary() const noexcept { return primary_; }
    [[nodiscard]] const std::optional<AgentBinding>& secondary() const noexcept { return secondary_; }
    [[nodiscard]] const DualGpuSchedulerReceipt& receipt() const noexcept { return receipt_; }

private:
    void destroyBinding(std::optional<AgentBinding>& binding) noexcept;
    std::optional<AgentDevice> select(const std::vector<AgentDevice>& devices, std::uint32_t ordinal) const;

    DualGpuSchedulerConfig config_{};
    AgentContextCallbacks callbacks_{};
    std::optional<AgentBinding> primary_{};
    std::optional<AgentBinding> secondary_{};
    std::deque<AgentMessage> messages_{};
    DualGpuSchedulerReceipt receipt_{};
};

} // namespace RawrXD::Agentic
