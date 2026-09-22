#pragma once
#include "Common.hpp"
#include <filesystem>

namespace rawrxd::closure {

struct ProcessSpec {
    std::string command_line;
    std::filesystem::path working_directory;
    std::chrono::milliseconds timeout{std::chrono::minutes(10)};
};

struct ProcessResult {
    bool launched{};
    bool timed_out{};
    int exit_code{-1};
    std::string output;
    std::chrono::milliseconds elapsed{0};
};

class IProcessRunner {
public:
    virtual ~IProcessRunner() = default;
    virtual ProcessResult run(const ProcessSpec&) = 0;
};

class NativeProcessRunner final : public IProcessRunner {
public:
    ProcessResult run(const ProcessSpec&) override;
};

} // namespace rawrxd::closure
