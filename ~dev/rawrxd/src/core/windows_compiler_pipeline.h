#pragma once
// Native MSVC build pipeline for IDE and agent tool consumers.
// Requires an MSVC developer environment (cl.exe and link.exe on PATH).
#include "windows_subprocess_runner.h"
#include <filesystem>
#include <string>
#include <vector>

namespace rawrxd::build {
struct BuildStage {
    ProcessResult process;
    bool artifactExists = false;
    bool success() const {
        return !process.timedOut && process.error.empty() &&
               process.exitCode == 0 && artifactExists;
    }
};
inline BuildStage compileObject(const std::filesystem::path& source,
                                const std::filesystem::path& object,
                                const std::filesystem::path& workingDirectory,
                                DWORD timeoutMs = 120000) {
    BuildStage stage;
    if (!std::filesystem::is_regular_file(source)) {
        stage.process.error = "C++ source file not found";
        return stage;
    }
    std::error_code ec;
    std::filesystem::remove(object, ec); // Prevent stale .obj from being accepted.
    stage.process = run({L"cl.exe", L"/nologo", L"/EHsc", L"/c",
                         source.wstring(), L"/Fo" + object.wstring()},
                        workingDirectory.wstring(), timeoutMs);
    stage.artifactExists = std::filesystem::is_regular_file(object);
    return stage;
}
inline BuildStage linkExecutable(const std::vector<std::filesystem::path>& objects,
                                 const std::filesystem::path& executable,
                                 const std::filesystem::path& workingDirectory,
                                 DWORD timeoutMs = 120000) {
    BuildStage stage;
    if (objects.empty()) {
        stage.process.error = "No object files to link";
        return stage;
    }
    for (const auto& object : objects) {
        if (!std::filesystem::is_regular_file(object)) {
            stage.process.error = "Object file not found: " + object.string();
            return stage;
        }
    }
    std::error_code ec;
    std::filesystem::remove(executable, ec); // Prevent stale .exe from being accepted.
    std::vector<std::wstring> args{L"link.exe", L"/nologo"};
    for (const auto& object : objects) args.push_back(object.wstring());
    args.push_back(L"/OUT:" + executable.wstring());
    stage.process = run(args, workingDirectory.wstring(), timeoutMs);
    stage.artifactExists = std::filesystem::is_regular_file(executable);
    return stage;
}
inline ProcessResult runExecutable(const std::filesystem::path& executable,
                                   const std::filesystem::path& workingDirectory,
                                   DWORD timeoutMs = 30000) {
    if (!std::filesystem::is_regular_file(executable)) {
        ProcessResult result;
        result.error = "Executable not found";
        return result;
    }
    return run({executable.wstring()}, workingDirectory.wstring(), timeoutMs);
}
} // namespace rawrxd::build
