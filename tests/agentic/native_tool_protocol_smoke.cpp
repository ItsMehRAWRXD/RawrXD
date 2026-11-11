#include <cstdio>
#include <string>

#include "../../src/agentic/NativeToolProtocol.h"

static int failures = 0;

static void expect(bool condition, const char* name) {
    std::printf("%s %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition) ++failures;
}

int main() {
    using rawrxd::agentic::ParseNativeToolCommand;

    auto read = ParseNativeToolCommand("TOOL read src/main.cpp\n<|eot_id|>");
    expect(read.valid && read.tool == "readFile" && read.path == "src/main.cpp",
           "read_command_and_end_marker");

    auto write = ParseNativeToolCommand("TOOL write calc.cpp @@int main(){return 0;}@@");
    expect(write.valid && write.tool == "writeFile" && write.path == "calc.cpp" &&
               write.content == "int main(){return 0;}" ,
           "write_payload_is_exact");

    auto build = ParseNativeToolCommand("TOOL build");
    expect(build.valid && build.tool == "runInTerminal" &&
               build.command.find("cmake --build") != std::string::npos,
           "build_is_bounded_host_command");

    auto prose = ParseNativeToolCommand("I will inspect the file. TOOL read calc.cpp");
    expect(!prose.valid, "prose_never_dispatches");

    auto trailing = ParseNativeToolCommand("TOOL read calc.cpp\nextra");
    expect(!trailing.valid, "trailing_model_chatter_rejected");

    auto unknown = ParseNativeToolCommand("TOOL bash del *");
    expect(!unknown.valid, "arbitrary_shell_rejected");

    std::printf("FAIL_COUNT=%d\nPROMOTE=0\n", failures);
    return failures == 0 ? 0 : 1;
}
