#include "agent/native_action_executor.hpp"
#include <cassert>

int main() {
    NativeExecutionContext context;
    context.commandTimeoutMs = 2000;
    context.planTimeoutMs = 10000;
    NativeActionExecutor executor(context);

    NativeAction ok;
    ok.command = "cmd.exe";
    ok.args = {"/c", "exit", "0"};
    assert(executor.execute(ok));

    NativeAction fail;
    fail.command = "cmd.exe";
    fail.args = {"/c", "exit", "7"};
    assert(!executor.execute(fail));
    assert(!fail.error.empty());

    NativeActionExecutor cancelled(context);
    cancelled.cancel();
    NativeAction blocked;
    blocked.command = "cmd.exe";
    blocked.args = {"/c", "exit", "0"};
    assert(!cancelled.execute(blocked));
    return 0;
}
