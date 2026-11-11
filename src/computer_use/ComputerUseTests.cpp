#include "ComputerUse.h"
#include "AgentAdapter.h"
#include <cassert>
#include <iostream>
using namespace rawrxd::computer_use;
int main() {
    SafetyPolicy policy; ComputerUseEngine engine(policy);
    ComputerAction action; action.type=ActionType::Click;
    auto denied=engine.Execute(action); assert(!denied.success && denied.errorCode==ERROR_ACCESS_DENIED);
    action.type=ActionType::LaunchProcess; action.text=L"C:\\Windows\\System32\\notepad.exe";
    assert(!engine.Execute(action).success);
    AgentAdapter adapter(engine,[](const ComputerAction&){return false;});
    assert(adapter.Dispatch(action).errorCode==ERROR_ACCESS_DENIED);
    engine.Cancel(); assert(engine.Execute(action).errorCode==ERROR_CANCELLED);
    engine.ResetCancel();
    action.type=ActionType::FindWindow; action.text=L"";
    assert(engine.Execute(action).errorCode==ERROR_INVALID_PARAMETER);
    std::wcout<<L"Policy/cancel/validation smoke tests PASS\n";
}
