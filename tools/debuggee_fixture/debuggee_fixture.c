/* Deterministic debuggee for WaitForDebugEvent product verification.
 * Exports: break_site, g_watch_value, g_hit_counter
 * Exit code: 7
 */
#include <windows.h>

__declspec(dllexport) volatile int g_watch_value = 42;
__declspec(dllexport) volatile int g_hit_counter = 0;

__declspec(dllexport) void break_site(void)
{
    g_hit_counter += 1;
    g_watch_value = 100 + g_hit_counter;
    OutputDebugStringA("DEBUGGEE:break_site\n");
}

static void helper_leaf(void)
{
    OutputDebugStringA("DEBUGGEE:helper\n");
    g_watch_value += 1;
}

int main(void)
{
    OutputDebugStringA("DEBUGGEE:start\n");
    g_watch_value = 42;
    break_site();
    helper_leaf();
    break_site();
    OutputDebugStringA("DEBUGGEE:exit\n");
    return 7;
}
