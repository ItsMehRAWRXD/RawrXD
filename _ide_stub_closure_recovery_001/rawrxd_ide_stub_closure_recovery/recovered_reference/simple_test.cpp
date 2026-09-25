// ============================================================================
// [SOURCE] win32app\simple_test.cpp
// FILE: D:\rawrxd\src\win32app\simple_test.cpp
// ============================================================================

// Simple IDE instantiation test
// [SYSINCLUDE] #include <windows.h>
// [SYSINCLUDE] #include <iostream>
// [SYSINCLUDE] #include <fstream>

int main() {
    std::ofstream log("simple_test_log.txt");
    log << "Test started\n";
    log.flush();


    log << "About to load library\n";
    log.flush();
    
    // Just test if we can reach main
    
    log << "Success\n";
    log.close();
    
    return 0;
}
