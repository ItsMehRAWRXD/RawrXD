#include "NativeProfilePath.h"
#include <iostream>

int main() {
    SetEnvironmentVariableW(L"RAWRXD_USER_DATA_DIR", nullptr);
    const auto normal = RawrXD::NativeProfile::directory();
    const std::filesystem::path isolated(L"C:\\RawrXD profile test\\session");
    if (!SetEnvironmentVariableW(L"RAWRXD_USER_DATA_DIR", isolated.c_str())) return 1;
    if (RawrXD::NativeProfile::directory() != isolated) return 2;
    if (RawrXD::NativeProfile::directory() == normal) return 3;
    SetEnvironmentVariableW(L"RAWRXD_USER_DATA_DIR", nullptr);
    if (RawrXD::NativeProfile::directory() != normal) return 4;
    std::cout << "NATIVE_PROFILE_PATH_TEST PASS\n";
    return 0;
}
