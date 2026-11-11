#include "editor/tools.hpp"
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
using namespace worldforge::editor;
using namespace worldforge::editor::tools;
int main(){
    std::filesystem::path p("/etc/passwd");
    std::cout << "path: " << p.string() << "\n";
    std::cout << "is_absolute: " << p.is_absolute() << "\n";
    std::cout << "has_root_name: " << p.has_root_name() << "\n";
    std::cout << "has_root_directory: " << p.has_root_directory() << "\n";
    std::cout << "has_root_path: " << p.has_root_path() << "\n";
    std::cout << "has_relative_path: " << p.has_relative_path() << "\n";
    for(auto& part : p) {
        std::cout << "part: " << part.string() << "\n";
    }
    return 0;
}
