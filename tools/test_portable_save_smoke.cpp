// Portable filesystem acceptance smoke. Not a native Win32IDE GUI test.
#include <filesystem>
#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
namespace fs = std::filesystem;
static bool save(const fs::path& p, const std::string& bytes) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    out.flush();
    if (!out) return false;
    out.close();
    if (!out) return false;
    std::ifstream in(p, std::ios::binary);
    if (!in) return false;
    std::string actual((std::istreambuf_iterator<char>(in)), {});
    return !in.bad() && actual == bytes;
}
static std::string read(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), {});
}
int main() {
    const auto root = fs::temp_directory_path() /
        ("rawrxd_portable_save_" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(root);
    int passed = 0, total = 0;
    auto check = [&](bool ok, const char* name) {
        ++total;
        if (ok) ++passed;
        std::cout << name << "=" << (ok ? "PASS" : "FAIL") << "\n";
    };
    const auto p = root / "fixture.cpp";
    check(save(p, "int x=1;\n"), "01_new_file");
    check(read(p) == "int x=1;\n", "02_disk_readback");
    check(save(p, "int x=2;\n"), "03_overwrite");
    check(read(p) == "int x=2;\n", "04_overwrite_readback");
    check(save(p, ""), "05_empty_file");
    check(read(p).empty(), "06_empty_readback");
    check(save(p, "line1\nline2\n"), "07_multiline");
    check(read(p) == "line1\nline2\n", "08_multiline_readback");
    const std::string binary("a\0b", 3);
    check(save(p, binary), "09_binary_write");
    check(read(p) == binary, "10_binary_readback");
    const auto unicode = fs::path(u8"文件-данные-Δ.cpp");
    check(save(root / unicode, "unicode-path"), "11_unicode_filename");
    check(read(root / unicode) == "unicode-path", "12_unicode_filename_readback");
    check(!save(root / "missing" / "x.cpp", "bad"), "13_missing_parent_fails");
    check(!fs::exists(root / "missing" / "x.cpp"), "14_missing_parent_no_file");
    check(save(p, "final\n") && read(p) == "final\n", "15_final_roundtrip");
    fs::remove_all(root);
    std::cout << "PORTABLE_FILESYSTEM_SMOKE=" << passed << "/" << total << "\n";
    return passed == total ? 0 : 1;
}
