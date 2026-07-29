#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
<<<<<<< HEAD
=======
#include <filesystem>
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

struct FileInfo {
    std::string name;
    std::string path;
    bool isDirectory;
    uint64_t size;
};

class FileBrowser {
public:
    FileBrowser();
    ~FileBrowser();

    void initialize();
    std::vector<FileInfo> listDirectory(const std::string& dirpath);
    std::vector<std::string> getDrives();

    // Callbacks
    std::function<void(const std::string&)> onFileSelected;
    std::function<void(const std::string&, const std::string&)> onError;

private:
    void logOperation(const std::string& level, const std::string& message);
};

