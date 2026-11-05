#include <filesystem>
#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
namespace fs=std::filesystem;
static bool save(const fs::path& p,const std::string& content) {
    std::ofstream file(p,std::ios::binary|std::ios::trunc);
    if(!file)return false;
    file.write(content.data(),static_cast<std::streamsize>(content.size()));
    file.flush(); if(!file)return false;
    file.close(); if(!file)return false;
    std::ifstream verify(p,std::ios::binary);if(!verify)return false;
    std::string actual((std::istreambuf_iterator<char>(verify)),{});
    return actual==content && !verify.bad();
}
static std::string read(const fs::path&p) {
    std::ifstream f(p,std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)),{});
}
int main(){
 fs::path root=fs::temp_directory_path()/("rawrxd_batch27_portable_"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
 fs::create_directories(root);
 int pass=0,all=0;
 auto check=[&](bool ok,const char*name){++all;pass+=ok;std::cout<<name<<"="<<(ok?"PASS":"FAIL")<<"\n";};
 auto p=root/"fixture.cpp";
 check(save(p,"int x=1;\n"),"01_new_file");
 check(read(p)=="int x=1;\n","02_disk_readback");
 check(save(p,"int x=2;\n"),"03_overwrite");
 check(read(p)=="int x=2;\n","04_overwrite_readback");
 check(save(p,""),"05_empty_file");
 check(read(p).empty(),"06_empty_readback");
 check(save(p,"line1\nline2\n"),"07_multiline");
 check(read(p)=="line1\nline2\n","08_multiline_readback");
 std::string nul("a\0b",3);
 check(save(p,nul),"09_binary_write");
 check(read(p)==nul,"10_binary_readback");
 auto unicode=fs::path(u8"文件-данные-Δ.cpp");
 check(save(root/unicode,"unicode-path"),"11_unicode_filename");
 check(read(root/unicode)=="unicode-path","12_unicode_filename_readback");
 check(!save(root/"nonexistent"/"x.cpp","bad"),"13_missing_parent_fails");
 check(!fs::exists(root/"nonexistent"/"x.cpp"),"14_missing_parent_no_file");
 check(save(p,"final\n") && read(p)=="final\n","15_final_roundtrip");
 fs::remove_all(root);
 std::cout<<"PORTABLE_FILESYSTEM_SMOKE="<<pass<<"/"<<all<<"\n";
 return pass==all?0:1;
}
