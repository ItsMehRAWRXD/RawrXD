#include "rawr_ide_gates.hpp"
#include <cassert>
#include <fstream>
#include <filesystem>
#include <iostream>
int main(){namespace fs=std::filesystem;auto g=rawr::default_gates();assert(g.size()==30);assert(g.front().id==121&&g.back().id==150);assert(rawr::parse_status("PASS")==rawr::Status::pass);assert(!rawr::parse_status("PASSED"));auto d=fs::temp_directory_path()/"rawrxd_ide_006_tests";fs::create_directories(d);assert(rawr::safe_evidence_path(d,"receipts/a.json"));assert(!rawr::safe_evidence_path(d,"../outside"));{std::ofstream f(d/"bad.txt");f<<"121|PASS|\n";}std::string e;assert(!rawr::apply_results(d/"bad.txt",g,e));assert(g[0].status==rawr::Status::not_run);{std::ofstream f(d/"good.txt");f<<"121|PASS|hwnd_dump.json\n127|FAIL|q2k_divergence.log\n";}assert(rawr::apply_results(d/"good.txt",g,e));assert(g[0].status==rawr::Status::pass);assert(g[6].status==rawr::Status::fail);assert(g[1].status==rawr::Status::not_run);assert(rawr::write_receipt_atomic(d/"receipt.json",g,e));assert(fs::file_size(d/"receipt.json")>100);fs::remove_all(d);std::cout<<"gate tests pass\n";}
