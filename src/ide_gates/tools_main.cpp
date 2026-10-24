#include "rawr_ide_gates.hpp"
#include <iostream>
#include <string>
int main(int argc, char** argv) {
  if (argc < 3 || (std::string(argv[1]) != "init" && std::string(argv[1]) != "apply")) {
    std::cerr << "usage: rawrxd-ide-gates init <receipt> | apply <results> <receipt>\n"; return 2;
  }
  std::vector<rawr::Gate> gates = rawr::default_gates(); std::string error;
  std::filesystem::path out;
  if (std::string(argv[1]) == "init") out = argv[2];
  else { if (argc < 4 || !rawr::apply_results(argv[2], gates, error)) { std::cerr << error << "\n"; return 4; } out = argv[3]; }
  if (!rawr::write_receipt_atomic(out, gates, error)) { std::cerr << error << "\n"; return 5; }
  std::cout << "wrote " << out.string() << "\n"; return 0;
}
