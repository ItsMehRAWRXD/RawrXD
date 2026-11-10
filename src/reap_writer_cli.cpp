#include "deep2/GGUFLoader.hpp"
#include "deep2/ReapWriter.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
namespace fs=std::filesystem;
static std::string readAll(const fs::path& p){std::ifstream f(p,std::ios::binary);return std::string((std::istreambuf_iterator<char>(f)),{});}
int main(int argc,char**argv){
  if(argc!=4){std::cerr<<"usage: rawr-reap-writer <first-shard.gguf> <mask.json> <output-dir>\n";return 2;}
  const fs::path src=fs::absolute(argv[1]), mask=fs::absolute(argv[2]), out=fs::absolute(argv[3]);
  if(!fs::exists(src)||!fs::exists(mask)){std::cerr<<"REAP_WRITER_INPUT_MISSING\n";return 4;}
  Deep2::GGUFLoader l; if(!l.load(src.string())){std::cerr<<"REAP_WRITER_SOURCE_INVALID: "<<l.error()<<"\n";return 4;}
  const std::string m=readAll(mask);
  // A writer must never infer a mask. Accept either a completed selection
  // manifest or a real replay calibration receipt with generated windows.
  const bool maskReady = m.find("\"complete\":true")!=std::string::npos &&
      m.find("mask_sha256") != std::string::npos && m.find("\"selected_bytes\"")!=std::string::npos;
  const bool calibrationReady = m.find("RAWRXD_REAP_CALIBRATION_001")!=std::string::npos &&
      m.find("\"generated\":1")!=std::string::npos;
  if(!maskReady && !calibrationReady){
    std::cout<<"{\"status\":\"BLOCKED\",\"reason\":\"INCOMPLETE_SELECTION_MANIFEST\",\"output_written\":false}\n";return 4;
  }
  // This is the safe production operation currently proven by the codebase:
  // a lossless GGUF round-trip.  It never prunes or rewrites tensor payloads.
  // Calibration masks are accepted only as a completed, hashed manifest; the
  // mask cannot alter bytes until a separate parity-certified transformer exists.
  std::error_code ec;
  fs::create_directories(out, ec);
  if(ec){ std::cout<<"{\"status\":\"BLOCKED\",\"reason\":\"OUTPUT_DIRECTORY_FAILED\",\"output_written\":false}\n"; return 4; }
  const fs::path dst = out / (src.stem().string() + ".reap.gguf");
  Deep2::ReapWriter writer;
  const auto written = writer.writeRoundTrip(src.string(), dst.string(), true);
  if(!written.success){ std::cout<<"{\"status\":\"FAIL\",\"reason\":\""<<written.error<<"\",\"output_written\":false}\n"; return 5; }
  const auto verified = Deep2::ReapWriter::verifyRoundTrip(src.string(), dst.string());
  if(!verified.success){ std::cout<<"{\"status\":\"FAIL\",\"reason\":\"ROUND_TRIP_VERIFY_FAILED\",\"detail\":\""<<verified.error<<"\",\"output_written\":true}\n"; return 6; }
  std::cout<<"{\"status\":\"PASS\",\"mode\":\"LOSSLESS_ROUND_TRIP\",\"source_shards_valid\":true,\"output_written\":true,\"verified\":true,\"tensors\":"<<l.tensorCount()<<",\"bytes\":"<<written.bytesWritten<<",\"output\":\""<<dst.string()<<"\"}\n";
  return 0;
}
