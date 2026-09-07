#pragma once
#include "rawr_argument_parser.hpp"
#include "rawr_exit_codes.hpp"
namespace rawr {
int CmdRun(const CliArgs& a);
int CmdChat(const CliArgs& a);
int CmdAgent(const CliArgs& a);
int CmdSteer(const CliArgs& a);
int CmdResume(const CliArgs& a);
int CmdTerm(const CliArgs& a);
int CmdServe(const CliArgs& a);
void PrintUsage();
} // namespace rawr
