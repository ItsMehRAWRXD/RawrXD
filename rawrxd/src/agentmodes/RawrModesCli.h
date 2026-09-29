// RawrModesCli.h — CLI surface for the honesty-gated agent modes.
#pragma once

namespace rawrxd { namespace modes {

// Dispatch a `rawr <sub>` modes command. argv[0] is the subcommand name.
int runRawrModes(int argc, char** argv);

}} // namespace rawrxd::modes
