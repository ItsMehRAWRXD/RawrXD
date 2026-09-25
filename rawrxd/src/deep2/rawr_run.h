#pragma once

// rawr_run.h
// CLI entry point for: rawr run <model> <prompt>
// Called by rawrxd_cli main after consuming the "run" subcommand token.
// argc/argv start at the first argument after "run".
int rawr_run_main(int argc, char** argv);
