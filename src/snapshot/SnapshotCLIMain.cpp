// snapshot/SnapshotCLIMain.cpp
//
// Main entry point for the RawrXD Snapshot Engine CLI.

#include "snapshot/SnapshotCLI.hpp"
#include <vector>
#include <string>
#include <iostream>

int main(int argc, char** argv) {
    kartgib::SnapshotCLI cli;
    return cli.Run(argc, argv);
}