/**
 * main_qualification.cpp
 *
 * Phase C.1: Sovereign Runtime Qualification Entry Point
 *
 * One-command qualification for the complete Sovereign Runtime.
 *
 * Usage:
 *   sovereign-qualification
 *   sovereign-qualification --output report.json
 *   sovereign-qualification --json
 */

#include "SovereignQualification.hpp"

int main(int argc, char* argv[]) {
    return Sovereign::SovereignQualificationCLI::Run(argc, argv);
}
