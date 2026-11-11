#!/usr/bin/env python3
"""
RawrXD CI Verification Pipeline
Automated verification for release candidates in CI/CD environments.
"""

import json
import os
import sys
import hashlib
import subprocess
import argparse
from datetime import datetime
from pathlib import Path

class CIVerifier:
    def __init__(self, release_path):
        self.release_path = Path(release_path)
        self.results = {}
        self.all_passed = True
    
    def log_result(self, check, passed, detail=""):
        self.results[check] = {
            "passed": passed,
            "detail": detail,
            "timestamp": datetime.now().isoformat()
        }
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status} | {check}")
        if detail:
            print(f"         {detail}")
        if not passed:
            self.all_passed = False
    
    def verify_release_structure(self):
        """Verify the release directory has all required components."""
        print("\n📁 Release Structure Verification")
        required = [
            "RELEASE_MANIFEST.json",
            "RELEASE_NOTES.md",
            "verify_release.bat",
            "evidence/RC0.2_CERTIFICATION.json",
            "evidence/release_manifest.json",
            "evidence/hardware_attestation.json",
            "evidence/inference_witness.json",
            "evidence/performance_certification.json",
            "evidence/val_certification.json",
            "evidence/release_freeze_evidence.json",
        ]
        
        all_found = True
        for f in required:
            path = self.release_path / f
            if not path.exists():
                self.log_result(f"Required file: {f}", False)
                all_found = False
        
        if all_found:
            self.log_result("Release structure", True, "All required files present")
    
    def verify_manifest_integrity(self):
        """Verify the release manifest is valid JSON and contains required fields."""
        print("\n📄 Manifest Integrity Verification")
        manifest_path = self.release_path / "RELEASE_MANIFEST.json"
        
        if not manifest_path.exists():
            self.log_result("Manifest file exists", False)
            return
        
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
            
            required = ["release", "build_timestamp", "git_commit", "file_manifest", "signature"]
            for field in required:
                if field not in manifest:
                    self.log_result(f"Manifest field: {field}", False)
                    return
            
            self.log_result("Manifest integrity", True, 
                          f"Release: {manifest.get('release')}, "
                          f"Commit: {manifest.get('git_commit', 'unknown')[:12]}")
        except json.JSONDecodeError as e:
            self.log_result("Manifest JSON parse", False, str(e))
    
    def verify_certification(self):
        """Verify the RC0.2 certification document."""
        print("\n🏆 Certification Verification")
        cert_path = self.release_path / "evidence" / "RC0.2_CERTIFICATION.json"
        
        if not cert_path.exists():
            self.log_result("Certification file", False)
            return
        
        try:
            with open(cert_path) as f:
                cert = json.load(f)
            
            status = cert.get("status", "UNKNOWN")
            passed = cert.get("summary", {}).get("passed_checks", 0)
            total = cert.get("summary", {}).get("total_checks", 0)
            
            if status == "CERTIFIED" and passed == total:
                self.log_result("Certification status", True, 
                              f"{passed}/{total} checks passed, Status: {status}")
            else:
                self.log_result("Certification status", False,
                              f"{passed}/{total} checks passed, Status: {status}")
        except json.JSONDecodeError as e:
            self.log_result("Certification JSON parse", False, str(e))
    
    def verify_hardware_attestation(self):
        """Verify hardware attestation evidence."""
        print("\n🖥️  Hardware Attestation Verification")
        hw_path = self.release_path / "evidence" / "hardware_attestation.json"
        
        if not hw_path.exists():
            self.log_result("Hardware attestation file", False)
            return
        
        try:
            with open(hw_path) as f:
                hw = json.load(f)
            
            gpus = hw.get("gpus", [])
            total_vram = hw.get("total_vram_mb", 0)
            matches = hw.get("matches_target_configuration", False)
            
            if len(gpus) >= 2 and matches:
                self.log_result("Hardware attestation", True,
                              f"{len(gpus)} GPUs, {total_vram/(1024):.0f} GB total VRAM")
            else:
                self.log_result("Hardware attestation", False,
                              f"GPUs: {len(gpus)}, Target match: {matches}")
        except json.JSONDecodeError as e:
            self.log_result("Hardware attestation JSON parse", False, str(e))
    
    def verify_performance(self):
        """Verify performance certification."""
        print("\n⚡ Performance Verification")
        perf_path = self.release_path / "evidence" / "performance_certification.json"
        
        if not perf_path.exists():
            self.log_result("Performance file", False)
            return
        
        try:
            with open(perf_path) as f:
                perf = json.load(f)
            
            tps = perf.get("overall_tps", 0)
            latency = perf.get("first_token_latency_ms", 0)
            
            if tps >= 200 and latency <= 100:
                self.log_result("Performance targets", True,
                              f"{tps:.0f} TPS, {latency:.0f}ms latency")
            else:
                self.log_result("Performance targets", False,
                              f"{tps:.0f} TPS, {latency:.0f}ms latency (min 200 TPS, max 100ms)")
        except json.JSONDecodeError as e:
            self.log_result("Performance JSON parse", False, str(e))
    
    def verify_val_suite(self):
        """Verify VAL certification suite."""
        print("\n✅ VAL Suite Verification")
        val_path = self.release_path / "evidence" / "val_certification.json"
        
        if not val_path.exists():
            self.log_result("VAL certification file", False)
            return
        
        try:
            with open(val_path) as f:
                val = json.load(f)
            
            passed = val.get("tests_passed", 0)
            total = val.get("total_tests", 0)
            
            if passed == total and total >= 27:
                self.log_result("VAL suite", True, f"{passed}/{total} tests passed")
            else:
                self.log_result("VAL suite", False, f"{passed}/{total} tests passed")
        except json.JSONDecodeError as e:
            self.log_result("VAL certification JSON parse", False, str(e))
    
    def verify_release_freeze(self):
        """Verify release freeze evidence."""
        print("\n❄️  Release Freeze Verification")
        freeze_path = self.release_path / "evidence" / "release_freeze_evidence.json"
        
        if not freeze_path.exists():
            self.log_result("Release freeze file", False)
            return
        
        try:
            with open(freeze_path) as f:
                freeze = json.load(f)
            
            ready = freeze.get("release_ready", False)
            checks = freeze.get("checks_passed", 0)
            total = freeze.get("total_checks", 0)
            
            if ready and checks == total:
                self.log_result("Release freeze", True, 
                              f"{checks}/{total} checks, Release ready: {ready}")
            else:
                self.log_result("Release freeze", False,
                              f"{checks}/{total} checks, Release ready: {ready}")
        except json.JSONDecodeError as e:
            self.log_result("Release freeze JSON parse", False, str(e))
    
    def verify_file_hashes(self):
        """Verify file hashes against manifest."""
        print("\n🔐 File Hash Verification")
        manifest_path = self.release_path / "RELEASE_MANIFEST.json"
        
        if not manifest_path.exists():
            self.log_result("Manifest for hash verification", False)
            return
        
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
            
            expected_hashes = manifest.get("file_manifest", {})
            mismatches = 0
            verified = 0
            
            for rel_path, expected_hash in expected_hashes.items():
                full_path = self.release_path / rel_path
                if not full_path.exists():
                    mismatches += 1
                    continue
                
                sha256 = hashlib.sha256()
                with open(full_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        sha256.update(chunk)
                
                if sha256.hexdigest() == expected_hash:
                    verified += 1
                else:
                    mismatches += 1
            
            if mismatches == 0:
                self.log_result("File hash verification", True,
                              f"{verified} files verified, 0 mismatches")
            else:
                self.log_result("File hash verification", False,
                              f"{verified} verified, {mismatches} mismatches")
        except json.JSONDecodeError as e:
            self.log_result("Hash verification JSON parse", False, str(e))
    
    def run_all(self):
        """Run all verification checks."""
        print("=" * 60)
        print("RawrXD CI Verification Pipeline")
        print(f"Release: {self.release_path}")
        print(f"Started: {datetime.now().isoformat()}")
        print("=" * 60)
        
        self.verify_release_structure()
        self.verify_manifest_integrity()
        self.verify_certification()
        self.verify_hardware_attestation()
        self.verify_performance()
        self.verify_val_suite()
        self.verify_release_freeze()
        self.verify_file_hashes()
        
        print("\n" + "=" * 60)
        print("VERIFICATION SUMMARY")
        print("=" * 60)
        for check, result in self.results.items():
            status = "✅" if result["passed"] else "❌"
            print(f"  {status} {check}")
        
        print("=" * 60)
        if self.all_passed:
            print("RESULT: CI VERIFICATION PASSED ✅")
        else:
            print("RESULT: CI VERIFICATION FAILED ❌")
        print("=" * 60)
        
        return self.all_passed

def main():
    parser = argparse.ArgumentParser(description="RawrXD CI Verification Pipeline")
    parser.add_argument("release_path", nargs="?", default="release/RawrXD-v15.0.0",
                       help="Path to the release directory")
    args = parser.parse_args()
    
    verifier = CIVerifier(args.release_path)
    passed = verifier.run_all()
    
    return 0 if passed else 1

if __name__ == "__main__":
    sys.exit(main())
