#!/usr/bin/env python3
"""
Sovereign Batch Protocol — Incremental MASM Migration

Processes 500+ ASM files in batches of 5, implementing missing
MASM features on-demand as each batch fails.

Usage:
    python sovereign_batch_protocol.py [--batch-size 5] [--start-batch 0]
"""

import subprocess
import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional

# Configuration
ASM_SOURCE_DIR = Path("d:/rawrxd/src/asm")
TOOLCHAIN_DIR = Path("d:/rawrxd-ci-bootstrap/toolchain/from_scratch/phase1_assembler")
BUILD_DIR = Path("d:/rawrxd-ci-bootstrap/build/sovereign_batch")
STATUS_FILE = BUILD_DIR / "batch_status.json"
LOG_DIR = BUILD_DIR / "logs"

# Required MASM features (in order of complexity)
REQUIRED_FEATURES = [
    "basic_syntax",           # Labels, instructions, data
    "sections",               # .CODE, .DATA
    "proc_endp",              # PROC/ENDP with FRAME
    "unwind_directives",      # .pushreg, .allocstack, .endprolog
    "include",                # INCLUDE directive
    "equ_constants",          # EQU definitions
    "invoke_macro",           # INVOKE macro expansion
    "local_labels",           # @@local labels
    "conditional_asm",        # IF/ELSE/ENDIF
    "macro_definitions",      # MACRO/ENDM
    "full_preprocessor",      # Complete MASM preprocessor
]

class SovereignBatchProtocol:
    def __init__(self, batch_size: int = 5, assembler_path: Optional[Path] = None):
        self.batch_size = batch_size
        self.assembler = assembler_path or (TOOLCHAIN_DIR / "rawrxd_asm.exe")
        self.status = self._load_status()
        self.current_feature_idx = self.status.get("current_feature", 0)
        
        # Ensure directories exist
        BUILD_DIR.mkdir(parents=True, exist_ok=True)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    def _load_status(self) -> Dict:
        """Load or initialize batch status."""
        if STATUS_FILE.exists():
            with open(STATUS_FILE) as f:
                return json.load(f)
        return {
            "batches": [],
            "current_feature": 0,
            "files_processed": 0,
            "files_failed": [],
            "features_implemented": [],
            "start_time": datetime.now().isoformat()
        }
    
    def _save_status(self):
        """Save current status to JSON."""
        self.status["last_updated"] = datetime.now().isoformat()
        with open(STATUS_FILE, "w") as f:
            json.dump(self.status, f, indent=2)
    
    def _get_asm_files(self) -> List[Path]:
        """Get all .asm files in source directory."""
        files = list(ASM_SOURCE_DIR.glob("*.asm"))
        # Sort for deterministic ordering
        files.sort()
        return files
    
    def _create_batches(self, files: List[Path]) -> List[List[Path]]:
        """Split files into batches."""
        batches = []
        for i in range(0, len(files), self.batch_size):
            batch = files[i:i + self.batch_size]
            batches.append(batch)
        return batches
    
    def _run_assembler(self, asm_file: Path) -> Tuple[bool, str, str]:
        """Run assembler on a single file. Returns (success, stdout, stderr)."""
        obj_file = BUILD_DIR / (asm_file.stem + ".obj")
        
        cmd = [
            str(self.assembler),
            str(asm_file),
            "-o", str(obj_file),
            "-v"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(TOOLCHAIN_DIR)
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "TIMEOUT: Assembly took too long"
        except Exception as e:
            return False, "", f"EXCEPTION: {str(e)}"
    
    def _analyze_error(self, stderr: str) -> Optional[str]:
        """Analyze error to determine missing feature."""
        stderr_lower = stderr.lower()
        
        # Feature detection patterns
        if "include" in stderr_lower or "cannot open file" in stderr_lower:
            return "include"
        if "macro" in stderr_lower or "invoke" in stderr_lower:
            return "invoke_macro"
        if "equ" in stderr_lower and "undefined" in stderr_lower:
            return "equ_constants"
        if "ifnb" in stderr_lower or "if" in stderr_lower:
            return "conditional_asm"
        if "local" in stderr_lower:
            return "local_labels"
        if "@@" in stderr_lower:
            return "local_labels"
        if "proc" in stderr_lower and "frame" in stderr_lower:
            return "proc_endp"
        if ".pushreg" in stderr_lower or ".allocstack" in stderr_lower:
            return "unwind_directives"
        if "unknown directive" in stderr_lower:
            return "basic_syntax"
        
        return None
    
    def _log_batch(self, batch_num: int, results: List[Dict]):
        """Log batch results to file."""
        log_file = LOG_DIR / f"batch_{batch_num:04d}.log"
        with open(log_file, "w") as f:
            f.write(f"Batch {batch_num} — {datetime.now().isoformat()}\n")
            f.write("=" * 60 + "\n\n")
            
            for r in results:
                f.write(f"File: {r['file']}\n")
                f.write(f"Status: {'PASS' if r['success'] else 'FAIL'}\n")
                if not r['success']:
                    f.write(f"Error: {r['stderr'][:500]}\n")
                f.write("-" * 40 + "\n")
    
    def _print_progress(self, batch_num: int, total_batches: int, 
                        current_file: str, status: str):
        """Print progress to console."""
        pct = (batch_num / total_batches) * 100
        print(f"\r[{batch_num:4d}/{total_batches:4d}] {pct:5.1f}% | "
              f"{status:10s} | {current_file[:40]:40s}", end="", flush=True)
    
    def run_batch(self, batch_num: int, files: List[Path]) -> bool:
        """Process a single batch. Returns True if all files pass."""
        results = []
        all_pass = True
        
        print(f"\n{'='*60}")
        print(f"BATCH {batch_num}: Processing {len(files)} files")
        print(f"Current Feature Target: {REQUIRED_FEATURES[self.current_feature_idx]}")
        print(f"{'='*60}")
        
        for i, asm_file in enumerate(files):
            self._print_progress(batch_num, len(files), asm_file.name, "TESTING")
            
            success, stdout, stderr = self._run_assembler(asm_file)
            
            results.append({
                "file": str(asm_file),
                "success": success,
                "stdout": stdout,
                "stderr": stderr
            })
            
            if success:
                self._print_progress(batch_num, len(files), asm_file.name, "PASS")
                self.status["files_processed"] += 1
            else:
                self._print_progress(batch_num, len(files), asm_file.name, "FAIL")
                all_pass = False
                
                # Analyze what feature is missing
                missing = self._analyze_error(stderr)
                if missing:
                    print(f"\n  -> Missing feature: {missing}")
                    print(f"  -> Error: {stderr[:200]}")
                
                self.status["files_failed"].append({
                    "file": str(asm_file),
                    "error": stderr[:500],
                    "missing_feature": missing
                })
        
        print()  # Newline after progress
        self._log_batch(batch_num, results)
        
        # Update status
        batch_record = {
            "batch_num": batch_num,
            "files": [str(f) for f in files],
            "all_pass": all_pass,
            "timestamp": datetime.now().isoformat()
        }
        self.status["batches"].append(batch_record)
        self._save_status()
        
        return all_pass
    
    def run_protocol(self, start_batch: int = 0):
        """Run the full Sovereign Batch Protocol."""
        files = self._get_asm_files()
        batches = self._create_batches(files)
        
        print(f"\n{'='*60}")
        print("SOVEREIGN BATCH PROTOCOL")
        print(f"{'='*60}")
        print(f"Total files: {len(files)}")
        print(f"Batch size: {self.batch_size}")
        print(f"Total batches: {len(batches)}")
        print(f"Starting at batch: {start_batch}")
        print(f"{'='*60}\n")
        
        # Process batches
        for batch_num in range(start_batch, len(batches)):
            batch_files = batches[batch_num]
            success = self.run_batch(batch_num, batch_files)
            
            if not success:
                print(f"\n{'!'*60}")
                print("HALT: Batch failed. Assembler needs enhancement.")
                print(f"{'!'*60}")
                print(f"\nNext steps:")
                print(f"1. Check {LOG_DIR}/batch_{batch_num:04d}.log")
                print(f"2. Implement missing feature in phase1_assembler")
                print(f"3. Rebuild assembler: cd {TOOLCHAIN_DIR} && make")
                print(f"4. Resume: python sovereign_batch_protocol.py --start-batch {batch_num}")
                return batch_num
        
        print(f"\n{'='*60}")
        print("SUCCESS: All batches completed!")
        print(f"{'='*60}")
        print(f"Files processed: {self.status['files_processed']}")
        print(f"Features implemented: {len(self.status['features_implemented'])}")
        return -1


def main():
    parser = argparse.ArgumentParser(description="Sovereign Batch Protocol")
    parser.add_argument("--batch-size", type=int, default=5,
                       help="Files per batch (default: 5)")
    parser.add_argument("--start-batch", type=int, default=0,
                       help="Resume from batch number (default: 0)")
    parser.add_argument("--assembler", type=str,
                       help="Path to custom assembler executable")
    
    args = parser.parse_args()
    
    assembler_path = Path(args.assembler) if args.assembler else None
    
    protocol = SovereignBatchProtocol(
        batch_size=args.batch_size,
        assembler_path=assembler_path
    )
    
    failed_batch = protocol.run_protocol(start_batch=args.start_batch)
    
    if failed_batch >= 0:
        sys.exit(1)
    else:
        print("\n✓ Sovereign toolchain now fully supports your 500+ ASM files!")
        sys.exit(0)


if __name__ == "__main__":
    main()
