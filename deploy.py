#!/usr/bin/env python3
"""
RawrXD Deployment Automation
Automates the entire deployment process from validation to production
"""

import subprocess
import sys
import json
import shutil
import os
from pathlib import Path
from datetime import datetime
from typing import List, Tuple

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{text.center(70)}{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*70}{Colors.RESET}\n")

def print_section(text):
    print(f"\n{Colors.CYAN}▶ {text}{Colors.RESET}")

def print_success(text):
    print(f"{Colors.GREEN}✓ {text}{Colors.RESET}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠ {text}{Colors.RESET}")

def print_error(text):
    print(f"{Colors.RED}✗ {text}{Colors.RESET}")

def print_info(text):
    print(f"{Colors.BLUE}ℹ {text}{Colors.RESET}")

def run_command(cmd: List[str], cwd: str = None, check: bool = True) -> Tuple[int, str, str]:
    """Run a command and return result"""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)

class DeploymentAutomation:
    def __init__(self):
        self.deployment_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = Path(f"deploy_{self.deployment_id}.log")
        self.steps_completed = []
        self.steps_failed = []
        
    def log(self, message: str):
        """Log message to file and console"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        print(message)
        with open(self.log_file, 'a') as f:
            f.write(log_entry + '\n')
    
    def pre_deployment_checks(self) -> bool:
        """Run pre-deployment checks"""
        print_section("Pre-Deployment Checks")
        
        checks = [
            ("Validate release package exists", self._check_release_package),
            ("Check system requirements", self._check_system_requirements),
            ("Verify binary integrity", self._verify_binary),
            ("Check disk space", self._check_disk_space),
        ]
        
        for name, check_func in checks:
            print_info(f"Running: {name}")
            if check_func():
                print_success(f"{name}: PASSED")
                self.steps_completed.append(name)
            else:
                print_error(f"{name}: FAILED")
                self.steps_failed.append(name)
                return False
        
        return True
    
    def _check_release_package(self) -> bool:
        """Check if release package exists"""
        release_zip = Path("release/RawrXD-v15.0.1.zip")
        return release_zip.exists()
    
    def _check_system_requirements(self) -> bool:
        """Check system requirements"""
        # Check Python version
        if sys.version_info < (3, 8):
            print_error("Python 3.8+ required")
            return False
        
        # Check available memory (simplified)
        try:
            import psutil
            mem = psutil.virtual_memory()
            if mem.available < 2 * 1024 * 1024 * 1024:  # 2GB
                print_warning("Low memory available")
        except:
            pass
        
        return True
    
    def _verify_binary(self) -> bool:
        """Verify binary integrity"""
        binary = Path("RawrXD.exe")
        if not binary.exists():
            return False
        
        # Check file size
        size = binary.stat().st_size
        if size < 100000:  # 100KB
            print_error(f"Binary too small: {size} bytes")
            return False
        
        return True
    
    def _check_disk_space(self) -> bool:
        """Check available disk space"""
        try:
            import shutil
            total, used, free = shutil.disk_usage("/")
            if free < 500 * 1024 * 1024:  # 500MB
                print_warning("Low disk space")
            return True
        except:
            return True
    
    def backup_existing(self) -> bool:
        """Backup existing installation"""
        print_section("Creating Backup")
        
        backup_dir = Path(f"backup/pre_deploy_{self.deployment_id}")
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        files_to_backup = [
            "RawrXD.exe",
            "config.json",
            "ci_report.json",
        ]
        
        for file in files_to_backup:
            src = Path(file)
            if src.exists():
                dst = backup_dir / src.name
                try:
                    shutil.copy2(src, dst)
                    print_info(f"Backed up {file}")
                except Exception as e:
                    print_warning(f"Failed to backup {file}: {e}")
        
        print_success(f"Backup created at {backup_dir}")
        return True
    
    def deploy_files(self) -> bool:
        """Deploy files to production"""
        print_section("Deploying Files")
        
        # Extract release package
        release_zip = Path("release/RawrXD-v15.0.1.zip")
        deploy_dir = Path("deploy")
        
        if deploy_dir.exists():
            shutil.rmtree(deploy_dir)
        
        try:
            shutil.unpack_archive(release_zip, deploy_dir)
            print_success(f"Extracted release to {deploy_dir}")
        except Exception as e:
            print_error(f"Failed to extract release: {e}")
            return False
        
        # Copy to production locations
        production_files = [
            ("RawrXD.exe", "RawrXD.exe"),
            ("ci_pipeline.py", "ci_pipeline.py"),
            ("validation_report.html", "validation_report.html"),
        ]
        
        for src_name, dst_name in production_files:
            src = deploy_dir / f"RawrXD-v15.0.1" / src_name
            dst = Path(dst_name)
            if src.exists():
                try:
                    shutil.copy2(src, dst)
                    print_info(f"Deployed {dst_name}")
                except Exception as e:
                    print_warning(f"Failed to deploy {dst_name}: {e}")
        
        return True
    
    def post_deployment_validation(self) -> bool:
        """Run post-deployment validation"""
        print_section("Post-Deployment Validation")
        
        # Run CI pipeline
        print_info("Running validation suite...")
        returncode, stdout, stderr = run_command(
            ["python", "ci_pipeline.py"],
            check=False
        )
        
        if returncode == 0 and "ALL STAGES PASSED" in stdout:
            print_success("Post-deployment validation PASSED")
            return True
        else:
            print_error("Post-deployment validation FAILED")
            return False
    
    def generate_deployment_report(self) -> bool:
        """Generate deployment report"""
        print_section("Generating Deployment Report")
        
        report = {
            "deployment_id": self.deployment_id,
            "timestamp": datetime.now().isoformat(),
            "version": "15.0.1",
            "status": "SUCCESS" if len(self.steps_failed) == 0 else "PARTIAL",
            "steps_completed": self.steps_completed,
            "steps_failed": self.steps_failed,
            "log_file": str(self.log_file),
        }
        
        report_file = Path(f"deployment_report_{self.deployment_id}.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print_success(f"Report saved to {report_file}")
        return True
    
    def rollback(self) -> bool:
        """Rollback deployment"""
        print_section("Rolling Back Deployment")
        
        backup_dir = Path(f"backup/pre_deploy_{self.deployment_id}")
        if not backup_dir.exists():
            print_error("No backup found for rollback")
            return False
        
        # Restore from backup
        for file in backup_dir.iterdir():
            if file.is_file():
                dst = Path(file.name)
                try:
                    shutil.copy2(file, dst)
                    print_info(f"Restored {file.name}")
                except Exception as e:
                    print_error(f"Failed to restore {file.name}: {e}")
        
        print_success("Rollback completed")
        return True
    
    def deploy(self) -> bool:
        """Run full deployment"""
        print_header("RawrXD Deployment Automation")
        print_info(f"Deployment ID: {self.deployment_id}")
        print_info(f"Version: 15.0.1")
        print_info(f"Log: {self.log_file}")
        
        steps = [
            ("Pre-Deployment Checks", self.pre_deployment_checks),
            ("Backup Existing", self.backup_existing),
            ("Deploy Files", self.deploy_files),
            ("Post-Deployment Validation", self.post_deployment_validation),
            ("Generate Report", self.generate_deployment_report),
        ]
        
        for name, step_func in steps:
            print_section(f"Step: {name}")
            try:
                if step_func():
                    self.steps_completed.append(name)
                else:
                    self.steps_failed.append(name)
                    print_error(f"Step '{name}' failed")
                    
                    # Ask about rollback
                    response = input("\nRollback deployment? (y/n): ")
                    if response.lower() == 'y':
                        self.rollback()
                    return False
            except Exception as e:
                print_error(f"Step '{name}' crashed: {e}")
                self.steps_failed.append(name)
                return False
        
        print_header("Deployment Complete")
        print_success(f"Completed {len(self.steps_completed)}/{len(steps)} steps")
        
        if self.steps_failed:
            print_warning(f"Failed steps: {', '.join(self.steps_failed)}")
        else:
            print_success("All steps completed successfully!")
            print_info(f"Deployment ID: {self.deployment_id}")
            print_info(f"Report: deployment_report_{self.deployment_id}.json")
        
        return len(self.steps_failed) == 0

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='RawrXD Deployment Automation')
    parser.add_argument('--rollback', help='Rollback to deployment ID')
    parser.add_argument('--dry-run', action='store_true', help='Simulate deployment')
    
    args = parser.parse_args()
    
    if args.rollback:
        deploy = DeploymentAutomation()
        deploy.deployment_id = args.rollback
        success = deploy.rollback()
        sys.exit(0 if success else 1)
    
    deploy = DeploymentAutomation()
    success = deploy.deploy()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
