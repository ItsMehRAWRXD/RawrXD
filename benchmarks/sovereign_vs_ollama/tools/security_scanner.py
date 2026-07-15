#!/usr/bin/env python3
"""
RawrXD Benchmark Suite - Security Scanner
Vulnerability scanning and security assessment

Copyright (c) 2026 RawrXD Team
"""

import json
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import click
import yaml


@dataclass
class Vulnerability:
    """Security vulnerability"""
    id: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    file_path: str
    line_number: int
    recommendation: str
    references: List[str]
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None


@dataclass
class ScanResult:
    """Scan result"""
    scan_type: str
    timestamp: str
    duration_seconds: float
    vulnerabilities: List[Vulnerability]
    passed: bool
    summary: Dict[str, int]


class SecurityScanner:
    """Security scanner for benchmark suite"""
    
    def __init__(self, target_path: Path):
        self.target_path = target_path
        self.vulnerabilities: List[Vulnerability] = []
    
    def scan_dependencies(self) -> List[Vulnerability]:
        """Scan for vulnerable dependencies"""
        vulns = []
        
        # Check Python dependencies
        requirements_file = self.target_path / "requirements.txt"
        if requirements_file.exists():
            try:
                result = subprocess.run(
                    ["safety", "check", "-r", str(requirements_file), "--json"],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    for vuln in data.get("vulnerabilities", []):
                        vulns.append(Vulnerability(
                            id=vuln.get("vulnerability_id", "UNKNOWN"),
                            title=f"Vulnerable dependency: {vuln.get('package_name')}",
                            description=vuln.get("advisory", ""),
                            severity=vuln.get("severity", "MEDIUM").upper(),
                            category="DEPENDENCY",
                            file_path="requirements.txt",
                            line_number=0,
                            recommendation=f"Upgrade to {vuln.get('fixed_version', 'latest')}",
                            references=vuln.get("references", [])
                        ))
            except FileNotFoundError:
                pass  # safety not installed
        
        return vulns
    
    def scan_secrets(self) -> List[Vulnerability]:
        """Scan for hardcoded secrets"""
        vulns = []
        
        secret_patterns = [
            (r'api[_-]?key["\']?\s*[:=]\s*["\'][^"\']{10,}["\']', "API Key"),
            (r'password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']', "Password"),
            (r'secret["\']?\s*[:=]\s*["\'][^"\']{10,}["\']', "Secret"),
            (r'token["\']?\s*[:=]\s*["\'][^"\']{10,}["\']', "Token"),
            (r'private[_-]?key["\']?\s*[:=]\s*["\'][^"\']{20,}["\']', "Private Key"),
        ]
        
        import re
        
        for file_path in self.target_path.rglob("*"):
            if file_path.is_file() and file_path.suffix in ['.py', '.cpp', '.hpp', '.h', '.c', '.sh', '.yml', '.yaml', '.json']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')
                        
                        for line_num, line in enumerate(lines, 1):
                            for pattern, secret_type in secret_patterns:
                                if re.search(pattern, line, re.IGNORECASE):
                                    vulns.append(Vulnerability(
                                        id=f"SECRET-{len(vulns)+1}",
                                        title=f"Potential hardcoded {secret_type}",
                                        description=f"Found potential hardcoded {secret_type} in source code",
                                        severity="HIGH",
                                        category="SECRETS",
                                        file_path=str(file_path.relative_to(self.target_path)),
                                        line_number=line_num,
                                        recommendation="Use environment variables or secure secret management",
                                        references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"],
                                        cwe_id="CWE-798"
                                    ))
                except Exception:
                    pass
        
        return vulns
    
    def scan_code_quality(self) -> List[Vulnerability]:
        """Scan for code quality issues"""
        vulns = []
        
        # Check for dangerous functions
        dangerous_functions = {
            'strcpy': ('Buffer overflow risk', 'HIGH', 'CWE-120'),
            'sprintf': ('Buffer overflow risk', 'HIGH', 'CWE-120'),
            'gets': ('Buffer overflow risk', 'CRITICAL', 'CWE-120'),
            'system': ('Command injection risk', 'HIGH', 'CWE-78'),
            'eval': ('Code injection risk', 'CRITICAL', 'CWE-95'),
            'exec': ('Code injection risk', 'CRITICAL', 'CWE-95'),
        }
        
        for file_path in self.target_path.rglob("*"):
            if file_path.is_file() and file_path.suffix in ['.cpp', '.hpp', '.h', '.c', '.py']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')
                        
                        for line_num, line in enumerate(lines, 1):
                            for func, (desc, severity, cwe) in dangerous_functions.items():
                                if func in line:
                                    vulns.append(Vulnerability(
                                        id=f"QUALITY-{len(vulns)+1}",
                                        title=f"Dangerous function: {func}",
                                        description=desc,
                                        severity=severity,
                                        category="CODE_QUALITY",
                                        file_path=str(file_path.relative_to(self.target_path)),
                                        line_number=line_num,
                                        recommendation=f"Replace {func} with safer alternative",
                                        references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
                                        cwe_id=cwe
                                    ))
                except Exception:
                    pass
        
        return vulns
    
    def scan_configuration(self) -> List[Vulnerability]:
        """Scan for insecure configuration"""
        vulns = []
        
        # Check config files
        config_files = [
            self.target_path / "config" / "benchmark.conf",
            self.target_path / ".env",
        ]
        
        for config_file in config_files:
            if config_file.exists():
                try:
                    with open(config_file) as f:
                        content = f.read()
                        
                        # Check for debug mode
                        if 'debug=true' in content.lower() or 'debug=1' in content.lower():
                            vulns.append(Vulnerability(
                                id="CONFIG-001",
                                title="Debug mode enabled",
                                description="Debug mode is enabled in production configuration",
                                severity="MEDIUM",
                                category="CONFIGURATION",
                                file_path=str(config_file.relative_to(self.target_path)),
                                line_number=0,
                                recommendation="Disable debug mode in production",
                                references=["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"]
                            ))
                        
                        # Check for weak crypto
                        if 'md5' in content.lower() or 'sha1' in content.lower():
                            vulns.append(Vulnerability(
                                id="CONFIG-002",
                                title="Weak cryptographic algorithm",
                                description="Configuration uses weak cryptographic algorithm",
                                severity="HIGH",
                                category="CONFIGURATION",
                                file_path=str(config_file.relative_to(self.target_path)),
                                line_number=0,
                                recommendation="Use SHA-256 or stronger hashing algorithm",
                                references=["https://cwe.mitre.org/data/definitions/326.html"],
                                cwe_id="CWE-326"
                            ))
                except Exception:
                    pass
        
        return vulns
    
    def scan_permissions(self) -> List[Vulnerability]:
        """Scan for permission issues"""
        vulns = []
        
        # Check for overly permissive files
        for file_path in self.target_path.rglob("*"):
            if file_path.is_file():
                try:
                    import stat
                    mode = file_path.stat().st_mode
                    
                    # Check for world-writable files
                    if mode & stat.S_IWOTH:
                        vulns.append(Vulnerability(
                            id=f"PERM-{len(vulns)+1}",
                            title="World-writable file",
                            description=f"File is writable by everyone",
                            severity="MEDIUM",
                            category="PERMISSIONS",
                            file_path=str(file_path.relative_to(self.target_path)),
                            line_number=0,
                            recommendation="Remove world-write permission",
                            references=["https://cwe.mitre.org/data/definitions/732.html"],
                            cwe_id="CWE-732"
                        ))
                    
                    # Check for SUID files
                    if mode & stat.S_ISUID:
                        vulns.append(Vulnerability(
                            id=f"PERM-{len(vulns)+1}",
                            title="SUID file",
                            description=f"File has SUID bit set",
                            severity="HIGH",
                            category="PERMISSIONS",
                            file_path=str(file_path.relative_to(self.target_path)),
                            line_number=0,
                            recommendation="Review SUID permissions",
                            references=["https://cwe.mitre.org/data/definitions/250.html"],
                            cwe_id="CWE-250"
                        ))
                except Exception:
                    pass
        
        return vulns
    
    def run_full_scan(self) -> ScanResult:
        """Run complete security scan"""
        import time
        
        start_time = time.time()
        
        self.vulnerabilities = []
        
        click.echo("Running security scan...")
        
        click.echo("  [1/5] Scanning dependencies...")
        self.vulnerabilities.extend(self.scan_dependencies())
        
        click.echo("  [2/5] Scanning for secrets...")
        self.vulnerabilities.extend(self.scan_secrets())
        
        click.echo("  [3/5] Scanning code quality...")
        self.vulnerabilities.extend(self.scan_code_quality())
        
        click.echo("  [4/5] Scanning configuration...")
        self.vulnerabilities.extend(self.scan_configuration())
        
        click.echo("  [5/5] Scanning permissions...")
        self.vulnerabilities.extend(self.scan_permissions())
        
        duration = time.time() - start_time
        
        # Calculate summary
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for vuln in self.vulnerabilities:
            summary[vuln.severity] = summary.get(vuln.severity, 0) + 1
        
        passed = summary["CRITICAL"] == 0 and summary["HIGH"] == 0
        
        return ScanResult(
            scan_type="full",
            timestamp=datetime.now().isoformat(),
            duration_seconds=duration,
            vulnerabilities=self.vulnerabilities,
            passed=passed,
            summary=summary
        )


@click.group()
def cli():
    """RawrXD Security Scanner"""
    pass


@cli.command()
@click.option('--path', '-p', default='.', help='Path to scan')
@click.option('--output', '-o', help='Output file for results')
@click.option('--format', '-f', 'fmt', default='text', type=click.Choice(['text', 'json', 'sarif']))
def scan(path: str, output: str, fmt: str):
    """Run security scan"""
    scanner = SecurityScanner(Path(path))
    result = scanner.run_full_scan()
    
    if fmt == 'json':
        output_data = {
            "scan_type": result.scan_type,
            "timestamp": result.timestamp,
            "duration_seconds": result.duration_seconds,
            "passed": result.passed,
            "summary": result.summary,
            "vulnerabilities": [asdict(v) for v in result.vulnerabilities]
        }
        output_text = json.dumps(output_data, indent=2)
    elif fmt == 'sarif':
        # Generate SARIF format
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "RawrXD Security Scanner",
                        "version": "1.0.0"
                    }
                },
                "results": [{
                    "ruleId": v.id,
                    "message": {"text": v.description},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": v.file_path},
                            "region": {"startLine": v.line_number}
                        }
                    }],
                    "level": v.severity.lower()
                } for v in result.vulnerabilities]
            }]
        }
        output_text = json.dumps(sarif, indent=2)
    else:
        # Text format
        lines = []
        lines.append("=" * 70)
        lines.append("SECURITY SCAN RESULTS")
        lines.append("=" * 70)
        lines.append(f"Timestamp: {result.timestamp}")
        lines.append(f"Duration: {result.duration_seconds:.2f}s")
        lines.append(f"Status: {'PASSED' if result.passed else 'FAILED'}")
        lines.append("")
        lines.append("Summary:")
        for severity, count in result.summary.items():
            if count > 0:
                lines.append(f"  {severity}: {count}")
        
        if result.vulnerabilities:
            lines.append("")
            lines.append("Vulnerabilities:")
            lines.append("-" * 70)
            for vuln in result.vulnerabilities:
                lines.append(f"\n[{vuln.severity}] {vuln.id}: {vuln.title}")
                lines.append(f"  File: {vuln.file_path}:{vuln.line_number}")
                lines.append(f"  Description: {vuln.description}")
                lines.append(f"  Recommendation: {vuln.recommendation}")
        
        lines.append("")
        lines.append("=" * 70)
        output_text = "\n".join(lines)
    
    if output:
        with open(output, 'w') as f:
            f.write(output_text)
        click.echo(f"Results saved to: {output}")
    else:
        click.echo(output_text)
    
    sys.exit(0 if result.passed else 1)


@cli.command()
@click.option('--path', '-p', default='.', help='Path to scan')
def quick(path: str):
    """Quick security check"""
    scanner = SecurityScanner(Path(path))
    
    click.echo("Running quick security check...")
    
    # Just scan for critical issues
    vulns = scanner.scan_secrets()
    vulns.extend(scanner.scan_configuration())
    
    critical = [v for v in vulns if v.severity in ['CRITICAL', 'HIGH']]
    
    if critical:
        click.echo(f"\nFound {len(critical)} critical/high severity issues:")
        for vuln in critical:
            click.echo(f"  [{vuln.severity}] {vuln.title} in {vuln.file_path}")
        sys.exit(1)
    else:
        click.echo("\n✓ No critical security issues found")
        sys.exit(0)


if __name__ == "__main__":
    cli()
