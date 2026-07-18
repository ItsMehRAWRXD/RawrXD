#!/usr/bin/env python3
"""
RawrXD Benchmark Suite - Compliance Checker
GDPR, SOC2, ISO27001 compliance validation

Copyright (c) 2026 RawrXD Team
"""

import json
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import click


@dataclass
class ComplianceRequirement:
    """Compliance requirement"""
    id: str
    framework: str  # GDPR, SOC2, ISO27001
    category: str
    description: str
    check_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW


@dataclass
class ComplianceFinding:
    """Compliance finding"""
    requirement: ComplianceRequirement
    status: str  # PASS, FAIL, WARNING, NOT_APPLICABLE
    evidence: str
    remediation: Optional[str]
    file_path: Optional[str]
    line_number: Optional[int]


@dataclass
class ComplianceReport:
    """Compliance report"""
    framework: str
    timestamp: str
    findings: List[ComplianceFinding]
    summary: Dict[str, int]
    passed: bool
    score: float  # 0-100


class GDPRChecker:
    """GDPR compliance checker"""
    
    REQUIREMENTS = [
        ComplianceRequirement(
            id="GDPR-1",
            framework="GDPR",
            category="Data Protection",
            description="Personal data must be processed lawfully, fairly, and transparently",
            check_type="data_processing",
            severity="CRITICAL"
        ),
        ComplianceRequirement(
            id="GDPR-2",
            framework="GDPR",
            category="Data Minimization",
            description="Only collect data necessary for specified purposes",
            check_type="data_collection",
            severity="HIGH"
        ),
        ComplianceRequirement(
            id="GDPR-3",
            framework="GDPR",
            category="Storage Limitation",
            description="Personal data must not be kept longer than necessary",
            check_type="data_retention",
            severity="HIGH"
        ),
        ComplianceRequirement(
            id="GDPR-4",
            framework="GDPR",
            category="Security",
            description="Appropriate security measures must protect personal data",
            check_type="security",
            severity="CRITICAL"
        ),
        ComplianceRequirement(
            id="GDPR-5",
            framework="GDPR",
            category="Audit Logging",
            description="Processing activities must be logged for accountability",
            check_type="logging",
            severity="HIGH"
        ),
    ]
    
    def check(self, target_path: Path) -> List[ComplianceFinding]:
        """Run GDPR compliance checks"""
        findings = []
        
        for req in self.REQUIREMENTS:
            finding = self._check_requirement(req, target_path)
            findings.append(finding)
        
        return findings
    
    def _check_requirement(
        self,
        req: ComplianceRequirement,
        target_path: Path
    ) -> ComplianceFinding:
        """Check individual requirement"""
        
        if req.check_type == "data_processing":
            # Check for privacy policy
            privacy_policy = target_path / "docs" / "privacy_policy.md"
            if privacy_policy.exists():
                return ComplianceFinding(
                    requirement=req,
                    status="PASS",
                    evidence="Privacy policy document found",
                    remediation=None,
                    file_path=str(privacy_policy),
                    line_number=None
                )
            else:
                return ComplianceFinding(
                    requirement=req,
                    status="FAIL",
                    evidence="No privacy policy document found",
                    remediation="Create privacy_policy.md in docs/ directory",
                    file_path=None,
                    line_number=None
                )
        
        elif req.check_type == "data_collection":
            # Check for data collection documentation
            data_doc = target_path / "docs" / "data_collection.md"
            if data_doc.exists():
                return ComplianceFinding(
                    requirement=req,
                    status="PASS",
                    evidence="Data collection documentation found",
                    remediation=None,
                    file_path=str(data_doc),
                    line_number=None
                )
            else:
                return ComplianceFinding(
                    requirement=req,
                    status="WARNING",
                    evidence="Data collection documentation not found",
                    remediation="Document what data is collected and why",
                    file_path=None,
                    line_number=None
                )
        
        elif req.check_type == "data_retention":
            # Check for retention policy
            retention_policy = target_path / "docs" / "retention_policy.md"
            if retention_policy.exists():
                return ComplianceFinding(
                    requirement=req,
                    status="PASS",
                    evidence="Data retention policy found",
                    remediation=None,
                    file_path=str(retention_policy),
                    line_number=None
                )
            else:
                return ComplianceFinding(
                    requirement=req,
                    status="FAIL",
                    evidence="No data retention policy found",
                    remediation="Create retention_policy.md with data retention schedules",
                    file_path=None,
                    line_number=None
                )
        
        elif req.check_type == "security":
            # Check for security documentation
            security_doc = target_path / "docs" / "security.md"
            if security_doc.exists():
                return ComplianceFinding(
                    requirement=req,
                    status="PASS",
                    evidence="Security documentation found",
                    remediation=None,
                    file_path=str(security_doc),
                    line_number=None
                )
            else:
                return ComplianceFinding(
                    requirement=req,
                    status="FAIL",
                    evidence="No security documentation found",
                    remediation="Create security.md documenting security measures",
                    file_path=None,
                    line_number=None
                )
        
        elif req.check_type == "logging":
            # Check for audit logging
            audit_config = target_path / "config" / "audit.conf"
            if audit_config.exists():
                return ComplianceFinding(
                    requirement=req,
                    status="PASS",
                    evidence="Audit logging configuration found",
                    remediation=None,
                    file_path=str(audit_config),
                    line_number=None
                )
            else:
                return ComplianceFinding(
                    requirement=req,
                    status="FAIL",
                    evidence="No audit logging configuration found",
                    remediation="Create audit.conf with logging configuration",
                    file_path=None,
                    line_number=None
                )
        
        return ComplianceFinding(
            requirement=req,
            status="NOT_APPLICABLE",
            evidence="Check type not implemented",
            remediation=None,
            file_path=None,
            line_number=None
        )


class SOC2Checker:
    """SOC2 compliance checker"""
    
    REQUIREMENTS = [
        ComplianceRequirement(
            id="SOC2-CC6.1",
            framework="SOC2",
            category="Logical Access",
            description="Logical access security measures are implemented",
            check_type="access_control",
            severity="CRITICAL"
        ),
        ComplianceRequirement(
            id="SOC2-CC6.2",
            framework="SOC2",
            category="Access Removal",
            description="Access is removed when no longer needed",
            check_type="access_review",
            severity="HIGH"
        ),
        ComplianceRequirement(
            id="SOC2-CC7.1",
            framework="SOC2",
            category="Monitoring",
            description="Activities are monitored to detect security events",
            check_type="monitoring",
            severity="CRITICAL"
        ),
        ComplianceRequirement(
            id="SOC2-CC7.2",
            framework="SOC2",
            category="Incident Response",
            description="Security incidents are detected and responded to",
            check_type="incident_response",
            severity="CRITICAL"
        ),
        ComplianceRequirement(
            id="SOC2-CC8.1",
            framework="SOC2",
            category="Change Management",
            description="Changes are authorized, tested, and approved",
            check_type="change_management",
            severity="HIGH"
        ),
    ]
    
    def check(self, target_path: Path) -> List[ComplianceFinding]:
        """Run SOC2 compliance checks"""
        findings = []
        
        for req in self.REQUIREMENTS:
            finding = self._check_requirement(req, target_path)
            findings.append(finding)
        
        return findings
    
    def _check_requirement(
        self,
        req: ComplianceRequirement,
        target_path: Path
    ) -> ComplianceFinding:
        """Check individual requirement"""
        
        if req.check_type == "access_control":
            # Check for RBAC implementation
            rbac_file = target_path / "include" / "security_manager.hpp"
            if rbac_file.exists():
                return ComplianceFinding(
                    requirement=req,
                    status="PASS",
                    evidence="RBAC implementation found",
                    remediation=None,
                    file_path=str(rbac_file),
                    line_number=None
                )
            else:
                return ComplianceFinding(
                    requirement=req,
                    status="FAIL",
                    evidence="No RBAC implementation found",
                    remediation="Implement role-based access control",
                    file_path=None,
                    line_number=None
                )
        
        elif req.check_type == "monitoring":
            # Check for monitoring
            monitor_script = target_path / "scripts" / "monitor.sh"
            if monitor_script.exists():
                return ComplianceFinding(
                    requirement=req,
                    status="PASS",
                    evidence="Monitoring script found",
                    remediation=None,
                    file_path=str(monitor_script),
                    line_number=None
                )
            else:
                return ComplianceFinding(
                    requirement=req,
                    status="FAIL",
                    evidence="No monitoring implementation found",
                    remediation="Implement system monitoring",
                    file_path=None,
                    line_number=None
                )
        
        elif req.check_type == "incident_response":
            # Check for incident response plan
            ir_plan = target_path / "docs" / "incident_response.md"
            if ir_plan.exists():
                return ComplianceFinding(
                    requirement=req,
                    status="PASS",
                    evidence="Incident response plan found",
                    remediation=None,
                    file_path=str(ir_plan),
                    line_number=None
                )
            else:
                return ComplianceFinding(
                    requirement=req,
                    status="FAIL",
                    evidence="No incident response plan found",
                    remediation="Create incident_response.md",
                    file_path=None,
                    line_number=None
                )
        
        return ComplianceFinding(
            requirement=req,
            status="NOT_APPLICABLE",
            evidence="Check type not implemented",
            remediation=None,
            file_path=None,
            line_number=None
        )


class ISO27001Checker:
    """ISO27001 compliance checker"""
    
    REQUIREMENTS = [
        ComplianceRequirement(
            id="ISO-A.9.1.1",
            framework="ISO27001",
            category="Access Control",
            description="Access control policy is established",
            check_type="access_policy",
            severity="CRITICAL"
        ),
        ComplianceRequirement(
            id="ISO-A.9.4.1",
            framework="ISO27001",
            category="Passwords",
            description="Password management system is implemented",
            check_type="password_policy",
            severity="HIGH"
        ),
        ComplianceRequirement(
            id="ISO-A.12.3",
            framework="ISO27001",
            category="Backup",
            description="Backup copies of information are made",
            check_type="backup",
            severity="HIGH"
        ),
        ComplianceRequirement(
            id="ISO-A.12.4",
            framework="ISO27001",
            category="Logging",
            description="Event logs record user activities",
            check_type="logging",
            severity="CRITICAL"
        ),
        ComplianceRequirement(
            id="ISO-A.16.1",
            framework="ISO27001",
            category="Incident Management",
            description="Incident management procedures are established",
            check_type="incident_management",
            severity="CRITICAL"
        ),
    ]
    
    def check(self, target_path: Path) -> List[ComplianceFinding]:
        """Run ISO27001 compliance checks"""
        findings = []
        
        for req in self.REQUIREMENTS:
            finding = self._check_requirement(req, target_path)
            findings.append(finding)
        
        return findings
    
    def _check_requirement(
        self,
        req: ComplianceRequirement,
        target_path: Path
    ) -> ComplianceFinding:
        """Check individual requirement"""
        
        if req.check_type == "backup":
            # Check for backup script
            backup_script = target_path / "scripts" / "backup.sh"
            if backup_script.exists():
                return ComplianceFinding(
                    requirement=req,
                    status="PASS",
                    evidence="Backup script found",
                    remediation=None,
                    file_path=str(backup_script),
                    line_number=None
                )
            else:
                return ComplianceFinding(
                    requirement=req,
                    status="FAIL",
                    evidence="No backup implementation found",
                    remediation="Create backup.sh script",
                    file_path=None,
                    line_number=None
                )
        
        elif req.check_type == "logging":
            # Check for audit logger
            audit_logger = target_path / "include" / "audit_logger.hpp"
            if audit_logger.exists():
                return ComplianceFinding(
                    requirement=req,
                    status="PASS",
                    evidence="Audit logging implementation found",
                    remediation=None,
                    file_path=str(audit_logger),
                    line_number=None
                )
            else:
                return ComplianceFinding(
                    requirement=req,
                    status="FAIL",
                    evidence="No audit logging implementation found",
                    remediation="Implement audit logging",
                    file_path=None,
                    line_number=None
                )
        
        return ComplianceFinding(
            requirement=req,
            status="NOT_APPLICABLE",
            evidence="Check type not implemented",
            remediation=None,
            file_path=None,
            line_number=None
        )


class ComplianceChecker:
    """Main compliance checker"""
    
    def __init__(self, target_path: Path):
        self.target_path = target_path
        self.gdpr_checker = GDPRChecker()
        self.soc2_checker = SOC2Checker()
        self.iso_checker = ISO27001Checker()
    
    def check_all(self) -> Dict[str, ComplianceReport]:
        """Run all compliance checks"""
        reports = {}
        
        # GDPR
        click.echo("Checking GDPR compliance...")
        gdpr_findings = self.gdpr_checker.check(self.target_path)
        reports["GDPR"] = self._create_report("GDPR", gdpr_findings)
        
        # SOC2
        click.echo("Checking SOC2 compliance...")
        soc2_findings = self.soc2_checker.check(self.target_path)
        reports["SOC2"] = self._create_report("SOC2", soc2_findings)
        
        # ISO27001
        click.echo("Checking ISO27001 compliance...")
        iso_findings = self.iso_checker.check(self.target_path)
        reports["ISO27001"] = self._create_report("ISO27001", iso_findings)
        
        return reports
    
    def _create_report(
        self,
        framework: str,
        findings: List[ComplianceFinding]
    ) -> ComplianceReport:
        """Create compliance report"""
        
        summary = {"PASS": 0, "FAIL": 0, "WARNING": 0, "NOT_APPLICABLE": 0}
        for finding in findings:
            summary[finding.status] = summary.get(finding.status, 0) + 1
        
        # Calculate score
        total = summary["PASS"] + summary["FAIL"] + summary["WARNING"]
        if total > 0:
            score = (summary["PASS"] / total) * 100
        else:
            score = 100.0
        
        passed = summary["FAIL"] == 0
        
        return ComplianceReport(
            framework=framework,
            timestamp=datetime.now().isoformat(),
            findings=findings,
            summary=summary,
            passed=passed,
            score=round(score, 1)
        )


@click.group()
def cli():
    """RawrXD Compliance Checker"""
    pass


@cli.command()
@click.option('--path', '-p', default='.', help='Path to check')
@click.option('--framework', '-f', multiple=True, type=click.Choice(['GDPR', 'SOC2', 'ISO27001']), help='Framework to check')
@click.option('--output', '-o', help='Output file')
def check(path: str, framework: List[str], output: str):
    """Run compliance check"""
    checker = ComplianceChecker(Path(path))
    
    if not framework:
        framework = ['GDPR', 'SOC2', 'ISO27001']
    
    reports = checker.check_all()
    
    # Filter reports
    filtered_reports = {k: v for k, v in reports.items() if k in framework}
    
    # Print results
    click.echo("\n" + "=" * 70)
    click.echo("COMPLIANCE CHECK RESULTS")
    click.echo("=" * 70)
    
    for fw, report in filtered_reports.items():
        click.echo(f"\n{fw} Compliance:")
        click.echo(f"  Score: {report.score}%")
        click.echo(f"  Status: {'PASS' if report.passed else 'FAIL'}")
        click.echo(f"  Summary: {report.summary}")
        
        if report.findings:
            click.echo("  Findings:")
            for finding in report.findings:
                status_icon = "✓" if finding.status == "PASS" else "✗" if finding.status == "FAIL" else "⚠"
                click.echo(f"    {status_icon} [{finding.status}] {finding.requirement.id}: {finding.requirement.description}")
                if finding.remediation:
                    click.echo(f"      Remediation: {finding.remediation}")
    
    # Save to file if requested
    if output:
        output_data = {
            fw: {
                "framework": report.framework,
                "timestamp": report.timestamp,
                "score": report.score,
                "passed": report.passed,
                "summary": report.summary,
                "findings": [
                    {
                        "requirement": asdict(f.requirement),
                        "status": f.status,
                        "evidence": f.evidence,
                        "remediation": f.remediation,
                        "file_path": f.file_path,
                        "line_number": f.line_number
                    }
                    for f in report.findings
                ]
            }
            for fw, report in filtered_reports.items()
        }
        
        with open(output, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        click.echo(f"\nResults saved to: {output}")
    
    # Exit with appropriate code
    all_passed = all(r.passed for r in filtered_reports.values())
    sys.exit(0 if all_passed else 1)


@cli.command()
@click.option('--path', '-p', default='.', help='Path to check')
def summary(path: str):
    """Print compliance summary"""
    checker = ComplianceChecker(Path(path))
    reports = checker.check_all()
    
    click.echo("\n" + "=" * 70)
    click.echo("COMPLIANCE SUMMARY")
    click.echo("=" * 70)
    
    for fw, report in reports.items():
        status = "✓ PASS" if report.passed else "✗ FAIL"
        click.echo(f"{fw:12s} {status:8s} Score: {report.score:5.1f}%")
    
    overall = sum(r.score for r in reports.values()) / len(reports)
    click.echo("-" * 70)
    click.echo(f"{'Overall':12s} Score: {overall:5.1f}%")


if __name__ == "__main__":
    cli()
