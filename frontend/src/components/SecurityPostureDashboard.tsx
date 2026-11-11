/**
 * SecurityPostureDashboard.tsx
 * Day 20: Single Pane of Glass — Security Posture Overview
 *
 * Aggregates:
 * - ReplayEngine stability scores (resilience)
 * - AuditLogService compliance metrics (visibility)
 * - ToolRegistry + GovernanceEnforcer enforcement state (defense)
 *
 * Provides the operator with a real-time "Certificate of Resilience"
 * for the agent configuration.
 */

import React, { useEffect, useState, useCallback } from 'react';
import { auditLogService, AuditEvent, ComplianceReportPayload } from '../telemetry/AuditLogService';
import { governanceEnforcer, ToolOverride } from '../telemetry/GovernanceEnforcer';
import { replayEngine, StabilityReport } from '../telemetry/ReplayEngine';
import { statefulRegistry } from '../agent/ToolRegistry';

interface PostureMetrics {
  overallScore: number; // 0-100 composite
  stabilityScore: number;
  complianceRate: number; // percentage
  activeOverrides: number;
  totalEvents: number;
  pendingApprovals: number;
  avgBinaryThreatScore: number; // Day 21: average threat score of last 10 binaries
  lastUpdated: number;
}

const computeCompositeScore = (
  stability: number,
  complianceRate: number,
  overrideCount: number
): number => {
  // Stability is 40%, compliance is 40%, override penalty is 20%
  const stabilityWeight = stability * 0.4;
  const complianceWeight = complianceRate * 0.4;
  const overridePenalty = Math.min(overrideCount * 5, 20); // max 20 point penalty
  return Math.max(0, Math.min(100, Math.round(stabilityWeight + complianceWeight - overridePenalty)));
};

const ScoreRing: React.FC<{ score: number; label: string; color: string }> = ({ score, label, color }) => {
  const circumference = 2 * Math.PI * 36;
  const offset = circumference - (score / 100) * circumference;
  return (
    <div className="posture-score-ring">
      <svg width="80" height="80" viewBox="0 0 80 80">
        <circle cx="40" cy="40" r="36" fill="none" stroke="#e5e7eb" strokeWidth="6" />
        <circle
          cx="40" cy="40" r="36" fill="none"
          stroke={color}
          strokeWidth="6"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 40 40)"
        />
      </svg>
      <div className="posture-score-value">{score}</div>
      <div className="posture-score-label">{label}</div>
    </div>
  );
};

export const SecurityPostureDashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<PostureMetrics>({
    overallScore: 100,
    stabilityScore: 100,
    complianceRate: 100,
    activeOverrides: 0,
    totalEvents: 0,
    pendingApprovals: 0,
    avgBinaryThreatScore: 0,
    lastUpdated: Date.now(),
  });
  const [overrides, setOverrides] = useState<ToolOverride[]>([]);
  const [replayReport, setReplayReport] = useState<StabilityReport | null>(null);
  const [complianceReport, setComplianceReport] = useState<ComplianceReportPayload | null>(null);
  const [recentEvents, setRecentEvents] = useState<AuditEvent[]>([]);

  const refreshMetrics = useCallback(() => {
    const events = auditLogService.getEvents(1000);
    const compliance = auditLogService.exportComplianceReport();
    const overrideList = governanceEnforcer.getOverrides();

    const pendingCount = events.filter(
      (e) => e.kind === 'PENDING_APPROVAL' || e.executionStatus === 'PENDING_APPROVAL'
    ).length;

    // Day 21: Compute average binary threat score from last 10 pe_writer events
    const peWriterEvents = events.filter((e) => e.toolName === 'pe_writer' && typeof e.threatScore === 'number');
    const avgThreat = peWriterEvents.length > 0
      ? Math.round(peWriterEvents.slice(0, 10).reduce((sum, e) => sum + (e.threatScore ?? 0), 0) / Math.min(peWriterEvents.length, 10))
      : 0;

    const complianceRate = compliance.analyzedWriteOperations > 0
      ? Math.round((compliance.compliantWriteOperations / compliance.analyzedWriteOperations) * 100)
      : 100;

    const stability = replayReport?.overallScore ?? 100;
    const overall = computeCompositeScore(stability, complianceRate, overrideList.length);

    setMetrics({
      overallScore: overall,
      stabilityScore: stability,
      complianceRate,
      activeOverrides: overrideList.length,
      totalEvents: events.length,
      pendingApprovals: pendingCount,
      avgBinaryThreatScore: avgThreat,
      lastUpdated: Date.now(),
    });
    setOverrides(overrideList);
    setComplianceReport(compliance);
    setRecentEvents(events.slice(0, 20));
  }, [replayReport]);

  useEffect(() => {
    const unsubAudit = auditLogService.onChange(() => refreshMetrics());
    const unsubGov = governanceEnforcer.onEnforcement(() => refreshMetrics());
    refreshMetrics();
    return () => {
      unsubAudit();
      unsubGov();
    };
  }, [refreshMetrics]);

  const runReplaySuite = async () => {
    const report = await replayEngine.runAllScenarios();
    setReplayReport(report);
    refreshMetrics();
  };

  const exportCertificate = () => {
    const payload = {
      schemaVersion: 'day20.security-posture.v1',
      generatedAtEpochMs: Date.now(),
      certificateTitle: 'Sovereign IDE — Certificate of Resilience',
      metrics,
      replayReport: replayReport
        ? {
            overallScore: replayReport.overallScore,
            scenariosRun: replayReport.scenariosRun,
            scenariosPassed: replayReport.scenariosPassed,
            deadlockCount: replayReport.deadlockCount,
          }
        : null,
      complianceReport: complianceReport
        ? {
            totalAuditEvents: complianceReport.totalAuditEvents,
            analyzedWriteOperations: complianceReport.analyzedWriteOperations,
            compliantWriteOperations: complianceReport.compliantWriteOperations,
            suspiciousWriteOperations: complianceReport.suspiciousWriteOperations,
          }
        : null,
      activeOverrides: overrides.map((o) => ({
        toolName: o.toolName,
        enforcedRiskLevel: o.enforcedRiskLevel,
        reason: o.reason,
        enforcedAt: o.enforcedAt,
      })),
      toolRegistryStatus: statefulRegistry.listTools().map((t) => ({
        name: t.name,
        baseRisk: t.riskLevel,
        effectiveRisk: statefulRegistry.getEffectiveRiskLevel(t.name),
      })),
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-posture-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const scoreColor = (score: number): string => {
    if (score >= 80) return '#22c55e';
    if (score >= 50) return '#f59e0b';
    return '#ef4444';
  };

  return (
    <div className="security-posture-dashboard">
      <div className="posture-header">
        <h3>🛡️ Security Posture Dashboard</h3>
        <div className="posture-actions">
          <button className="posture-btn" onClick={runReplaySuite}>
            {replayReport ? 'Re-run Replay Suite' : 'Run Replay Suite'}
          </button>
          <button className="posture-btn posture-btn-export" onClick={exportCertificate}>
            Export Certificate
          </button>
        </div>
      </div>

      <div className="posture-score-row">
        <ScoreRing score={metrics.overallScore} label="Overall" color={scoreColor(metrics.overallScore)} />
        <ScoreRing score={metrics.stabilityScore} label="Stability" color={scoreColor(metrics.stabilityScore)} />
        <ScoreRing score={metrics.complianceRate} label="Compliance" color={scoreColor(metrics.complianceRate)} />
      </div>

      <div className="posture-stats-grid">
        <div className="posture-stat-card">
          <span className="posture-stat-value">{metrics.activeOverrides}</span>
          <span className="posture-stat-label">Active Overrides</span>
        </div>
        <div className="posture-stat-card">
          <span className="posture-stat-value">{metrics.pendingApprovals}</span>
          <span className="posture-stat-label">Pending Approvals</span>
        </div>
        <div className="posture-stat-card">
          <span className="posture-stat-value">{metrics.totalEvents}</span>
          <span className="posture-stat-label">Audit Events</span>
        </div>
        <div className="posture-stat-card">
          <span className="posture-stat-value">{replayReport?.scenariosRun ?? 0}</span>
          <span className="posture-stat-label">Replay Scenarios</span>
        </div>
      </div>

      {metrics.avgBinaryThreatScore > 0 && (
        <div className="posture-binary-risk-section">
          <h4>🧬 Binary Risk Gauge</h4>
          <div className="posture-binary-risk-bar">
            <div
              className="posture-binary-risk-fill"
              style={{
                width: `${metrics.avgBinaryThreatScore}%`,
                background: metrics.avgBinaryThreatScore >= 50 ? '#ef4444' : metrics.avgBinaryThreatScore >= 20 ? '#f59e0b' : '#22c55e',
              }}
            />
          </div>
          <div className="posture-binary-risk-label">
            Avg Threat Score (last 10 binaries): {metrics.avgBinaryThreatScore}/100
          </div>
        </div>
      )}

      {overrides.length > 0 && (
        <div className="posture-overrides-section">
          <h4>🔒 Active Governance Overrides</h4>
          <div className="posture-overrides-list">
            {overrides.map((o) => (
              <div key={o.toolName} className="posture-override-chip">
                <span className="posture-override-tool">{o.toolName}</span>
                <span className={`posture-override-risk risk-${o.enforcedRiskLevel.toLowerCase()}`}>
                  {o.enforcedRiskLevel}
                </span>
                <span className="posture-override-reason">{o.reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {replayReport && (
        <div className="posture-replay-section">
          <h4>🧪 Replay Engine Results</h4>
          <div className="posture-replay-summary">
            <span>Overall: {replayReport.overallScore}/100</span>
            <span>Passed: {replayReport.scenariosPassed}/{replayReport.scenariosRun}</span>
            <span>Deadlocks: {replayReport.deadlockCount}</span>
          </div>
          <div className="posture-replay-list">
            {replayReport.results.map((r) => (
              <div key={r.scenarioId} className={`posture-replay-item ${r.deadlocked ? 'deadlocked' : r.passed ? 'passed' : 'failed'}`}>
                <span className="posture-replay-name">{r.scenarioName}</span>
                <span className="posture-replay-score">{r.stabilityScore}/100</span>
                <span className="posture-replay-status">
                  {r.deadlocked ? '🔒 Deadlock' : r.passed ? '✅ Pass' : '❌ Fail'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {recentEvents.length > 0 && (
        <div className="posture-events-section">
          <h4>📋 Recent Audit Events</h4>
          <div className="posture-events-list">
            {recentEvents.slice(0, 10).map((e) => (
              <div key={e.id} className="posture-event-row">
                <span className="posture-event-kind">{e.kind}</span>
                <span className="posture-event-tool">{e.toolName ?? '-'}</span>
                <span className={`posture-event-risk risk-${(e.riskLevel ?? 'low').toLowerCase()}`}>
                  {e.riskLevel ?? 'LOW'}
                </span>
                <span className="posture-event-status">{e.executionStatus ?? '-'}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="posture-footer">
        Last updated: {new Date(metrics.lastUpdated).toLocaleTimeString()}
      </div>
    </div>
  );
};
