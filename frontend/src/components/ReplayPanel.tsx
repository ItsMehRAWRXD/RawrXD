/**
 * ReplayPanel.tsx
 * Day 19 UI: Adversarial Replay Engine control surface.
 *
 * Allows the operator to run shadow-context replays, observe governance
 * reactions, and review Stability Scores for each scenario.
 */

import React, { useState, useCallback } from 'react';
import { replayEngine, ReplayResult, StabilityReport, ReplayScenario } from '../telemetry/ReplayEngine';

const ScenarioCard: React.FC<{
  scenario: ReplayScenario;
  result?: ReplayResult;
  onRun: (id: string) => void;
  running: boolean;
}> = ({ scenario, result, onRun, running }) => {
  const statusColor = result
    ? result.deadlocked
      ? 'var(--color-fault)'
      : result.passed
        ? 'var(--color-success)'
        : 'var(--color-warning)'
    : 'inherit';

  return (
    <div className="replay-scenario-card">
      <div className="replay-scenario-header">
        <strong>{scenario.name}</strong>
        <span className="replay-scenario-id">{scenario.id}</span>
      </div>
      <p className="replay-scenario-desc">{scenario.description}</p>
      <div className="replay-scenario-meta">
        <span>Expected triggers: {scenario.expectedGovernanceTriggers.join(', ') || 'none'}</span>
        <span>Expect completion: {scenario.expectCompletion ? 'Yes' : 'No'}</span>
      </div>
      {result && (
        <div className="replay-result-block" style={{ borderLeftColor: statusColor }}>
          <div className="replay-result-row">
            <span>Stability Score: <b>{result.stabilityScore}/100</b></span>
            <span>Duration: {result.durationMs}ms</span>
          </div>
          <div className="replay-result-row">
            <span>Completed: {result.completed ? '✅' : '❌'}</span>
            <span>Outcome: {result.passed ? '✅ Pass' : '❌ Fail'}</span>
            <span>Deadlocked: {result.deadlocked ? '🔒 YES' : 'No'}</span>
          </div>
          <div className="replay-result-row">
            <span>Governance triggers: {result.governanceTriggers.join(', ') || 'none'}</span>
          </div>
          <div className="replay-result-row">
            <span>Recovery actions: {result.agentRecoveryActions.length}</span>
          </div>
          {result.enforcementEvents.length > 0 && (
            <div className="replay-enforcement-list">
              <strong>Enforcement Events:</strong>
              <ul>
                {result.enforcementEvents.map((e) => (
                  <li key={e.id}>
                    {e.toolName}: {e.previousRiskLevel} → {e.enforcedRiskLevel} ({e.action})
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
      <button
        className="replay-run-btn"
        onClick={() => onRun(scenario.id)}
        disabled={running}
      >
        {running ? 'Running…' : result ? 'Re-run Scenario' : 'Run Scenario'}
      </button>
    </div>
  );
};

export const ReplayPanel: React.FC = () => {
  const [results, setResults] = useState<Record<string, ReplayResult>>({});
  const [report, setReport] = useState<StabilityReport | null>(null);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [runningAll, setRunningAll] = useState(false);

  const scenarios = replayEngine.getScenarios();

  const handleRun = useCallback(async (id: string) => {
    setRunningId(id);
    try {
      const result = await replayEngine.runScenario(id);
      setResults((prev) => ({ ...prev, [id]: result }));
    } catch (err) {
      console.error('Replay scenario failed:', err);
    } finally {
      setRunningId(null);
    }
  }, []);

  const handleRunAll = useCallback(async () => {
    setRunningAll(true);
    try {
      const r = await replayEngine.runAllScenarios();
      setReport(r);
      const mapped: Record<string, ReplayResult> = {};
      for (const res of r.results) {
        mapped[res.scenarioId] = res;
      }
      setResults(mapped);
    } catch (err) {
      console.error('Replay all failed:', err);
    } finally {
      setRunningAll(false);
    }
  }, []);

  const handleClear = useCallback(() => {
    replayEngine.clearResults();
    setResults({});
    setReport(null);
  }, []);

  return (
    <div className="replay-panel">
      <div className="replay-panel-header">
        <h3>🛡️ Adversarial Replay Engine</h3>
        <div className="replay-panel-actions">
          <button className="replay-run-all-btn" onClick={handleRunAll} disabled={runningAll}>
            {runningAll ? 'Running All…' : 'Run All Scenarios'}
          </button>
          <button className="replay-clear-btn" onClick={handleClear}>Clear Results</button>
        </div>
      </div>

      {report && (
        <div className="replay-report-summary">
          <div className="replay-score-ring">
            <span className="replay-score-value">{report.overallScore}</span>
            <span className="replay-score-label">Stability Score</span>
          </div>
          <div className="replay-stats">
            <span>Scenarios: {report.scenariosRun}</span>
            <span>Passed: {report.scenariosPassed}</span>
            <span>Deadlocks: {report.deadlockCount}</span>
          </div>
        </div>
      )}

      <div className="replay-scenario-list">
        {scenarios.map((scenario) => (
          <ScenarioCard
            key={scenario.id}
            scenario={scenario}
            result={results[scenario.id]}
            onRun={handleRun}
            running={runningId === scenario.id || runningAll}
          />
        ))}
      </div>
    </div>
  );
};
