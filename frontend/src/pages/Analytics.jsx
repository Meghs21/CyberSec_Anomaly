import React, { useState, useEffect } from 'react';
import { BarChart2, CheckSquare, Award } from 'lucide-react';

export default function Analytics() {
  const [metrics, setMetrics] = useState(null);

  useEffect(() => {
    fetch('/api/metrics')
      .then((res) => res.json())
      .then((data) => setMetrics(data))
      .catch((err) => console.error(err));
  }, []);

  if (!metrics) return <div style={{ color: 'var(--text-muted)' }}>Loading Benchmark Metrics...</div>;

  const cm = metrics.confusion_matrix || { tn: 0, fp: 0, fn: 0, tp: 0 };

  return (
    <div>
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#FFF' }}>Analytics & Benchmark Evaluation</h1>
        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>Quantitative detection performance vs synthetic ground truth</p>
      </div>

      {/* Top Metrics Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20, marginBottom: 24 }}>
        <div className="card" style={{ borderLeft: '4px solid var(--hw-green)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600 }}>PRECISION</div>
          <div style={{ fontSize: 32, fontWeight: 700, color: 'var(--hw-green)', marginTop: 4 }}>{metrics.precision}%</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>Low False Positive Rate</div>
        </div>

        <div className="card" style={{ borderLeft: '4px solid var(--hw-blue)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600 }}>RECALL</div>
          <div style={{ fontSize: 32, fontWeight: 700, color: 'var(--hw-blue)', marginTop: 4 }}>{metrics.recall}%</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>Attack Catch Rate vs Ground Truth</div>
        </div>

        <div className="card" style={{ borderLeft: '4px solid var(--hw-amber)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600 }}>F1-SCORE</div>
          <div style={{ fontSize: 32, fontWeight: 700, color: 'var(--hw-amber)', marginTop: 4 }}>{metrics.f1_score}</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>Harmonic Mean Score</div>
        </div>
      </div>

      {/* Grid: Confusion Matrix + Performance Story */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 24 }}>
        {/* Confusion Matrix */}
        <div className="card">
          <h3 style={{ fontSize: 16, color: '#FFF', marginBottom: 16 }}>Confusion Matrix</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, textAlign: 'center' }}>
            <div style={{ backgroundColor: '#111520', padding: 16, borderRadius: 6, border: '1px solid var(--border-color)' }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>TRUE NEGATIVES (TN)</div>
              <div style={{ fontSize: 24, fontWeight: 700, color: '#FFF', marginTop: 4 }}>{cm.tn}</div>
              <div style={{ fontSize: 11, color: 'var(--hw-green)' }}>Normal traffic passed</div>
            </div>

            <div style={{ backgroundColor: '#111520', padding: 16, borderRadius: 6, border: '1px solid var(--border-color)' }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>FALSE POSITIVES (FP)</div>
              <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--hw-amber)', marginTop: 4 }}>{cm.fp}</div>
              <div style={{ fontSize: 11, color: 'var(--hw-amber)' }}>False alarms</div>
            </div>

            <div style={{ backgroundColor: '#111520', padding: 16, borderRadius: 6, border: '1px solid var(--border-color)' }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>FALSE NEGATIVES (FN)</div>
              <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--hw-red)', marginTop: 4 }}>{cm.fn}</div>
              <div style={{ fontSize: 11, color: 'var(--hw-red)' }}>Missed attack events</div>
            </div>

            <div style={{ backgroundColor: '#111520', padding: 16, borderRadius: 6, border: '1px solid var(--border-color)' }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>TRUE POSITIVES (TP)</div>
              <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--hw-green)', marginTop: 4 }}>{cm.tp}</div>
              <div style={{ fontSize: 11, color: 'var(--hw-green)' }}>Correctly caught attacks</div>
            </div>
          </div>
        </div>

        {/* Evaluation Summary */}
        <div className="card">
          <h3 style={{ fontSize: 16, color: '#FFF', marginBottom: 16 }}>Evaluation Criteria & Defense Rationale</h3>
          <div style={{ fontSize: 13, lineHeight: 1.6, color: 'var(--text-main)', display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <strong>🎯 Signature-Less Detection:</strong> Trained purely on normal entity behavior without attack labels.
            </div>
            <div>
              <strong>⚡ Zero Cold-Start False Alarms:</strong> Role domain priors prevent false alerts for new entity profiles.
            </div>
            <div>
              <strong>🛡️ Honeywell Industrial Value:</strong> Detects lateral movement crossover from IT accounts into OT controllers.
            </div>
          </div>
        </div>
      </div>

      {/* Scenario Performance Breakdown Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-color)', fontWeight: 700, color: '#FFF' }}>
          Detection Performance per Attack Scenario Category
        </div>
        <table>
          <thead>
            <tr>
              <th>Attack Scenario Type</th>
              <th>Total Injected Bursts</th>
              <th>Successfully Caught</th>
              <th>Scenario Recall Rate</th>
            </tr>
          </thead>
          <tbody>
            {(metrics.scenario_breakdown || []).map((sc, i) => (
              <tr key={i}>
                <td style={{ fontWeight: 600, color: '#FFF' }}>{sc.scenario}</td>
                <td className="mono">{sc.total_injected}</td>
                <td className="mono" style={{ color: 'var(--hw-green)', fontWeight: 700 }}>{sc.detected_count}</td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{ fontWeight: 700, color: sc.recall_rate >= 90 ? 'var(--hw-green)' : 'var(--hw-amber)' }}>
                      {sc.recall_rate}%
                    </span>
                    <div style={{ flex: 1, height: 6, backgroundColor: '#2E364F', borderRadius: 3, overflow: 'hidden', maxWidth: 100 }}>
                      <div style={{ height: '100%', width: `${sc.recall_rate}%`, backgroundColor: sc.recall_rate >= 90 ? 'var(--hw-green)' : 'var(--hw-amber)' }}></div>
                    </div>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
