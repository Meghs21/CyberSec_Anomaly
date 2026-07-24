import React, { useState, useEffect } from 'react';
import { Settings, Sliders, CheckCircle } from 'lucide-react';

export default function SettingsPage() {
  const [threshold, setThreshold] = useState(60.0);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    fetch('/api/overview')
      .then((res) => res.json())
      .then((data) => {
        if (data.current_threshold) setThreshold(data.current_threshold);
      })
      .catch((err) => console.error(err));
  }, []);

  const handleSaveThreshold = (newVal) => {
    setThreshold(newVal);
    fetch('/api/settings/threshold', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ threshold: newVal })
    })
      .then((res) => res.json())
      .then(() => {
        setSaved(true);
        setTimeout(() => setSaved(false), 3000);
      })
      .catch((err) => console.error(err));
  };

  return (
    <div>
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#FFF' }}>Model Tuning & System Config</h1>
        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>Dynamic threshold adjustment & pipeline configuration</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* Risk Threshold Tuning Card */}
        <div className="card">
          <h3 style={{ fontSize: 16, color: '#FFF', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Sliders size={18} style={{ color: 'var(--hw-amber)' }} />
            Dynamic Risk Threshold Adjustment
          </h3>

          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 20 }}>
            Adjust the risk score cutoff for flagging alerts. Lower values increase sensitivity; higher values reduce false alarms.
          </p>

          <div style={{ marginBottom: 24 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: 14 }}>
              <span>Risk Score Cutoff:</span>
              <strong style={{ fontSize: 18, color: 'var(--hw-amber)' }}>{threshold}/100</strong>
            </div>

            <input
              type="range"
              min="30"
              max="95"
              step="5"
              value={threshold}
              onChange={(e) => handleSaveThreshold(Number(e.target.value))}
              style={{ width: '100%' }}
            />
          </div>

          {saved && (
            <div style={{ color: 'var(--hw-green)', fontSize: 13, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
              <CheckCircle size={16} /> Dynamic threshold updated live in detection pipeline!
            </div>
          )}
        </div>

        {/* System Rationale Card */}
        <div className="card">
          <h3 style={{ fontSize: 16, color: '#FFF', marginBottom: 16 }}>Smart Thresholding Mechanism</h3>
          <div style={{ fontSize: 13, color: 'var(--text-main)', lineHeight: 1.6, display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <strong>Exponential Weighting:</strong> Baselines adjust via EWMA ($\alpha = 0.1$) to absorb routine behavioral changes over time.
            </div>
            <div>
              <strong>Cold-Start Threshold Widening:</strong> Unmatured entities with fewer than 10 historical logs receive an automatic +10 point threshold padding to avoid false positives.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
