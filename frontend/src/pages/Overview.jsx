import React, { useState, useEffect } from 'react';
import { Shield, Zap, AlertTriangle, CheckCircle, Activity, Server } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

export default function Overview({ onNavigate }) {
  const [data, setData] = useState(null);
  const [triggering, setTriggering] = useState(false);
  const [msg, setMsg] = useState('');

  const fetchOverview = () => {
    fetch('/api/overview')
      .then((res) => res.json())
      .then((d) => setData(d))
      .catch((err) => console.error("Error fetching overview:", err));
  };

  useEffect(() => {
    fetchOverview();
    const interval = setInterval(fetchOverview, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleTriggerAttack = () => {
    setTriggering(true);
    fetch('/api/simulate/trigger-attack', { method: 'POST' })
      .then((res) => res.json())
      .then((res) => {
        setMsg('🚨 LIVE ATTACK BURST TRIGGERED! IT-OT Crossover & Impossible Travel injected.');
        fetchOverview();
        setTimeout(() => setMsg(''), 5000);
      })
      .catch((err) => console.error(err))
      .finally(() => setTriggering(false));
  };

  if (!data) return <div style={{ color: 'var(--text-muted)' }}>Loading Overview Metrics...</div>;

  const sparklineData = Object.entries(data.alert_volume_timeseries || {}).map(([date, count]) => ({
    date: date.substring(5),
    alerts: count
  }));

  return (
    <div>
      {/* Top Banner with Trigger CTA */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700, color: '#FFF' }}>Honeywell Cyber Security Console</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: 14 }}>Real-Time Behavioral Anomaly Detection across IT + OT Assets</p>
        </div>
        <button
          className="btn btn-primary"
          onClick={handleTriggerAttack}
          disabled={triggering}
          style={{ fontSize: 14, padding: '10px 20px', boxShadow: '0 0 15px rgba(238, 49, 36, 0.4)' }}
        >
          <Zap size={18} />
          {triggering ? 'Injecting Attack...' : '🚨 Trigger Attack Burst'}
        </button>
      </div>

      {msg && (
        <div style={{ backgroundColor: 'rgba(238, 49, 36, 0.2)', border: '1px solid var(--hw-red)', color: '#FFF', padding: 12, borderRadius: 6, marginBottom: 20, fontSize: 13, fontWeight: 600 }}>
          {msg}
        </div>
      )}

      {/* KPI Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 16, marginBottom: 24 }}>
        <div className="card">
          <div style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600 }}>TOTAL LOG EVENTS</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#FFF', marginTop: 4 }}>{data.total_events.toLocaleString()}</div>
          <div style={{ fontSize: 11, color: 'var(--hw-blue)', marginTop: 4 }}>Processed in Engine</div>
        </div>

        <div className="card">
          <div style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600 }}>ACTIVE ALERTS</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--hw-amber)', marginTop: 4 }}>{data.active_alerts}</div>
          <div style={{ fontSize: 11, color: 'var(--hw-amber)', marginTop: 4 }}>Risk ≥ {data.current_threshold}</div>
        </div>

        <div className="card" style={{ borderLeft: '4px solid var(--hw-red)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600 }}>IT-OT CROSSOVERS</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--hw-red)', marginTop: 4 }}>{data.crossover_alerts_count}</div>
          <div style={{ fontSize: 11, color: 'var(--hw-red)', marginTop: 4 }}>High-Severity OT Threat</div>
        </div>

        <div className="card">
          <div style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600 }}>DETECTION PRECISION</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--hw-green)', marginTop: 4 }}>{data.precision}%</div>
          <div style={{ fontSize: 11, color: 'var(--hw-green)', marginTop: 4 }}>Low False Positive Rate</div>
        </div>

        <div className="card">
          <div style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600 }}>ATTACK RECALL</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--hw-blue)', marginTop: 4 }}>{data.recall}%</div>
          <div style={{ fontSize: 11, color: 'var(--hw-blue)', marginTop: 4 }}>Ground Truth Catch Rate</div>
        </div>
      </div>

      {/* Main Overview Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 20 }}>
        {/* Alert Volume Time Series */}
        <div className="card">
          <h3 style={{ fontSize: 16, color: '#FFF', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Activity size={18} style={{ color: 'var(--hw-amber)' }} />
            Alert Volume Timeline
          </h3>
          <div style={{ height: 260 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={sparklineData}>
                <XAxis dataKey="date" stroke="var(--text-muted)" fontSize={11} />
                <YAxis stroke="var(--text-muted)" fontSize={11} />
                <Tooltip contentStyle={{ backgroundColor: '#111520', borderColor: 'var(--border-color)', color: '#FFF' }} />
                <Area type="monotone" dataKey="alerts" stroke="var(--hw-red)" fill="rgba(238, 49, 36, 0.2)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* IT vs OT Breakdown Card */}
        <div className="card">
          <h3 style={{ fontSize: 16, color: '#FFF', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Server size={18} style={{ color: 'var(--hw-blue)' }} />
            Asset Domain Alert Split
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginTop: 20 }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 6 }}>
                <span>IT Endpoints (VPN, AD, Cloud)</span>
                <span style={{ fontWeight: 700, color: 'var(--hw-blue)' }}>{data.it_alerts_count}</span>
              </div>
              <div style={{ height: 8, backgroundColor: '#2E364F', borderRadius: 4, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${(data.it_alerts_count / (data.active_alerts || 1)) * 100}%`, backgroundColor: 'var(--hw-blue)' }}></div>
              </div>
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 6 }}>
                <span>OT / Industrial Controllers (BMS, SCADA)</span>
                <span style={{ fontWeight: 700, color: 'var(--hw-red)' }}>{data.ot_alerts_count}</span>
              </div>
              <div style={{ height: 8, backgroundColor: '#2E364F', borderRadius: 4, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${(data.ot_alerts_count / (data.active_alerts || 1)) * 100}%`, backgroundColor: 'var(--hw-red)' }}></div>
              </div>
            </div>

            <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border-color)' }}>
              <button
                className="btn btn-secondary"
                style={{ width: '100%', justifyContent: 'center' }}
                onClick={() => onNavigate('triage')}
              >
                Go to Alerts Triage Queue →
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
