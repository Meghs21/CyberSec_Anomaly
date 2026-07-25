import React, { useState, useEffect } from 'react';
import { Search, User, Shield, AlertTriangle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, ScatterChart, Scatter } from 'recharts';

export default function EntityInvestigate() {
  const [entities, setEntities] = useState([]);
  const [selectedEntityId, setSelectedEntityId] = useState('');
  const [entityData, setEntityData] = useState(null);

  useEffect(() => {
    fetch('/api/entities')
      .then((res) => res.json())
      .then((data) => {
        setEntities(data);
        if (data.length > 0) {
          const defaultEntity = data.find(e => e.user_id === 'USR_012') || data[0];
          setSelectedEntityId(defaultEntity.user_id);
        }
      })
      .catch((err) => console.error(err));
  }, []);

  useEffect(() => {
    if (!selectedEntityId) return;
    fetch(`/api/entities/${selectedEntityId}`)
      .then((res) => res.json())
      .then((data) => setEntityData(data))
      .catch((err) => console.error(err));
  }, [selectedEntityId]);

  if (!entityData) return <div style={{ color: 'var(--text-muted)' }}>Loading Entity Data...</div>;

  // Prepare hour distribution chart data
  const hourCounts = Array(24).fill(0);
  (entityData.hours || []).forEach((h) => hourCounts[h]++);
  const hourChartData = hourCounts.map((count, hr) => ({
    hour: `${String(hr).padStart(2, '0')}:00`,
    events: count
  }));

  const scatterData = (entityData.events || []).map((e) => ({
    timestamp: e.timestamp.substring(11),
    mb: e.mb_transferred,
    is_alert: e.is_alert,
    risk: e.risk_score
  }));

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#FFF' }}>Entity Investigation</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>Deep-dive analysis of entity baselines vs current activity</p>
        </div>

        {/* Entity Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <User size={18} style={{ color: 'var(--hw-blue)' }} />
          <select
            value={selectedEntityId}
            onChange={(e) => setSelectedEntityId(e.target.value)}
            style={{
              backgroundColor: '#111520',
              border: '1px solid var(--border-color)',
              color: '#FFF',
              padding: '8px 16px',
              borderRadius: 6,
              fontSize: 14,
              fontWeight: 600
            }}
          >
            {entities.map((ent) => {
              let storyLabel = '';
              if (ent.user_id === 'USR_012') storyLabel = ' ⭐ [DEMO VICTIM: IT-OT Crossover]';
              else if (ent.user_id === 'USR_004') storyLabel = ' ⭐ [DEMO VICTIM: Dormant Reactivation]';
              else if (ent.user_id === 'USR_001') storyLabel = ' 🟢 [NORMAL BASELINE]';

              return (
                <option key={ent.user_id} value={ent.user_id}>
                  {ent.user_id} ({ent.role}){storyLabel} - {ent.alert_count} Alerts
                </option>
              );
            })}
          </select>
        </div>
      </div>

      {/* Entity Profile Header Card */}
      <div className="card" style={{ marginBottom: 20, display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
        <div>
          <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>ENTITY USER ID</div>
          <div className="mono" style={{ fontSize: 20, fontWeight: 700, color: '#FFF' }}>{entityData.entity_id}</div>
        </div>
        <div>
          <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>ASSIGNED ROLE</div>
          <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--hw-blue)' }}>{entityData.role}</div>
        </div>
        <div>
          <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>DOMAIN</div>
          <div style={{ marginTop: 4 }}>
            <span className={`badge ${entityData.domain === 'OT' ? 'badge-ot' : 'badge-it'}`}>{entityData.domain}</span>
          </div>
        </div>
        <div>
          <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>PROFILING BASELINE STRATEGY</div>
          <div style={{ marginTop: 4 }}>
            <span className="badge" style={{ backgroundColor: entityData.baseline_type === 'cohort' ? 'var(--hw-amber)' : 'var(--hw-blue)', color: '#000' }}>
              {entityData.baseline_type ? entityData.baseline_type.toUpperCase() + ' BASELINE' : 'PERSONAL BASELINE'}
            </span>
          </div>
        </div>
      </div>

      {/* Baseline vs Activity Charts */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
        <div className="card">
          <h3 style={{ fontSize: 15, color: '#FFF', marginBottom: 16 }}>Historical Login Hour Distribution</h3>
          <div style={{ height: 240 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={hourChartData}>
                <XAxis dataKey="hour" stroke="var(--text-muted)" fontSize={10} />
                <YAxis stroke="var(--text-muted)" fontSize={10} />
                <Tooltip contentStyle={{ backgroundColor: '#111520', borderColor: 'var(--border-color)', color: '#FFF' }} />
                <Bar dataKey="events" fill="var(--hw-blue)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <h3 style={{ fontSize: 15, color: '#FFF', marginBottom: 16 }}>Data Transfer Payload (MB) Scatter</h3>
          <div style={{ height: 240 }}>
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart>
                <XAxis dataKey="timestamp" stroke="var(--text-muted)" fontSize={10} />
                <YAxis dataKey="mb" stroke="var(--text-muted)" fontSize={10} unit=" MB" />
                <Tooltip contentStyle={{ backgroundColor: '#111520', borderColor: 'var(--border-color)', color: '#FFF' }} />
                <Scatter data={scatterData} fill="var(--hw-amber)" />
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Historical Alerts Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-color)', fontWeight: 700, color: '#FFF' }}>
          Entity Alert History
        </div>
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Target Resource</th>
              <th>Asset Domain</th>
              <th>MB Transferred</th>
              <th>Risk Score</th>
              <th>Attack Scenario</th>
            </tr>
          </thead>
          <tbody>
            {(entityData.alerts || []).map((alt, i) => (
              <tr key={i}>
                <td className="mono" style={{ fontSize: 12 }}>{alt.timestamp}</td>
                <td style={{ fontWeight: 600 }}>{alt.target_resource}</td>
                <td><span className={`badge ${alt.asset_domain === 'OT' ? 'badge-ot' : 'badge-it'}`}>{alt.asset_domain}</span></td>
                <td className="mono">{alt.mb_transferred} MB</td>
                <td style={{ fontWeight: 700, color: 'var(--hw-red)' }}>{alt.risk_score}/100</td>
                <td style={{ fontWeight: 600, color: 'var(--hw-amber)' }}>{alt.predicted_attack_type}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
