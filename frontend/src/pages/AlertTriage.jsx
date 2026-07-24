import React, { useState, useEffect } from 'react';
import { AlertTriangle, Shield, CheckCircle, XCircle, ArrowUpRight, MessageSquare, X } from 'lucide-react';

export default function AlertTriage() {
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [filterDomain, setFilterDomain] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [noteText, setNoteText] = useState('');

  const fetchAlerts = () => {
    fetch('/api/alerts')
      .then((res) => res.json())
      .then((data) => {
        setAlerts(data);
        if (selectedAlert) {
          const updated = data.find((a) => a.id === selectedAlert.id);
          if (updated) setSelectedAlert(updated);
        }
      })
      .catch((err) => console.error(err));
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  const handleAction = (actionType) => {
    if (!selectedAlert) return;
    fetch(`/api/alerts/${selectedAlert.id}/action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: actionType, note: noteText || null })
    })
      .then((res) => res.json())
      .then((updated) => {
        setSelectedAlert(updated);
        setNoteText('');
        fetchAlerts();
      })
      .catch((err) => console.error(err));
  };

  const handleAddNote = () => {
    if (!noteText.trim() || !selectedAlert) return;
    handleAction('ADD_NOTE');
  };

  const filteredAlerts = alerts.filter((a) => {
    if (filterDomain !== 'ALL' && a.asset_domain !== filterDomain) return false;
    if (filterStatus !== 'ALL' && a.status !== filterStatus) return false;
    return true;
  });

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#FFF' }}>Security Alerts Triage Queue</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>Review, triage, and manage flagged behavioral cyber anomalies</p>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="card" style={{ padding: 16, marginBottom: 20, display: 'flex', gap: 20, alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Status:</span>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            style={{ backgroundColor: '#111520', border: '1px solid var(--border-color)', color: '#FFF', padding: '6px 12px', borderRadius: 6, fontSize: 13 }}
          >
            <option value="ALL">All Statuses</option>
            <option value="NEW">New</option>
            <option value="ACKNOWLEDGED">Acknowledged</option>
            <option value="ESCALATED">Escalated</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Domain:</span>
          <select
            value={filterDomain}
            onChange={(e) => setFilterDomain(e.target.value)}
            style={{ backgroundColor: '#111520', border: '1px solid var(--border-color)', color: '#FFF', padding: '6px 12px', borderRadius: 6, fontSize: 13 }}
          >
            <option value="ALL">All Domains</option>
            <option value="IT">IT Endpoints</option>
            <option value="OT">OT Industrial</option>
          </select>
        </div>
      </div>

      {/* Main Grid: Alert List + Detail Drawer */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedAlert ? '1fr 450px' : '1fr', gap: 20 }}>
        {/* Alerts Table */}
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table>
            <thead>
              <tr>
                <th>Alert ID</th>
                <th>Risk Score</th>
                <th>Entity / User</th>
                <th>Taxonomy Category</th>
                <th>Attack Scenario</th>
                <th>Domain</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((alt) => {
                const isCrossover = alt.predicted_attack_type === 'IT-OT Crossover';
                const isSelected = selectedAlert && selectedAlert.id === alt.id;
                return (
                  <tr
                    key={alt.id}
                    onClick={() => setSelectedAlert(alt)}
                    style={{
                      backgroundColor: isSelected ? 'rgba(238, 49, 36, 0.2)' : isCrossover ? 'rgba(238, 49, 36, 0.08)' : 'transparent',
                      borderLeft: isCrossover ? '4px solid var(--hw-red)' : '4px solid transparent'
                    }}
                  >
                    <td className="mono" style={{ fontWeight: 700, color: 'var(--hw-amber)' }}>{alt.id}</td>
                    <td>
                      <span style={{ fontWeight: 700, fontSize: 14, color: alt.risk_score >= 85 ? 'var(--hw-red)' : 'var(--hw-amber)' }}>
                        {alt.risk_score}/100
                      </span>
                    </td>
                    <td className="mono" style={{ color: '#FFF' }}>{alt.user_id}</td>
                    <td>{alt.predicted_taxonomy}</td>
                    <td style={{ fontWeight: 600 }}>{alt.predicted_attack_type}</td>
                    <td>
                      <span className={`badge ${alt.asset_domain === 'OT' ? 'badge-ot' : 'badge-it'}`}>{alt.asset_domain}</span>
                    </td>
                    <td>
                      <span className={`badge badge-status-${alt.status.toLowerCase().substring(0, 3)}`}>
                        {alt.status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Alert Detail Drawer */}
        {selectedAlert && (
          <div className="card" style={{ borderLeft: selectedAlert.predicted_attack_type === 'IT-OT Crossover' ? '4px solid var(--hw-red)' : '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, borderBottom: '1px solid var(--border-color)', paddingBottom: 12 }}>
              <div>
                <span className="mono" style={{ fontSize: 13, color: 'var(--hw-amber)', fontWeight: 700 }}>{selectedAlert.id}</span>
                <h3 style={{ fontSize: 18, fontWeight: 700, color: '#FFF', marginTop: 2 }}>{selectedAlert.predicted_attack_type}</h3>
              </div>
              <button onClick={() => setSelectedAlert(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <X size={20} />
              </button>
            </div>

            {/* Explainability Attribution Box */}
            <div style={{ backgroundColor: 'rgba(255, 180, 0, 0.1)', border: '1px solid var(--hw-amber)', padding: 12, borderRadius: 6, marginBottom: 16 }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--hw-amber)', marginBottom: 4 }}>🧠 EXPLAINABILITY ATTRIBUTION</div>
              <div style={{ fontSize: 13, color: '#FFF', lineHeight: 1.4 }}>{selectedAlert.explanation}</div>
            </div>

            {/* Event Metadata */}
            <div style={{ fontSize: 13, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 20, backgroundColor: '#111520', padding: 12, borderRadius: 6 }}>
              <div><span style={{ color: 'var(--text-muted)' }}>User:</span> <strong>{selectedAlert.user_id}</strong></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Role:</span> <strong>{selectedAlert.role}</strong></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Asset:</span> <strong>{selectedAlert.target_resource}</strong></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Domain:</span> <strong>{selectedAlert.asset_domain}</strong></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Device:</span> <strong>{selectedAlert.device_id}</strong></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Location:</span> <strong>{selectedAlert.location_name}</strong></div>
            </div>

            {/* Analyst Action Buttons */}
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600, marginBottom: 8 }}>ANALYST ACTIONS</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <button className="btn btn-success" onClick={() => handleAction('ACKNOWLEDGE')}>
                  <CheckCircle size={14} /> Acknowledge
                </button>
                <button className="btn btn-primary" onClick={() => handleAction('ESCALATE')}>
                  <ArrowUpRight size={14} /> Escalate
                </button>
                <button className="btn btn-secondary" onClick={() => handleAction('MARK_FALSE_POSITIVE')} style={{ gridColumn: 'span 2' }}>
                  <XCircle size={14} /> Mark as False Positive
                </button>
              </div>
            </div>

            {/* Notes Section */}
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600, marginBottom: 8 }}>ANALYST NOTES & LOGS</div>
              {selectedAlert.notes && selectedAlert.notes.length > 0 && (
                <div style={{ marginBottom: 12, display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {selectedAlert.notes.map((n, i) => (
                    <div key={i} style={{ fontSize: 12, backgroundColor: '#111520', padding: 8, borderRadius: 4, color: 'var(--text-main)' }}>
                      {n}
                    </div>
                  ))}
                </div>
              )}
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  type="text"
                  placeholder="Add investigation note..."
                  value={noteText}
                  onChange={(e) => setNoteText(e.target.value)}
                  style={{ flex: 1, backgroundColor: '#111520', border: '1px solid var(--border-color)', color: '#FFF', padding: '6px 10px', borderRadius: 4, fontSize: 12 }}
                />
                <button className="btn btn-secondary" onClick={handleAddNote} style={{ padding: '6px 12px' }}>
                  Add Note
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
