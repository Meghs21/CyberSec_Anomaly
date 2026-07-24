import React, { useState, useEffect } from 'react';
import { Shield, Filter, Search } from 'lucide-react';

export default function LiveFeed({ wsEvents }) {
  const [events, setEvents] = useState([]);
  const [domain, setDomain] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [minRisk, setMinRisk] = useState(0);

  useEffect(() => {
    fetch('/api/events?limit=150')
      .then((res) => res.json())
      .then((d) => setEvents(d))
      .catch((err) => console.error(err));
  }, []);

  // Merge WebSocket real-time incoming events
  const combinedEvents = [...wsEvents, ...events].filter((ev, idx, self) => 
    idx === self.findIndex((e) => e.timestamp === ev.timestamp && e.user_id === ev.user_id)
  );

  const filteredEvents = combinedEvents.filter((e) => {
    if (domain !== 'ALL' && e.asset_domain !== domain) return false;
    if (e.risk_score < minRisk) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        e.user_id.toLowerCase().includes(term) ||
        e.target_resource.toLowerCase().includes(term) ||
        e.role.toLowerCase().includes(term)
      );
    }
    return true;
  });

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#FFF' }}>Real-Time Event Stream</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>Live log stream via WebSocket pipeline</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: '#111520', padding: '6px 12px', borderRadius: 20, border: '1px solid #2E364F' }}>
          <span style={{ height: 8, width: 8, borderRadius: '50%', backgroundColor: 'var(--hw-green)' }}></span>
          <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--hw-green)' }}>LIVE WEBSOCKET STREAMING</span>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="card" style={{ padding: 16, marginBottom: 20, display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Search size={16} style={{ color: 'var(--text-muted)' }} />
          <input
            type="text"
            placeholder="Search User ID, Resource, Role..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              backgroundColor: '#111520',
              border: '1px solid var(--border-color)',
              color: '#FFF',
              padding: '6px 12px',
              borderRadius: 6,
              fontSize: 13,
              width: 240
            }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Asset Domain:</span>
          <select
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            style={{
              backgroundColor: '#111520',
              border: '1px solid var(--border-color)',
              color: '#FFF',
              padding: '6px 12px',
              borderRadius: 6,
              fontSize: 13
            }}
          >
            <option value="ALL">All Domains</option>
            <option value="IT">IT Endpoints</option>
            <option value="OT">OT Industrial</option>
          </select>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Min Risk: {minRisk}</span>
          <input
            type="range"
            min="0"
            max="100"
            step="5"
            value={minRisk}
            onChange={(e) => setMinRisk(Number(e.target.value))}
            style={{ width: 120 }}
          />
        </div>
      </div>

      {/* Real-Time Events Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>User Entity</th>
              <th>Role</th>
              <th>Target Asset</th>
              <th>Domain</th>
              <th>MB Transferred</th>
              <th>Risk Score</th>
              <th>Status Flag</th>
            </tr>
          </thead>
          <tbody>
            {filteredEvents.map((ev, idx) => {
              const isOt = ev.asset_domain === 'OT';
              const isAlert = ev.is_alert;
              return (
                <tr key={idx} style={{ backgroundColor: isAlert ? (ev.predicted_attack_type === 'IT-OT Crossover' ? 'rgba(238,49,36,0.1)' : 'rgba(255,180,0,0.05)') : 'transparent' }}>
                  <td className="mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>{ev.timestamp}</td>
                  <td className="mono" style={{ fontWeight: 600, color: '#FFF' }}>{ev.user_id}</td>
                  <td>{ev.role}</td>
                  <td style={{ fontWeight: 500 }}>{ev.target_resource}</td>
                  <td>
                    <span className={`badge ${isOt ? 'badge-ot' : 'badge-it'}`}>{ev.asset_domain}</span>
                  </td>
                  <td className="mono">{ev.mb_transferred} MB</td>
                  <td>
                    <span style={{ fontWeight: 700, color: ev.risk_score >= 85 ? 'var(--hw-red)' : ev.risk_score >= 60 ? 'var(--hw-amber)' : 'var(--text-muted)' }}>
                      {ev.risk_score}
                    </span>
                  </td>
                  <td>
                    {isAlert ? (
                      <span className="badge badge-critical" style={{ fontSize: 10 }}>ALERT ({ev.predicted_attack_type})</span>
                    ) : (
                      <span style={{ color: 'var(--hw-green)', fontSize: 11, fontWeight: 600 }}>NORMAL</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
