import React, { useState, useEffect } from 'react';
import { Shield, Activity, AlertTriangle, Search, BarChart2, Settings } from 'lucide-react';
import Overview from './pages/Overview';
import LiveFeed from './pages/LiveFeed';
import AlertTriage from './pages/AlertTriage';
import EntityInvestigate from './pages/EntityInvestigate';
import Analytics from './pages/Analytics';
import SettingsPage from './pages/Settings';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [wsEvents, setWsEvents] = useState([]);

  // Resilient WebSocket Listener with Auto-Reconnect
  useEffect(() => {
    let ws;
    let timer;

    function connect() {
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${wsProtocol}//${window.location.host}/api/events/stream`;

      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          console.log('[WebSocket Connected]');
        };

        ws.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data);
            if (payload.type === 'NEW_EVENT') {
              setWsEvents((prev) => [payload.data, ...prev.slice(0, 199)]);
            } else if (payload.type === 'ATTACK_BURST_TRIGGERED') {
              console.log('[Attack Burst Notification Received]');
            }
          } catch (err) {
            console.error('WebSocket parse error', err);
          }
        };

        ws.onclose = () => {
          console.warn('[WebSocket Closed] Retrying in 3 seconds...');
          timer = setTimeout(connect, 3000);
        };

        ws.onerror = (err) => {
          console.error('[WebSocket Error]', err);
          ws.close();
        };
      } catch (e) {
        console.warn('WebSocket connection error', e);
        timer = setTimeout(connect, 3000);
      }
    }

    connect();

    return () => {
      if (ws) ws.close();
      if (timer) clearTimeout(timer);
    };
  }, []);

  const navItems = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'live-feed', label: 'Live Event Stream', icon: Shield },
    { id: 'triage', label: 'Alerts Triage Queue', icon: AlertTriangle },
    { id: 'investigate', label: 'Entity Investigation', icon: Search },
    { id: 'analytics', label: 'Analytics & Benchmarks', icon: BarChart2 },
    { id: 'settings', label: 'Model Tuning & Config', icon: Settings },
  ];

  return (
    <div className="app-container">
      {/* Sidebar */}
      <div className="sidebar">
        <div style={{ padding: '20px', borderBottom: '1px solid var(--border-color)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Shield style={{ color: 'var(--hw-red)', width: 28, height: 28 }} />
            <div>
              <h2 style={{ fontSize: 16, color: '#FFF', fontWeight: 700 }}>Honeywell</h2>
              <span style={{ fontSize: 11, color: 'var(--hw-blue)', fontWeight: 600 }}>CYBER INSIGHTS</span>
            </div>
          </div>
        </div>

        <nav style={{ padding: '12px 0', flex: 1 }}>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <div
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  padding: '12px 20px',
                  cursor: 'pointer',
                  color: isActive ? '#FFF' : 'var(--text-muted)',
                  backgroundColor: isActive ? 'rgba(238, 49, 36, 0.15)' : 'transparent',
                  borderLeft: isActive ? '3px solid var(--hw-red)' : '3px solid transparent',
                  fontWeight: isActive ? 600 : 400,
                  fontSize: 14,
                  transition: 'all 0.15s ease'
                }}
              >
                <Icon size={18} style={{ color: isActive ? 'var(--hw-red)' : 'inherit' }} />
                {item.label}
              </div>
            );
          })}
        </nav>

        <div style={{ padding: '16px', borderTop: '1px solid var(--border-color)', fontSize: 11, color: 'var(--text-muted)' }}>
          <div>SOC Console v2.0</div>
          <div>Domain: Mixed IT + OT Enterprise</div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="main-content">
        {activeTab === 'overview' && <Overview onNavigate={setActiveTab} />}
        {activeTab === 'live-feed' && <LiveFeed wsEvents={wsEvents} />}
        {activeTab === 'triage' && <AlertTriage />}
        {activeTab === 'investigate' && <EntityInvestigate />}
        {activeTab === 'analytics' && <Analytics />}
        {activeTab === 'settings' && <SettingsPage />}
      </div>
    </div>
  );
}
