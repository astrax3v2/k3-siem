import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth, LoginPage } from './components/Layout/Auth';
import Layout from './components/Layout/Layout';
import Dashboard from './components/Dashboard/Dashboard';
import TriageCenter from './components/Triage/TriageCenter';
import AlertManager from './components/Alerts/AlertManager';
import KQLEngine from './components/KQL/KQLEngine';
import { EventExplorer, IncidentResponse, Correlation, ThreatIntel, UEBA, SOAR } from './components/Pages';
import AgentManager from './components/Agents/AgentManager';
import AssetInventory from './components/Inventory/AssetInventory';
import VulnerabilityScanner from './components/Inventory/VulnerabilityScanner';
import OCSFParser from './components/OCSF/OCSFParser';
import ProcessTree from './components/Investigation/ProcessTree';
import DashboardGallery from './components/Dashboards/DashboardGallery';
import DashboardViewer from './components/Dashboards/DashboardViewer';
import DashboardBuilder from './components/Dashboards/DashboardBuilder';
import TeamManagement from './components/Admin/TeamManagement';
import { useWebSocket } from './hooks/useWebSocket';
import './index.css';

function ProtectedApp() {
  const { user, loading } = useAuth();
  const { connected, liveEvents, liveAlerts } = useWebSocket();

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg)' }}>
        <div style={{ color: 'var(--text2)', fontSize: 14 }}>Initializing K3 SIEM…</div>
      </div>
    );
  }

  if (!user) return <LoginPage />;

  return (
    <Layout connected={connected} liveAlertCount={liveAlerts.length}>
      <Routes>
        <Route path="/" element={<TriageCenter liveAlerts={liveAlerts} />} />
        <Route path="/overview" element={<Dashboard liveEvents={liveEvents} liveAlerts={liveAlerts} />} />
        <Route path="/alerts" element={<AlertManager liveAlerts={liveAlerts} />} />
        <Route path="/incidents" element={<IncidentResponse />} />
        <Route path="/events" element={<EventExplorer liveEvents={liveEvents} />} />
        <Route path="/kql" element={<KQLEngine />} />
        <Route path="/correlation" element={<Correlation />} />
        <Route path="/intel" element={<ThreatIntel />} />
        <Route path="/ueba" element={<UEBA />} />
        <Route path="/soar" element={<SOAR />} />
        <Route path="/agents" element={<AgentManager />} />
        <Route path="/inventory" element={<AssetInventory />} />
        <Route path="/vulnerabilities" element={<VulnerabilityScanner />} />
        <Route path="/ocsf" element={<OCSFParser />} />
        <Route path="/investigation/:id" element={<ProcessTree />} />
        <Route path="/dashboards" element={<DashboardGallery />} />
        <Route path="/dashboards/new" element={<DashboardBuilder liveEvents={liveEvents} liveAlerts={liveAlerts} />} />
        <Route path="/dashboards/:id/edit" element={<DashboardBuilder liveEvents={liveEvents} liveAlerts={liveAlerts} />} />
        <Route path="/dashboards/:id" element={<DashboardViewer liveEvents={liveEvents} liveAlerts={liveAlerts} />} />
        <Route path="/admin/teams" element={user?.role === 'admin' ? <TeamManagement /> : <Navigate to="/" />} />
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </Layout>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <ProtectedApp />
      </AuthProvider>
    </BrowserRouter>
  );
}
