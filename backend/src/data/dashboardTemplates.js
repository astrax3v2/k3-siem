'use strict';
/**
 * Built-in dashboard template catalog. These are not stored in the
 * `dashboards` table — they're served as read-only starting points that an
 * analyst can clone ("Use Template") into their own editable dashboard row.
 *
 * Widget shape: { id, type, title, size, config }
 *   size: 'sm' | 'md' | 'lg' | 'full' — hint for the frontend grid.
 *   type: maps 1:1 to data already exposed by existing endpoints — see
 *   frontend/src/components/Dashboards/widgets/WidgetRenderer.jsx for the
 *   type → data-source mapping.
 */

const DASHBOARD_TEMPLATES = [
  {
    id: 'soc-overview',
    name: 'SOC Overview',
    description: 'High-level KPIs, alert trend, and live feeds for daily triage.',
    category: 'Operations',
    widgets: [
      { id: 'w1', type: 'kpi_tile', title: 'Alerts (24h)', size: 'sm', config: { metric: 'alerts.total', color: '#fc8181' } },
      { id: 'w2', type: 'kpi_tile', title: 'Open Incidents', size: 'sm', config: { metric: 'alerts.open', color: '#f6ad55' } },
      { id: 'w3', type: 'kpi_tile', title: 'Events Indexed (24h)', size: 'sm', config: { metric: 'eventCount', color: 'var(--gold)' } },
      { id: 'w4', type: 'kpi_tile', title: 'Agents Online', size: 'sm', config: { metric: 'agentStats.online', color: '#68d391' } },
      { id: 'w5', type: 'alert_trend', title: 'Alert Trend (14 days)', size: 'md', config: {} },
      { id: 'w6', type: 'severity_bar', title: 'Severity Distribution', size: 'md', config: {} },
      { id: 'w7', type: 'live_alert_feed', title: 'Live Alert Feed', size: 'full', config: { limit: 5 } },
      { id: 'w8', type: 'live_event_stream', title: 'Live Event Stream', size: 'full', config: { limit: 10 } },
      { id: 'w9', type: 'agent_status', title: 'Agent Status', size: 'md', config: {} },
      { id: 'w10', type: 'asset_overview', title: 'Asset Overview', size: 'md', config: {} },
    ],
  },
  {
    id: 'threat-hunting',
    name: 'Threat Hunting',
    description: 'MITRE tactics, IOC hits, and raw event/alert search for proactive hunts.',
    category: 'Investigation',
    widgets: [
      { id: 'w1', type: 'kpi_tile', title: 'IOC Hits', size: 'sm', config: { metric: 'iocHits', color: '#fc8181' } },
      { id: 'w2', type: 'mitre_tactics', title: 'Top MITRE Tactics', size: 'md', config: {} },
      { id: 'w3', type: 'alert_status', title: 'Alert Status', size: 'md', config: {} },
      { id: 'w4', type: 'ioc_feed', title: 'Recent IOCs', size: 'full', config: { limit: 10 } },
      { id: 'w5', type: 'alerts_table', title: 'Critical & High Alerts', size: 'full', config: { severity: 'Critical', limit: 15 } },
      { id: 'w6', type: 'events_table', title: 'Recent Events', size: 'full', config: { limit: 20 } },
    ],
  },
  {
    id: 'vuln-compliance',
    name: 'Vulnerability & Compliance',
    description: 'CVE exposure and asset compliance posture across the fleet.',
    category: 'Risk',
    widgets: [
      { id: 'w1', type: 'vuln_summary', title: 'Vulnerability Summary', size: 'full', config: {} },
      { id: 'w2', type: 'asset_overview', title: 'Asset Overview', size: 'md', config: {} },
      { id: 'w3', type: 'kpi_tile', title: 'Compliant Assets', size: 'sm', config: { metric: 'assetStats.compliancePercent', color: '#68d391', suffix: '%' } },
      { id: 'w4', type: 'kpi_tile', title: 'Total Assets', size: 'sm', config: { metric: 'assetStats.total', color: 'var(--gold)' } },
    ],
  },
  {
    id: 'agent-fleet-health',
    name: 'Agent Fleet Health',
    description: 'Agent connectivity, coverage, and endpoint inventory at a glance.',
    category: 'Infrastructure',
    widgets: [
      { id: 'w1', type: 'agent_status', title: 'Agent Status', size: 'md', config: {} },
      { id: 'w2', type: 'kpi_tile', title: 'Agents Total', size: 'sm', config: { metric: 'agentStats.total', color: 'var(--gold)' } },
      { id: 'w3', type: 'kpi_tile', title: 'Agents Offline', size: 'sm', config: { metric: 'agentStats.offline', color: '#fc8181' } },
      { id: 'w4', type: 'asset_overview', title: 'Asset Overview', size: 'md', config: {} },
      { id: 'w5', type: 'live_event_stream', title: 'Live Event Stream', size: 'full', config: { limit: 15 } },
    ],
  },
  {
    id: 'identity-ueba',
    name: 'Identity & UEBA',
    description: 'User risk scoring and credential/identity-related alert activity.',
    category: 'Identity',
    widgets: [
      { id: 'w1', type: 'kpi_tile', title: 'High-Risk Users', size: 'sm', config: { metric: 'uebaHigh', color: '#fc8181' } },
      { id: 'w2', type: 'mitre_tactics', title: 'Top MITRE Tactics', size: 'md', config: {} },
      { id: 'w3', type: 'alert_status', title: 'Alert Status', size: 'md', config: {} },
      { id: 'w4', type: 'alerts_table', title: 'High-Severity Alerts', size: 'full', config: { severity: 'High', limit: 15 } },
    ],
  },
];

module.exports = { DASHBOARD_TEMPLATES };
