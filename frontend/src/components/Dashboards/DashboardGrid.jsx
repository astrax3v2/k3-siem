import React from 'react';
import WidgetRenderer, { SIZE_SPAN } from './widgets/WidgetRenderer';

export default function DashboardGrid({ widgets, liveEvents, liveAlerts }) {
  if (!widgets || widgets.length === 0) {
    return <div style={{ color: 'var(--text3)', padding: 20 }}>This dashboard has no widgets yet.</div>;
  }
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
      {widgets.map(w => (
        <div key={w.id} style={{ gridColumn: `span ${SIZE_SPAN[w.size] || 2}` }}>
          <WidgetRenderer widget={w} liveEvents={liveEvents} liveAlerts={liveAlerts} />
        </div>
      ))}
    </div>
  );
}
