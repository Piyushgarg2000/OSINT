import { useEffect, useState, useCallback, useRef } from 'react';
import axios from 'axios';
import MapChart from './MapChart';
import VpnAudit from './VpnAudit';
import ASNIntelligence from './ASNIntelligence';

/* ─── Theme (Mapped to CSS Variables) ────────────────────────────────────────── */
const T = {
  bg:        'var(--bg)',
  card:      'var(--card)',
  cardSub:   'var(--cardSub)',
  border:    'var(--border)',
  textMain:  'var(--textMain)',
  textMuted: 'var(--textMuted)',
  accent:    'var(--accent)',
  cyan:      'var(--cyan)',
  success:   'var(--success)',
  danger:    'var(--danger)',
  warning:   'var(--warning)',
  purple:    'var(--purple)',
  sidebar:   'var(--sidebar)',
  topbar:    'var(--topbar)',
};

const SIDEBAR_W  = 230; // px, expanded
const TOPBAR_H   = 60;  // px

/* ─── Navigation sections ─────────────────────────────────────────────── */
const NAV = [
  {
    id:    'dashboard',
    icon:  '📊',
    label: 'Dashboard',
    sub:   'Overview & Status',
    color: T.accent,
  },
  {
    id:    'ip_intel',
    icon:  '🔍',
    label: 'IP Intelligence',
    sub:   'Search & Profile',
    color: T.cyan,
  },
  {
    id:    'forensic_audit',
    icon:  '🔬',
    label: 'Forensic Audit',
    sub:   'VPN & Infrastructure',
    color: T.purple,
  },
  {
    id:    'asn_intel',
    icon:  '🛡️',
    label: 'ASN Analytics',
    sub:   'Threat Intelligence',
    color: T.danger,
  },
  {
    id:    'threat_map',
    icon:  '🗺️',
    label: 'Threat Map',
    sub:   'Global Coverage',
    color: T.success,
  },
];

/* ─── Shared mini-components ─────────────────────────────────────────── */

/** Top gradient header for every section */
function SectionBanner({ icon, title, subtitle, badge, action, color }) {
  return (
    <div style={{
      background: `linear-gradient(135deg, ${T.card} 0%, ${color}11 60%, ${T.card} 100%)`,
      borderBottom: `1px solid ${color}33`,
      padding: '26px 32px 22px',
      display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end',
      flexWrap: 'wrap', gap: '14px',
      position: 'sticky', top: 0, zIndex: 20,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{
          width: 48, height: 48, borderRadius: '12px', fontSize: 24,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: `${color}18`, border: `1px solid ${color}44`,
          flexShrink: 0,
        }}>{icon}</div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <h2 style={{ margin: 0, fontSize: 20, fontWeight: 800, color: T.textMain, letterSpacing: '-0.3px' }}>{title}</h2>
            {badge && (
              <span style={{
                fontSize: 11, padding: '2px 9px', borderRadius: 4, fontWeight: 700,
                backgroundColor: `${color}22`, color, border: `1px solid ${color}55`,
              }}>{badge}</span>
            )}
          </div>
          <p style={{ margin: '3px 0 0', fontSize: 13, color: T.textMuted }}>{subtitle}</p>
        </div>
      </div>
      {action}
    </div>
  );
}

/** Stat card used in Dashboard */
function StatCard({ icon, label, value, sub, color, onClick }) {
  return (
    <div
      onClick={onClick}
      style={{
        backgroundColor: T.cardSub, borderRadius: 10,
        border: `1px solid ${color}33`,
        padding: '18px 20px',
        cursor: onClick ? 'pointer' : 'default',
        transition: 'all 0.2s',
        position: 'relative', overflow: 'hidden',
      }}
      onMouseEnter={e => { if (onClick) e.currentTarget.style.borderColor = color; }}
      onMouseLeave={e => { if (onClick) e.currentTarget.style.borderColor = `${color}33`; }}
    >
      <div style={{ position: 'absolute', right: 14, top: 14, fontSize: 26, opacity: 0.15 }}>{icon}</div>
      <div style={{ fontSize: 11, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>
        {icon} {label}
      </div>
      <div style={{ fontSize: 28, fontWeight: 900, color, lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: T.textMuted, marginTop: 6 }}>{sub}</div>}
    </div>
  );
}

/** Recent scan row in Dashboard */
function RecentScanRow({ scan, onSearch }) {
  const hasFlag = scan.behavioral_flags && scan.behavioral_flags.length > 0;
  return (
    <div
      onClick={() => onSearch(scan.ip)}
      style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '10px 14px', borderRadius: 8,
        backgroundColor: `${T.card}`,
        border: `1px solid ${T.border}33`,
        cursor: 'pointer', transition: 'all 0.15s',
        gap: 10,
      }}
      onMouseEnter={e => e.currentTarget.style.backgroundColor = `${T.purple}15`}
      onMouseLeave={e => e.currentTarget.style.backgroundColor = T.card}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{
          width: 8, height: 8, borderRadius: '50%', display: 'inline-block', flexShrink: 0,
          backgroundColor: hasFlag ? T.danger : T.success,
        }} />
        <span style={{ fontFamily: 'monospace', fontWeight: 700, color: T.accent, fontSize: 13 }}>{scan.ip}</span>
        {scan.asn && <span style={{ fontSize: 11, color: T.textMuted }}>{scan.asn}</span>}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
        {hasFlag && (
          <span style={{
            fontSize: 10, padding: '2px 7px', borderRadius: 3, fontWeight: 700,
            backgroundColor: '#450a0a', color: T.danger, border: `1px solid ${T.danger}44`,
          }}>{scan.behavioral_flags[0]}</span>
        )}
        <span style={{ fontSize: 10, color: T.textMuted }}>{scan.cached_at || ''}</span>
        <span style={{ color: T.textMuted, fontSize: 11 }}>↗</span>
      </div>
    </div>
  );
}

/* ─── RIPEstat Telemetry Card ─────────────────────────────────────────── */
function RipestatTelemetryCard({ ripestat }) {
  const [collapsed, setCollapsed] = useState(false);
  if (!ripestat) return null;
  const { announced_asn, prefix, holder_registry, visibility, multilateral_probes } = ripestat;

  return (
    <div style={{ marginTop: 16, backgroundColor: T.bg, border: `1px solid ${T.border}`, borderRadius: 8, overflow: 'hidden' }}>
      <div
        onClick={() => setCollapsed(v => !v)}
        style={{
          padding: '14px 18px', backgroundColor: '#0B132B',
          borderBottom: collapsed ? 'none' : `1px solid ${T.border}`,
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          cursor: 'pointer', userSelect: 'none', flexWrap: 'wrap', gap: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 18 }}>🌐</span>
          <strong style={{ color: T.textMain, fontSize: 14 }}>Global RIPEstat & BGP Routing Telemetry</strong>
          {announced_asn && announced_asn !== 'Unknown' && (
            <span style={{ fontSize: 11, fontWeight: 700, padding: '3px 8px', borderRadius: 4, backgroundColor: '#083344', color: T.cyan, border: `1px solid ${T.cyan}` }}>
              {announced_asn}{prefix && prefix !== 'Unknown' ? ` · ${prefix}` : ''}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {visibility && visibility !== 'N/A' && (
            <span style={{ fontSize: 11, fontWeight: 700, padding: '3px 8px', borderRadius: 4, backgroundColor: '#052e16', color: T.success, border: `1px solid ${T.success}` }}>
              🟢 Visibility: {visibility}
            </span>
          )}
          <span style={{ color: T.textMuted, fontSize: 12 }}>{collapsed ? '▼ Show Details' : '▲ Collapse'}</span>
        </div>
      </div>

      {!collapsed && (
        <div style={{ padding: '16px 18px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 16, fontSize: 13 }}>
            {[
              { label: 'Announcing ASN', val: announced_asn, color: T.accent },
              { label: 'Network Prefix (CIDR)', val: prefix, color: T.cyan },
              { label: 'RIPE Registry Location', val: `${holder_registry?.country || 'Unknown'}${holder_registry?.city && holder_registry.city !== 'Registry Node' ? ` (${holder_registry.city})` : ''}`, color: T.textMain },
              { label: 'BGP Visibility Score', val: visibility, color: T.success },
            ].map(c => (
              <div key={c.label} style={{ backgroundColor: T.card, padding: '10px 14px', borderRadius: 6, border: `1px solid ${T.border}` }}>
                <div style={{ fontSize: 11, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px' }}>{c.label}</div>
                <strong style={{ color: c.color, fontSize: 14, fontFamily: 'monospace' }}>{c.val}</strong>
              </div>
            ))}
          </div>
          {multilateral_probes && multilateral_probes.length > 0 && (
            <div>
              <div style={{ fontSize: 11, color: T.textMuted, textTransform: 'uppercase', letterSpacing: 1, fontWeight: 700, marginBottom: 8 }}>
                📡 Multi-Vantage Probe Validation
              </div>
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, fontFamily: 'monospace' }}>
                  <thead>
                    <tr style={{ borderBottom: `1px solid ${T.border}`, textAlign: 'left', color: T.textMuted, fontSize: 11, textTransform: 'uppercase' }}>
                      {['Anchor Vantage Probe', 'Region', 'Geodesic Distance', 'Est. Latency', 'Route Status'].map(h => (
                        <th key={h} style={{ padding: '6px 10px' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {multilateral_probes.map((probe, i) => (
                      <tr key={i} style={{ borderBottom: `1px solid ${T.border}` }}>
                        <td style={{ padding: '7px 10px', color: T.textMain, fontWeight: 600 }}>{probe.anchor}</td>
                        <td style={{ padding: '7px 10px', color: T.textMuted }}>{probe.region}</td>
                        <td style={{ padding: '7px 10px', color: T.cyan }}>{probe.distance_km?.toLocaleString()} km</td>
                        <td style={{ padding: '7px 10px', color: T.accent, fontWeight: 700 }}>{probe.est_latency_ms} ms</td>
                        <td style={{ padding: '7px 10px' }}>
                          <span style={{
                            padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600,
                            backgroundColor: probe.route_status === 'Optimal Edge' ? '#052e16' : probe.route_status === 'Continental' ? '#083344' : '#2e1065',
                            color: probe.route_status === 'Optimal Edge' ? T.success : probe.route_status === 'Continental' ? T.cyan : '#a78bfa',
                            border: `1px solid ${probe.route_status === 'Optimal Edge' ? T.success : probe.route_status === 'Continental' ? T.cyan : '#8b5cf6'}`,
                          }}>{probe.route_status}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ─── Section: Dashboard ─────────────────────────────────────────────── */
function DashboardSection({ dbConnected, lastUpdated, asnStats, recentScans, onNavigate, onSearchIP }) {
  const stats = asnStats ? [
    { icon: '🗄️', label: 'DynamoDB Records',   value: asnStats.total_table_items > 0 ? asnStats.total_table_items.toLocaleString() : '50,000+', sub: 'Total cached IPs', color: T.cyan,    nav: null },
    { icon: '🛡️', label: 'Total Threat IPs', value: (asnStats.global_total_threats ?? 0).toLocaleString(), sub: 'With behavioral flags', color: T.danger,  nav: 'asn_intel' },
    { icon: '🌐', label: 'Analyzed ASNs (BGP)',  value: (asnStats.total_analyzed_ips ?? 0).toLocaleString(),   sub: 'IPs with valid routing', color: T.purple,  nav: 'asn_intel' },
    { icon: '⚡', label: 'IPs Scanned',          value: (asnStats.sample_size ?? 0).toLocaleString(), sub: 'In parallel 8-seg scan', color: T.accent, nav: null },
  ] : [];

  const quickLinks = [
    { icon: '🔍', label: 'Scan an IP Address',       sub: 'Profile geography, flags, BGP, telemetry', nav: 'ip_intel',       color: T.cyan },
    { icon: '🔬', label: 'Forensic Audit',            sub: 'VPN detection, consensus, traceroute',     nav: 'forensic_audit', color: T.purple },
    { icon: '🛡️', label: 'ASN Threat Analytics',     sub: 'Prefix clustering, findings, heatmaps',    nav: 'asn_intel',      color: T.danger },
    { icon: '🗺️', label: 'Global Threat Map',        sub: 'Multi-provider geo coverage by country',   nav: 'threat_map',     color: T.success },
  ];

  return (
    <div style={{ padding: '28px 32px' }}>
      {/* System status strip */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 28, flexWrap: 'wrap' }}>
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          backgroundColor: T.cardSub, padding: '10px 16px', borderRadius: 8,
          border: `1px solid ${dbConnected ? T.success : T.warning}44`,
        }}>
          <span style={{ width: 9, height: 9, borderRadius: '50%', backgroundColor: dbConnected ? T.success : T.warning, display: 'inline-block' }} />
          <div>
            <div style={{ fontSize: 10, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px' }}>DynamoDB Cache</div>
            <div style={{ fontWeight: 700, fontSize: 13, color: dbConnected ? T.success : T.warning }}>
              {dbConnected ? 'Connected & Active' : 'Standby / Local'}
            </div>
          </div>
        </div>
        <div style={{ backgroundColor: T.cardSub, padding: '10px 16px', borderRadius: 8, border: `1px solid ${T.border}` }}>
          <div style={{ fontSize: 10, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Data Sync</div>
          <div style={{ fontWeight: 600, fontSize: 13, color: T.success }}>● {lastUpdated}</div>
        </div>
      </div>

      {/* Stats Grid */}
      {stats.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14, marginBottom: 32 }}>
          {stats.map(s => (
            <StatCard key={s.label} {...s} onClick={s.nav ? () => onNavigate(s.nav) : undefined} />
          ))}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 24, alignItems: 'start' }}>
        {/* Quick-access links */}
        <div>
          <div style={{ fontSize: 12, fontWeight: 700, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 14 }}>
            🚀 Quick Access
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12 }}>
            {quickLinks.map(q => (
              <div
                key={q.nav}
                onClick={() => onNavigate(q.nav)}
                style={{
                  backgroundColor: T.cardSub, borderRadius: 10, padding: '16px 18px',
                  border: `1px solid ${q.color}33`, cursor: 'pointer',
                  display: 'flex', alignItems: 'flex-start', gap: 14,
                  transition: 'all 0.2s',
                }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = q.color; e.currentTarget.style.backgroundColor = `${q.color}10`; }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = `${q.color}33`; e.currentTarget.style.backgroundColor = T.cardSub; }}
              >
                <span style={{ fontSize: 22, flexShrink: 0 }}>{q.icon}</span>
                <div>
                  <div style={{ fontWeight: 700, color: T.textMain, fontSize: 14 }}>{q.label}</div>
                  <div style={{ fontSize: 12, color: T.textMuted, marginTop: 3 }}>{q.sub}</div>
                </div>
                <span style={{ color: T.textMuted, marginLeft: 'auto', fontSize: 14 }}>→</span>
              </div>
            ))}
          </div>

          {/* Methodology note */}
          <div style={{ marginTop: 20, backgroundColor: '#082030', borderRadius: 8, padding: '14px 18px', border: `1px solid ${T.cyan}22` }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: T.cyan, marginBottom: 8 }}>📋 Project Methodology</div>
            <div style={{ fontSize: 12, color: T.textMuted, lineHeight: 1.7 }}>
              This OSINT dashboard aggregates IP threat intelligence from
              <strong style={{ color: T.textMain }}> FireHOL blocklists</strong> (8 behavioral categories),
              cross-referenced with <strong style={{ color: T.textMain }}>4 GeoIP providers</strong>,
              <strong style={{ color: T.textMain }}> RIPEstat BGP data</strong>, and
              <strong style={{ color: T.textMain }}> ipinfo.io</strong> for ASN profiling.
              All analytics derive from observed OSINT data — empirical proportions, not predictive probabilities.
            </div>
          </div>
        </div>

        {/* Recent Scans */}
        <div>
          <div style={{ fontSize: 12, fontWeight: 700, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 14 }}>
            🕒 Recent Scans
          </div>
          {recentScans.length === 0 ? (
            <div style={{ color: T.textMuted, fontSize: 13, padding: '20px 0', textAlign: 'center' }}>No recent scans found.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {recentScans.slice(0, 8).map(s => (
                <RecentScanRow key={s.ip} scan={s} onSearch={ip => { onNavigate('ip_intel'); onSearchIP(ip); }} />
              ))}
            </div>
          )}
          <button
            onClick={() => onNavigate('ip_intel')}
            style={{
              marginTop: 12, width: '100%', padding: '9px', fontSize: 12, fontWeight: 600,
              backgroundColor: T.card, color: T.accent,
              border: `1px solid ${T.accent}44`, borderRadius: 8, cursor: 'pointer',
            }}
          >
            + Scan New IP →
          </button>
        </div>
      </div>
    </div>
  );
}

/* ─── ML Threat Assessment Card ─────────────────────────────────────────── */
function MLThreatCard({ ip }) {
  const [mlData,    setMlData]    = useState(null);
  const [mlLoading, setMlLoading] = useState(false);
  const [mlError,   setMlError]   = useState(null);
  const [expanded,  setExpanded]  = useState(true);
  const [modelInfo, setModelInfo] = useState(null);

  useEffect(() => {
    if (!ip) return;
    setMlLoading(true);
    setMlData(null);
    setMlError(null);

    // Pass ripestat+geo from search results directly in query isn't supported in GET,
    // so the backend pulls from DynamoDB cache if available, else uses defaults.
    axios.get(`http://127.0.0.1:8000/api/ml/threat-assessment?ip=${encodeURIComponent(ip)}`)
      .then(res => { setMlData(res.data); setMlLoading(false); })
      .catch(err => { setMlError(err.message); setMlLoading(false); });
  }, [ip]);

  useEffect(() => {
    axios.get('http://127.0.0.1:8000/api/ml/model-info')
      .then(r => setModelInfo(r.data))
      .catch(() => {});
  }, []);

  if (!ip) return null;

  const RISK_COLORS = {
    CRITICAL: '#EF4444', HIGH: '#F97316', MEDIUM: '#F59E0B', LOW: '#10B981',
  };
  const RISK_BG = {
    CRITICAL: '#450a0a', HIGH: '#431407', MEDIUM: '#422006', LOW: '#052e16',
  };
  const DIRECTION_ICON = { risk: '⬆️', safe: '⬇️', neutral: '➡️' };

  const prob     = mlData?.threat_probability ?? 0;
  const risk     = mlData?.risk_level ?? 'LOW';
  const riskColor = RISK_COLORS[risk] ?? T.success;
  const riskBg    = RISK_BG[risk]    ?? '#052e16';

  return (
    <div style={{ marginTop: 20, backgroundColor: T.card, borderRadius: 12, border: `1px solid ${T.purple}44`, overflow: 'hidden' }}>
      {/* Header */}
      <div
        onClick={() => setExpanded(v => !v)}
        style={{
          padding: '14px 20px', cursor: 'pointer',
          background: 'linear-gradient(135deg, #0F172A 0%, #1E1B4B 100%)',
          borderBottom: expanded ? `1px solid ${T.border}` : 'none',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 20 }}>🤖</span>
          <div>
            <div style={{ fontWeight: 700, fontSize: 14, color: T.textMain }}>ML Threat Assessment</div>
            <div style={{ fontSize: 11, color: T.textMuted }}>
              RandomForest trained on {modelInfo?.n_records?.toLocaleString() ?? '62,000+'} observed OSINT records
            </div>
          </div>
          <span style={{
            fontSize: 10, padding: '2px 8px', borderRadius: 4, fontWeight: 700,
            backgroundColor: '#1E1B4B', color: T.purple, border: `1px solid ${T.purple}55`,
          }}>STATISTICAL MODEL</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {!mlLoading && mlData?.status === 'success' && (
            <span style={{
              padding: '4px 14px', borderRadius: 6, fontWeight: 800, fontSize: 14,
              backgroundColor: riskBg, color: riskColor, border: `1px solid ${riskColor}44`,
            }}>{risk} · {prob}%</span>
          )}
          <span style={{ color: T.textMuted, fontSize: 12 }}>{expanded ? '▲' : '▼'}</span>
        </div>
      </div>

      {expanded && (
        <div style={{ padding: '20px 22px' }}>

          {/* Loading */}
          {mlLoading && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 0', color: T.textMuted }}>
              <span style={{ fontSize: 20, animation: 'spin 1s linear infinite' }}>⟳</span>
              <div>
                <div style={{ fontWeight: 600, color: T.purple, fontSize: 13 }}>Running threat assessment…</div>
                <div style={{ fontSize: 11 }}>Model may be training — this can take up to 60s on first use</div>
              </div>
            </div>
          )}

          {/* Model still training */}
          {!mlLoading && mlData?.status === 'model_not_ready' && (
            <div style={{ padding: '14px', backgroundColor: '#1E1B4B', borderRadius: 8, border: `1px solid ${T.purple}44`, color: T.purple, fontSize: 13 }}>
              ⏳ {mlData.message}
              <div style={{ fontSize: 11, color: T.textMuted, marginTop: 6 }}>
                Training scans 62K+ DynamoDB records and fits a RandomForest. Refresh in ~60 seconds.
              </div>
            </div>
          )}

          {/* Error */}
          {!mlLoading && mlError && (
            <div style={{ color: T.danger, fontSize: 13 }}>⚠️ {mlError}</div>
          )}

          {/* Result */}
          {!mlLoading && mlData?.status === 'success' && (
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr auto', gap: 24, alignItems: 'start', marginBottom: 20 }}>

                {/* Gauge */}
                <div style={{ textAlign: 'center', minWidth: 120 }}>
                  <div style={{
                    width: 100, height: 100, borderRadius: '50%', margin: '0 auto 10px',
                    background: `conic-gradient(${riskColor} ${prob * 3.6}deg, ${T.cardSub} 0deg)`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    position: 'relative',
                  }}>
                    <div style={{
                      width: 78, height: 78, borderRadius: '50%', backgroundColor: T.card,
                      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                    }}>
                      <div style={{ fontSize: 20, fontWeight: 900, color: riskColor, lineHeight: 1 }}>{prob}%</div>
                      <div style={{ fontSize: 9, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Threat</div>
                    </div>
                  </div>
                  <div style={{
                    padding: '5px 12px', borderRadius: 6, fontWeight: 800, fontSize: 13,
                    backgroundColor: riskBg, color: riskColor, border: `1px solid ${riskColor}44`,
                    display: 'inline-block',
                  }}>{risk}</div>
                  <div style={{ fontSize: 10, color: T.textMuted, marginTop: 5 }}>
                    Confidence: <strong style={{ color: T.textMain }}>{mlData.confidence}</strong>
                  </div>
                </div>

                {/* Top factors */}
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 10 }}>
                    Top Risk Factors
                  </div>
                  {mlData.top_factors.length === 0 ? (
                    <div style={{ color: T.textMuted, fontSize: 12, fontStyle: 'italic' }}>No significant risk factors identified.</div>
                  ) : (
                    mlData.top_factors.map((f, i) => (
                      <div key={i} style={{
                        backgroundColor: T.cardSub, borderRadius: 8, padding: '10px 14px', marginBottom: 8,
                        border: `1px solid ${f.direction === 'risk' ? T.danger : f.direction === 'safe' ? T.success : T.border}22`,
                        borderLeft: `3px solid ${f.direction === 'risk' ? T.danger : f.direction === 'safe' ? T.success : T.textMuted}`,
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, marginBottom: 3 }}>
                          <span style={{ fontWeight: 700, fontSize: 12, color: T.textMain }}>
                            {DIRECTION_ICON[f.direction]} {f.factor}
                          </span>
                          <span style={{
                            fontSize: 10, padding: '1px 7px', borderRadius: 3, fontWeight: 700,
                            backgroundColor: `${f.direction === 'risk' ? T.danger : T.success}18`,
                            color: f.direction === 'risk' ? T.danger : T.success,
                          }}>
                            weight {(f.weight * 100).toFixed(0)}%
                          </span>
                        </div>
                        <div style={{ fontSize: 11, color: T.textMuted, lineHeight: 1.5 }}>{f.detail}</div>
                      </div>
                    ))
                  )}
                </div>

                {/* Input features */}
                <div style={{ minWidth: 180 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 10 }}>
                    Feature Values
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {[
                      { label: 'ASN', val: mlData.input_features.asn, mono: true },
                      { label: 'Prefix', val: mlData.input_features.prefix, mono: true },
                      { label: 'BGP Visibility', val: mlData.input_features.bgp_visibility + '%' },
                      { label: 'GeoIP Consensus', val: mlData.input_features.geo_consensus + '/4' },
                      { label: 'Country', val: mlData.input_features.country },
                      { label: 'ASN Hist. Rate', val: mlData.input_features.asn_threat_rate + '%', color: mlData.input_features.asn_threat_rate > 15 ? T.danger : T.success },
                      { label: 'Country Rate', val: mlData.input_features.country_threat_rate + '%', color: mlData.input_features.country_threat_rate > 15 ? T.warning : T.success },
                    ].map(r => (
                      <div key={r.label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, gap: 8 }}>
                        <span style={{ color: T.textMuted }}>{r.label}</span>
                        <span style={{ fontFamily: r.mono ? 'monospace' : undefined, fontWeight: 600, color: r.color || T.textMain, textAlign: 'right', maxWidth: 110, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {r.val}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Category signals */}
              {mlData.category_signals.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 10 }}>
                    Predicted Category Signals (based on ASN/country patterns)
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 8 }}>
                    {mlData.category_signals.map(s => {
                      const CAT_COLORS = { attacks: '#EF4444', abuse: '#F97316', anonymizers: '#06B6D4', malware: '#8B5CF6', spam: '#F59E0B', reputation: '#EC4899', unroutable: '#64748B', organizations: '#10B981' };
                      const c = CAT_COLORS[s.category] || T.textMuted;
                      return (
                        <div key={s.category} style={{ backgroundColor: T.cardSub, borderRadius: 6, padding: '8px 12px', border: `1px solid ${c}33` }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 5, textTransform: 'capitalize', fontWeight: 700 }}>
                            <span style={{ color: c }}>{s.category}</span>
                            <span style={{ color: T.textMuted }}>{s.signal_pct}%</span>
                          </div>
                          <div style={{ width: '100%', height: 4, backgroundColor: T.bg, borderRadius: 2, overflow: 'hidden' }}>
                            <div style={{ width: `${Math.min(s.signal_pct, 100)}%`, height: '100%', backgroundColor: c, borderRadius: 2 }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Model metrics row */}
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 12 }}>
                {[
                  { label: 'Training IPs', val: mlData.model_info.n_records?.toLocaleString() },
                  { label: 'Threat IPs', val: mlData.model_info.n_threats?.toLocaleString() },
                  { label: 'Test Accuracy', val: ((mlData.model_info.test_accuracy || 0) * 100).toFixed(1) + '%' },
                  { label: 'AUC-ROC', val: mlData.model_info.test_auc_roc?.toFixed(3) },
                  { label: 'Trained', val: mlData.model_info.trained_at },
                ].map(m => (
                  <div key={m.label} style={{ backgroundColor: T.cardSub, padding: '6px 12px', borderRadius: 6, border: `1px solid ${T.border}` }}>
                    <div style={{ fontSize: 9, color: T.textMuted, textTransform: 'uppercase' }}>{m.label}</div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: T.textMain, fontFamily: 'monospace' }}>{m.val}</div>
                  </div>
                ))}
              </div>

              {/* Disclaimer */}
              <div style={{ backgroundColor: '#0B132B', borderRadius: 8, padding: '10px 14px', border: `1px solid ${T.cyan}22`, fontSize: 11, color: T.textMuted, lineHeight: 1.6 }}>
                ⚠️ <strong style={{ color: T.cyan }}>Statistical Estimate Only:</strong> {mlData.disclaimer}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ─── Section: IP Intelligence ───────────────────────────────────────── */
function IPIntelSection({ searchQuery, setSearchQuery, searchResults, isSearching, handleSearch }) {
  const hasResults = !!searchResults;


  return (
    <div style={{ padding: '28px 32px' }}>
      {/* Search form */}
      <div style={{ backgroundColor: T.cardSub, borderRadius: 12, padding: '22px 24px', border: `1px solid ${T.border}`, marginBottom: 24 }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 14 }}>
          🔎 Target IP Address
        </div>
        <form onSubmit={e => handleSearch(e, false)} style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <input
            type="text"
            placeholder="Enter IPv4 Address (e.g. 8.8.8.8, 1.1.1.1, 23.192.128.0)"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            style={{
              flex: '1 1 320px', padding: '13px 18px',
              backgroundColor: T.bg, border: `1px solid ${T.border}`,
              borderRadius: 8, color: T.textMain, fontSize: 15,
              fontFamily: 'monospace', outline: 'none',
              transition: 'border-color 0.2s',
            }}
            onFocus={e => e.target.style.borderColor = T.accent}
            onBlur={e => e.target.style.borderColor = T.border}
          />
          <button
            type="submit"
            style={{
              padding: '13px 28px', backgroundColor: T.accent, color: T.bg,
              border: 'none', borderRadius: 8, cursor: 'pointer',
              fontWeight: 800, fontSize: 15, letterSpacing: '0.3px',
              transition: 'opacity 0.2s',
            }}
            onMouseEnter={e => e.target.style.opacity = '0.85'}
            onMouseLeave={e => e.target.style.opacity = '1'}
          >
            {isSearching ? '⟳ Scanning…' : '⚡ Execute Scan'}
          </button>
          {hasResults && (
            <button
              type="button"
              onClick={() => handleSearch(null, true)}
              disabled={isSearching}
              style={{
                padding: '13px 18px', backgroundColor: T.cardSub, color: T.cyan,
                border: `1px solid ${T.cyan}`, borderRadius: 8,
                cursor: 'pointer', fontWeight: 600, fontSize: 13,
              }}
              title="Bypass DynamoDB cache and force live network probes"
            >
              🔄 Force Re-Scan
            </button>
          )}
          {hasResults && searchResults._from_cache && (
            <span style={{
              fontSize: 12, fontWeight: 700, padding: '7px 14px', borderRadius: 8,
              backgroundColor: '#052e16', color: T.success, border: `1px solid ${T.success}`,
            }}>
              ⚡ From Cache ({searchResults._cached_at || 'Recent'})
            </span>
          )}
        </form>
      </div>

      {/* Results */}
      {isSearching && (
        <div style={{ textAlign: 'center', padding: '50px', color: T.textMuted, fontSize: 14 }}>
          <div style={{ fontSize: 36, marginBottom: 14 }}>⟳</div>
          Scanning {searchQuery}…
        </div>
      )}

      {hasResults && !isSearching && (
        <div>
          {/* Results header */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
            <span style={{ fontFamily: 'monospace', fontWeight: 900, fontSize: 18, color: T.accent }}>{searchQuery}</span>
            <span style={{
              fontSize: 11, padding: '3px 10px', borderRadius: 4, fontWeight: 700,
              backgroundColor: searchResults.behavioral_flags?.length ? '#450a0a' : '#052e16',
              color: searchResults.behavioral_flags?.length ? T.danger : T.success,
              border: `1px solid ${searchResults.behavioral_flags?.length ? T.danger : T.success}55`,
            }}>
              {searchResults.behavioral_flags?.length ? `⚠️ ${searchResults.behavioral_flags.length} Threat Flag${searchResults.behavioral_flags.length > 1 ? 's' : ''}` : '✅ No Threats Detected'}
            </span>
          </div>

          {/* 4-column result grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16, marginBottom: 20 }}>

            {/* Geographic Consensus */}
            <div style={{ backgroundColor: T.cardSub, borderRadius: 10, padding: '18px 20px', border: `1px solid ${T.border}` }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 }}>
                🌍 Geographic Consensus
              </div>
              {searchResults.geography && Object.keys(searchResults.geography).length > 0
                ? Object.entries(searchResults.geography).map(([provider, country]) => (
                    <div key={provider} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 6, padding: '4px 0', borderBottom: `1px solid ${T.border}22` }}>
                      <span style={{ color: T.textMuted, textTransform: 'uppercase', fontSize: 11 }}>{provider}</span>
                      <strong style={{ color: T.textMain }}>{country}</strong>
                    </div>
                  ))
                : <span style={{ color: T.danger, fontSize: 13 }}>No records found.</span>
              }
            </div>

            {/* Behavioral Flags */}
            <div style={{ backgroundColor: T.cardSub, borderRadius: 10, padding: '18px 20px', border: `1px solid ${searchResults.behavioral_flags?.length ? T.danger : T.border}44` }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 }}>
                🚩 Behavioral Flags
              </div>
              {searchResults.behavioral_flags?.length > 0
                ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                    {searchResults.behavioral_flags.map((flag, i) => (
                      <span key={i} style={{
                        display: 'inline-flex', alignItems: 'center', gap: 6,
                        fontSize: 13, fontWeight: 700, textTransform: 'capitalize', color: T.danger,
                        padding: '5px 10px', borderRadius: 6,
                        backgroundColor: '#450a0a', border: `1px solid ${T.danger}44`,
                      }}>⚠️ {flag}</span>
                    ))}
                  </div>
                )
                : <span style={{ color: T.success, fontWeight: 600, fontSize: 14 }}>✅ No Malicious Activity Detected</span>
              }
            </div>

            {/* BGP / ASN Profile */}
            {searchResults.bgp_info && (
              <div style={{ backgroundColor: T.cardSub, borderRadius: 10, padding: '18px 20px', border: `1px solid ${T.border}` }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 }}>
                  🔗 BGP / ASN Profile
                </div>
                {[
                  { label: 'Organization', val: searchResults.bgp_info.org, color: T.textMain },
                  { label: 'ASN', val: searchResults.bgp_info.asn, color: T.accent, mono: true },
                  { label: 'Infrastructure', val: searchResults.bgp_info.infra_type, color: T.cyan },
                  { label: 'Country', val: searchResults.bgp_info.country, color: T.textMain },
                ].map(r => (
                  <div key={r.label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 7, alignItems: 'flex-start', gap: 8 }}>
                    <span style={{ color: T.textMuted, fontSize: 11, textTransform: 'uppercase', flexShrink: 0 }}>{r.label}</span>
                    <strong style={{ color: r.color, fontFamily: r.mono ? 'monospace' : undefined, textAlign: 'right', wordBreak: 'break-word' }}>{r.val}</strong>
                  </div>
                ))}
              </div>
            )}

            {/* Live Telemetry */}
            <div style={{ backgroundColor: T.cardSub, borderRadius: 10, padding: '18px 20px', border: `1px solid ${T.border}` }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 }}>
                📡 Live Telemetry
              </div>
              {searchResults.telemetry && (
                <div>
                  <div style={{
                    color: searchResults.telemetry.status?.includes('Online') ? T.success : T.danger,
                    fontWeight: 700, fontSize: 15, marginBottom: 10,
                    display: 'flex', alignItems: 'center', gap: 6,
                  }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: searchResults.telemetry.status?.includes('Online') ? T.success : T.danger, display: 'inline-block' }} />
                    {searchResults.telemetry.status}
                  </div>
                  <div style={{ fontSize: 13, color: T.textMuted, lineHeight: 1.7 }}>
                    <div><span style={{ color: T.textMain }}>RTT:</span> {searchResults.telemetry.rtt}</div>
                    {searchResults.telemetry.distance && (
                      <div><span style={{ color: T.textMain }}>Est. Distance:</span> {searchResults.telemetry.distance}</div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* RIPEstat card */}
          {searchResults.ripestat && <RipestatTelemetryCard ripestat={searchResults.ripestat} />}

          {/* ML Threat Assessment card */}
          <MLThreatCard ip={searchResults.ip || searchQuery} />

        </div>
      )}

      {!hasResults && !isSearching && (
        <div style={{ textAlign: 'center', padding: '60px 0', color: T.textMuted }}>
          <div style={{ fontSize: 48, marginBottom: 16 }}>🔍</div>
          <div style={{ fontSize: 16, fontWeight: 600, color: T.textMain, marginBottom: 8 }}>Ready to Profile a Target</div>
          <div style={{ fontSize: 13 }}>Enter any IPv4 address above to begin multi-source OSINT analysis.</div>
        </div>
      )}
    </div>
  );
}

/* ─── Main App ────────────────────────────────────────────────────────── */
export default function App() {
  /* ── Theme state ── */
  const [isDarkMode, setIsDarkMode] = useState(true);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', isDarkMode ? 'dark' : 'light');
  }, [isDarkMode]);

  /* ── Navigation state ── */
  const [activeSection, setActiveSection] = useState('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const mainRef = useRef(null);

  /* ── Shared data state ───────────────────────────────────────────── */
  const [allMapData,      setAllMapData]     = useState({});
  const [behaviorData,    setBehaviorData]   = useState({});
  const [activeMap,       setActiveMap]      = useState('combined');
  const [lastUpdated,     setLastUpdated]    = useState('Loading…');
  const [selectedCountry, setSelectedCountry] = useState(null);

  const [searchQuery,   setSearchQuery]   = useState('');
  const [searchResults, setSearchResults] = useState(null);
  const [isSearching,   setIsSearching]   = useState(false);
  const [auditTarget,   setAuditTarget]   = useState(null);

  const [dbConnected,  setDbConnected]  = useState(false);
  const [recentScans,  setRecentScans]  = useState([]);
  const [asnStats,     setAsnStats]     = useState(null);

  /* ── Data fetching ───────────────────────────────────────────────── */
  const fetchDbStatus = useCallback(() => {
    axios.get('http://127.0.0.1:8000/api/db-status')
      .then(r => setDbConnected(r.data.connected))
      .catch(() => setDbConnected(false));
  }, []);

  const fetchRecentScans = useCallback(() => {
    axios.get('http://127.0.0.1:8000/api/recent-scans')
      .then(r => {
        const items = r.data?.scans ?? r.data?.recent_scans ?? [];
        setRecentScans(Array.isArray(items) ? items : []);
      })
      .catch(() => {});
  }, []);

  const fetchAsnStats = useCallback(() => {
    axios.get('http://127.0.0.1:8000/api/analytics/asn-intelligence')
      .then(r => { if (r.data?.status === 'success') setAsnStats(r.data.data); })
      .catch(() => {});
  }, []);

  useEffect(() => {
    axios.get('http://127.0.0.1:8000/api/map-data')
      .then(r => {
        if (r.data?.status === 'success') {
          setAllMapData(r.data.data);
          setBehaviorData(r.data.behavior);
          setLastUpdated(r.data.last_updated);
        }
      })
      .catch(() => {});
    fetchDbStatus();
    fetchRecentScans();
    fetchAsnStats();

    // Refresh DB status every 30s
    const iv = setInterval(fetchDbStatus, 30000);
    return () => clearInterval(iv);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  /* ── IP search handler ───────────────────────────────────────────── */
  const handleSearch = useCallback(async (e, forceRefresh = false, targetOverride = null) => {
    if (e) e.preventDefault();
    const query = (targetOverride || searchQuery).trim();
    if (!query) return;
    setIsSearching(true);
    setSearchResults(null);
    setSearchQuery(query);
    setAuditTarget({ ip: query, forceRefresh, timestamp: Date.now() });
    try {
      const url = `http://127.0.0.1:8000/api/search-ip?ip=${query}${forceRefresh ? '&force_refresh=true' : ''}`;
      const r = await axios.get(url);
      setSearchResults(r.data.results);
      fetchDbStatus();
      fetchRecentScans();
    } catch (err) {
      console.error('Search failed', err);
    }
    setIsSearching(false);
  }, [searchQuery, fetchDbStatus, fetchRecentScans]);

  /* ── Navigation helper ───────────────────────────────────────────── */
  const navigateTo = useCallback((section) => {
    setActiveSection(section);
    if (mainRef.current) mainRef.current.scrollTop = 0;
  }, []);

  /* ── Search + navigate combo for recent scans ────────────────────── */
  const searchAndGoToIP = useCallback((ip) => {
    setSearchQuery(ip);
    navigateTo('ip_intel');
    // Trigger search after state settles
    setTimeout(() => {
      handleSearch(null, false, ip);
    }, 50);
  }, [navigateTo, handleSearch]);

  const currentMapData  = allMapData[activeMap] || [];
  const countryProfile  = selectedCountry ? behaviorData[selectedCountry] : null;
  const sidebarWidth    = sidebarCollapsed ? 62 : SIDEBAR_W;

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', backgroundColor: T.bg, fontFamily: "'Inter', 'Segoe UI', sans-serif", color: T.textMain }}>

      {/* ── SIDEBAR ─────────────────────────────────────────────────── */}
      <aside style={{
        width: sidebarWidth,
        minWidth: sidebarWidth,
        height: '100vh',
        backgroundColor: T.sidebar,
        borderRight: `1px solid ${T.border}`,
        display: 'flex',
        flexDirection: 'column',
        position: 'fixed',
        left: 0, top: 0, bottom: 0,
        zIndex: 100,
        transition: 'width 0.25s cubic-bezier(0.4,0,0.2,1)',
        overflowX: 'hidden',
      }}>
        {/* Sidebar header / logo */}
        <div style={{
          padding: sidebarCollapsed ? '16px 0' : '18px 18px',
          borderBottom: `1px solid ${T.border}`,
          display: 'flex', alignItems: 'center',
          justifyContent: sidebarCollapsed ? 'center' : 'space-between',
          minHeight: TOPBAR_H, boxSizing: 'border-box',
          flexShrink: 0,
        }}>
          {!sidebarCollapsed && (
            <div>
              <div style={{ fontWeight: 900, fontSize: 16, letterSpacing: '-0.5px' }}>
                <span style={{ color: T.accent }}>OSINT</span>
                <span style={{ color: T.textMain }}> TERMINAL</span>
              </div>
              <div style={{ fontSize: 10, color: T.textMuted, marginTop: 2, letterSpacing: '0.3px' }}>
                Threat Intelligence Platform
              </div>
            </div>
          )}
          {sidebarCollapsed && (
            <span style={{ fontSize: 18, fontWeight: 900, color: T.accent }}>⚡</span>
          )}
          <button
            onClick={() => setSidebarCollapsed(v => !v)}
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: T.textMuted, fontSize: 16, padding: 4,
              lineHeight: 1, flexShrink: 0,
            }}
            title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {sidebarCollapsed ? '›' : '‹'}
          </button>
        </div>

        {/* Nav items */}
        <nav style={{ flex: 1, padding: '10px 0', overflowY: 'auto' }}>
          {NAV.map(item => {
            const active = activeSection === item.id;
            return (
              <div
                key={item.id}
                onClick={() => navigateTo(item.id)}
                title={sidebarCollapsed ? item.label : undefined}
                style={{
                  display: 'flex', alignItems: 'center',
                  gap: 12,
                  padding: sidebarCollapsed ? '13px 0' : '11px 18px',
                  justifyContent: sidebarCollapsed ? 'center' : 'flex-start',
                  cursor: 'pointer',
                  position: 'relative',
                  backgroundColor: active ? `${item.color}14` : 'transparent',
                  borderLeft: `3px solid ${active ? item.color : 'transparent'}`,
                  transition: 'all 0.15s',
                  margin: '2px 0',
                }}
                onMouseEnter={e => { if (!active) e.currentTarget.style.backgroundColor = `${item.color}09`; }}
                onMouseLeave={e => { if (!active) e.currentTarget.style.backgroundColor = 'transparent'; }}
              >
                <span style={{ fontSize: 18, flexShrink: 0, lineHeight: 1 }}>{item.icon}</span>
                {!sidebarCollapsed && (
                  <div>
                    <div style={{ fontSize: 13, fontWeight: active ? 700 : 500, color: active ? item.color : T.textMain, letterSpacing: '-0.2px' }}>
                      {item.label}
                    </div>
                    <div style={{ fontSize: 10, color: T.textMuted, marginTop: 1 }}>{item.sub}</div>
                  </div>
                )}
                {active && !sidebarCollapsed && (
                  <span style={{ marginLeft: 'auto', width: 6, height: 6, borderRadius: '50%', backgroundColor: item.color, flexShrink: 0 }} />
                )}
              </div>
            );
          })}
        </nav>

        {/* Sidebar footer */}
        {!sidebarCollapsed && (
          <div style={{ padding: '12px 18px', borderTop: `1px solid ${T.border}`, flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: T.textMuted }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', backgroundColor: dbConnected ? T.success : T.warning, display: 'inline-block' }} />
              DynamoDB {dbConnected ? 'Connected' : 'Standby'}
            </div>
          </div>
        )}
      </aside>

      {/* ── MAIN AREA (top bar + content) ────────────────────────────── */}
      <div style={{
        marginLeft: sidebarWidth,
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        overflow: 'hidden',
        transition: 'margin-left 0.25s cubic-bezier(0.4,0,0.2,1)',
      }}>

        {/* ── TOP BAR ─────────────────────────────────────────────── */}
        <header style={{
          height: TOPBAR_H,
          minHeight: TOPBAR_H,
          backgroundColor: T.topbar,
          borderBottom: `1px solid ${T.border}`,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '0 28px',
          flexShrink: 0,
          gap: 12,
          zIndex: 50,
        }}>
          {/* Breadcrumb */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {NAV.find(n => n.id === activeSection) && (
              <>
                <span style={{ fontSize: 16 }}>{NAV.find(n => n.id === activeSection).icon}</span>
                <span style={{ fontWeight: 700, fontSize: 15, color: T.textMain }}>
                  {NAV.find(n => n.id === activeSection).label}
                </span>
                <span style={{ color: T.border }}>·</span>
                <span style={{ fontSize: 12, color: T.textMuted }}>
                  {NAV.find(n => n.id === activeSection).sub}
                </span>
              </>
            )}
          </div>

          {/* Right: status pills + quick actions */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
            {/* Theme Toggle */}
            <button
              onClick={() => setIsDarkMode(d => !d)}
              style={{
                background: 'none', border: `1px solid ${T.border}`, borderRadius: 6, cursor: 'pointer',
                fontSize: 16, padding: '5px 10px', color: T.textMain,
                backgroundColor: T.cardSub,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                transition: 'all 0.2s',
              }}
              title={isDarkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            >
              {isDarkMode ? '☀️' : '🌙'}
            </button>

            {/* Active section indicator chips */}
            {activeSection !== 'ip_intel' && (
              <button
                onClick={() => navigateTo('ip_intel')}
                style={{
                  padding: '6px 14px', fontSize: 12, fontWeight: 600,
                  backgroundColor: T.cardSub, color: T.cyan,
                  border: `1px solid ${T.cyan}44`, borderRadius: 6,
                  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
                }}
              >
                🔍 Scan IP
              </button>
            )}
            <div style={{
              backgroundColor: T.cardSub, padding: '6px 12px', borderRadius: 6,
              border: `1px solid ${dbConnected ? T.success : T.warning}44`,
              display: 'flex', alignItems: 'center', gap: 6, fontSize: 12,
            }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', backgroundColor: dbConnected ? T.success : T.warning, display: 'inline-block' }} />
              <span style={{ color: dbConnected ? T.success : T.warning, fontWeight: 600 }}>
                {dbConnected ? 'DB Live' : 'DB Standby'}
              </span>
            </div>
            <div style={{ fontSize: 11, color: T.textMuted, textAlign: 'right' }}>
              <div style={{ fontWeight: 600, color: T.success, fontSize: 12 }}>● {lastUpdated}</div>
            </div>
          </div>
        </header>

        {/* ── SCROLLABLE CONTENT AREA ──────────────────────────────── */}
        {/*
          All sections are mounted simultaneously (display: none when inactive)
          so their internal state (ASN data, etc.) is preserved on tab switch.
        */}
        <main
          ref={mainRef}
          style={{ flex: 1, overflowY: 'auto', backgroundColor: T.bg }}
        >
          {/* ── DASHBOARD ─────────────────────────────────────────── */}
          <div style={{ display: activeSection === 'dashboard' ? 'block' : 'none' }}>
            <SectionBanner
              icon="📊" title="Dashboard" color={T.accent}
              subtitle="System overview, live stats, recent activity, and quick access to all features."
              badge={asnStats ? `${(asnStats.total_analyzed_ips ?? 0).toLocaleString()} Threat IPs Tracked` : undefined}
            />
            <DashboardSection
              dbConnected={dbConnected}
              lastUpdated={lastUpdated}
              asnStats={asnStats}
              recentScans={recentScans}
              onNavigate={navigateTo}
              onSearchIP={searchAndGoToIP}
            />
          </div>

          {/* ── IP INTELLIGENCE ──────────────────────────────────── */}
          <div style={{ display: activeSection === 'ip_intel' ? 'block' : 'none' }}>
            <SectionBanner
              icon="🔍" title="IP Intelligence" color={T.cyan}
              subtitle="Multi-source IP profiling: geography consensus, behavioral threat flags, BGP/ASN routing, live telemetry, and RIPEstat BGP analysis."
              badge="4 GeoIP Providers · FireHOL Feeds · RIPEstat BGP"
              action={
                searchResults && (
                  <span style={{
                    fontSize: 12, padding: '4px 12px', borderRadius: 5, fontWeight: 700,
                    backgroundColor: searchResults.behavioral_flags?.length ? '#450a0a' : '#052e16',
                    color: searchResults.behavioral_flags?.length ? T.danger : T.success,
                    border: `1px solid ${searchResults.behavioral_flags?.length ? T.danger : T.success}55`,
                  }}>
                    {searchResults.behavioral_flags?.length
                      ? `⚠️ ${searchResults.behavioral_flags.length} Flag${searchResults.behavioral_flags.length > 1 ? 's' : ''} · ${searchQuery}`
                      : `✅ Clean · ${searchQuery}`}
                  </span>
                )
              }
            />
            <IPIntelSection
              searchQuery={searchQuery}
              setSearchQuery={setSearchQuery}
              searchResults={searchResults}
              isSearching={isSearching}
              handleSearch={handleSearch}
            />
          </div>

          {/* ── FORENSIC AUDIT ────────────────────────────────────── */}
          <div style={{ display: activeSection === 'forensic_audit' ? 'block' : 'none' }}>
            <SectionBanner
              icon="🔬" title="Forensic Audit" color={T.purple}
              subtitle="Deep VPN & infrastructure audit: multi-database classification, physics-based GeoIP validation, traceroute path analysis, and consensus scoring."
              badge="VPN Detection · BGP Profiling · Traceroute"
            />
            <div style={{ padding: '24px 32px' }}>
              <VpnAudit triggerTarget={auditTarget} />
            </div>
          </div>

          {/* ── ASN THREAT INTELLIGENCE ───────────────────────────── */}
          <div style={{ display: activeSection === 'asn_intel' ? 'block' : 'none' }}>
            <SectionBanner
              icon="🛡️" title="ASN Threat Intelligence" color={T.danger}
              subtitle="Per-ASN deep analytics: CIDR prefix clustering, observed threat density, Top-K concentration, category heatmaps, and auto-generated intelligence findings."
              badge={asnStats ? `${asnStats.total_asns ?? 0} ASNs · ${(asnStats.total_analyzed_ips ?? 0).toLocaleString()} Classified IPs` : 'Analytics Engine'}
            />
            <div style={{ padding: '24px 32px' }}>
              <ASNIntelligence />
            </div>
          </div>

          {/* ── GLOBAL THREAT MAP ─────────────────────────────────── */}
          <div style={{ display: activeSection === 'threat_map' ? 'block' : 'none' }}>
            <SectionBanner
              icon="🗺️" title="Global Threat Map" color={T.success}
              subtitle="Geospatial distribution of threat infrastructure across 4 GeoIP providers. Click any country to view behavioral attack vector profile."
              badge="GeoLite2 · IP2Location · IPDeny · IPIP"
              action={
                <select
                  value={activeMap}
                  onChange={e => setActiveMap(e.target.value)}
                  style={{
                    padding: '8px 14px', backgroundColor: T.cardSub, border: `1px solid ${T.border}`,
                    borderRadius: 7, color: T.textMain, fontSize: 13, cursor: 'pointer', outline: 'none',
                  }}
                >
                  <option value="combined">Total Global Consensus</option>
                  <option value="geolite2">MaxMind GeoLite2</option>
                  <option value="ip2location">IP2Location</option>
                  <option value="ipdeny">IPDeny</option>
                  <option value="ipip">IPIP Intelligence</option>
                </select>
              }
            />

            <div style={{ padding: '24px 32px', display: 'grid', gridTemplateColumns: '1fr 360px', gap: 24, alignItems: 'start' }}>
              {/* Map */}
              <div style={{ backgroundColor: T.card, borderRadius: 12, border: `1px solid ${T.border}`, overflow: 'hidden' }}>
                <div style={{ padding: '16px 20px', borderBottom: `1px solid ${T.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: 14, color: T.textMain }}>Global Infrastructure Heatmap</div>
                    <div style={{ fontSize: 11, color: T.textMuted, marginTop: 2 }}>Hover to view density · Click country to profile</div>
                  </div>
                  <span style={{ fontSize: 11, padding: '3px 9px', borderRadius: 4, fontWeight: 700, backgroundColor: '#1B2E1E', color: T.success, border: `1px solid ${T.success}44` }}>
                    {activeMap === 'combined' ? '🌐 Consensus View' : activeMap.toUpperCase()}
                  </span>
                </div>
                <MapChart data={currentMapData} onCountrySelect={setSelectedCountry} />
              </div>

              {/* Country profile panel */}
              <div style={{ backgroundColor: T.card, borderRadius: 12, border: `1px solid ${T.border}`, padding: '20px', minHeight: 400 }}>
                <div style={{ fontWeight: 700, fontSize: 14, color: T.textMain, marginBottom: 16, paddingBottom: 12, borderBottom: `1px solid ${T.border}` }}>
                  Country Threat Profile
                </div>

                {!selectedCountry && (
                  <div style={{ color: T.textMuted, textAlign: 'center', marginTop: 80, lineHeight: 1.7, fontSize: 14 }}>
                    <div style={{ fontSize: 36, marginBottom: 16 }}>🗺️</div>
                    Hover over the map to view network density.<br /><br />
                    Click any region to analyze its behavioral attack vectors.
                  </div>
                )}

                {selectedCountry && countryProfile && (
                  <div>
                    <h2 style={{ color: T.accent, margin: '0 0 4px', fontSize: 24 }}>{selectedCountry}</h2>
                    <p style={{ color: T.textMuted, fontSize: 13, margin: '0 0 20px', textTransform: 'uppercase', letterSpacing: 1 }}>Identified Threat Vectors</p>
                    {Object.entries(countryProfile).map(([category, count]) => (
                      <div key={category} style={{ marginBottom: 14 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: 13, textTransform: 'uppercase', fontWeight: 600 }}>
                          <span style={{ color: T.textMuted }}>{category}</span>
                          <span style={{ color: count > 0 ? T.danger : T.success }}>{count.toLocaleString()}</span>
                        </div>
                        <div style={{ width: '100%', height: 6, backgroundColor: T.bg, borderRadius: 3, overflow: 'hidden' }}>
                          <div style={{
                            width: `${Math.min((count / 1000) * 100, 100)}%`, height: '100%',
                            backgroundColor: count > 100 ? T.danger : count > 0 ? '#F97316' : T.success,
                            transition: 'width 0.6s cubic-bezier(0.4,0,0.2,1)',
                          }} />
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {selectedCountry && !countryProfile && (
                  <div style={{ color: T.success, textAlign: 'center', marginTop: 80, lineHeight: 1.6, fontSize: 15, fontWeight: 600 }}>
                    ✅ Database shows no significant malicious infrastructure for <br />
                    <span style={{ color: T.textMain }}>{selectedCountry}</span>.
                  </div>
                )}
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}