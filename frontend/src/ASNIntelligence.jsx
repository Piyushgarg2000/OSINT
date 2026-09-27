import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import axios from 'axios';

const theme = {
  bg:       '#020617',
  card:     '#0F172A',
  cardSub:  '#1E293B',
  border:   '#334155',
  textMain: '#F8FAFC',
  textMuted:'#94A3B8',
  accent:   '#38BDF8',
  cyan:     '#06B6D4',
  success:  '#10B981',
  danger:   '#EF4444',
  warning:  '#F59E0B',
  purple:   '#8B5CF6',
  orange:   '#F97316',
};

const CATEGORY_COLORS = {
  attacks:       '#EF4444',
  malware:       '#8B5CF6',
  spam:          '#F59E0B',
  abuse:         '#F97316',
  anonymizers:   '#06B6D4',
  reputation:    '#EC4899',
  unroutable:    '#64748B',
  organizations: '#10B981',
};

const INFRA_META = {
  DATACENTER: {
    icon: '🏢',
    label: 'Datacenter / VPN Hosting',
    color: '#EF4444',
    desc: 'Cloud servers, VPS, VPN exit nodes, C2 infrastructure',
  },
  RESIDENTIAL: {
    icon: '🏠',
    label: 'Residential / ISP',
    color: '#38BDF8',
    desc: 'Home networks, botnet-infected endpoints, IoT devices',
  },
  ANYCAST_CDN: {
    icon: '🌐',
    label: 'Anycast CDN / Edge',
    color: '#10B981',
    desc: 'CDN abuse, shared edge proxies, distributed services',
  },
};

const SEVERITY_META = {
  CRITICAL: { color: '#EF4444', bg: '#450a0a', icon: '🚨', label: 'Critical' },
  HIGH:     { color: '#F97316', bg: '#431407', icon: '⚠️', label: 'High' },
  MEDIUM:   { color: '#F59E0B', bg: '#422006', icon: '●', label: 'Medium' },
  INFO:     { color: '#38BDF8', bg: '#082030', icon: 'ℹ️', label: 'Info' },
};

const DENSITY_META = {
  VERY_HIGH: { color: '#EF4444', label: 'Very High' },
  HIGH:      { color: '#F97316', label: 'High' },
  MEDIUM:    { color: '#F59E0B', label: 'Medium' },
  LOW:       { color: '#10B981', label: 'Low' },
  UNKNOWN:   { color: '#64748B', label: 'N/A' },
};

/* ─── Shared Utility Components ───────────────────────────────────────────── */

function CategoryBar({ counts, percentages }) {
  if (!counts || Object.keys(counts).length === 0) {
    return <span style={{ color: theme.textMuted, fontSize: '11px' }}>No threat data</span>;
  }
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
      <div style={{ display: 'flex', height: '6px', borderRadius: '3px', overflow: 'hidden', width: '100%', backgroundColor: '#020617' }}>
        {sorted.map(([cat, count]) => (
          <div
            key={cat}
            title={`${cat}: ${count} IPs (${percentages?.[cat] ?? 0}%)`}
            style={{ width: `${(count / total) * 100}%`, backgroundColor: CATEGORY_COLORS[cat] || '#64748B', transition: 'width 0.6s ease' }}
          />
        ))}
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '4px' }}>
        {sorted.slice(0, 4).map(([cat]) => (
          <span key={cat} style={{
            fontSize: '10px', padding: '1px 6px', borderRadius: '3px',
            backgroundColor: `${CATEGORY_COLORS[cat] || '#64748B'}22`,
            color: CATEGORY_COLORS[cat] || '#64748B',
            border: `1px solid ${CATEGORY_COLORS[cat] || '#64748B'}55`,
            fontWeight: '700', textTransform: 'capitalize',
          }}>
            {cat} {percentages?.[cat] ?? 0}%
          </span>
        ))}
      </div>
    </div>
  );
}

function RankBadge({ rank }) {
  const colors = ['#F59E0B', '#94A3B8', '#B45309'];
  const c = rank <= 3 ? colors[rank - 1] : theme.textMuted;
  return (
    <span style={{ fontFamily: 'monospace', fontWeight: '800', fontSize: '14px', color: c, minWidth: '24px', display: 'inline-block', textAlign: 'center' }}>
      {rank <= 3 ? ['🥇', '🥈', '🥉'][rank - 1] : `#${rank}`}
    </span>
  );
}

function InfraMeterBar({ distribution }) {
  if (!distribution || Object.keys(distribution).length === 0) return null;
  const keys = ['DATACENTER', 'RESIDENTIAL', 'ANYCAST_CDN'];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      <div style={{ display: 'flex', height: '20px', borderRadius: '6px', overflow: 'hidden', border: `1px solid ${theme.border}` }}>
        {keys.map(key => {
          const info = distribution[key];
          if (!info || !info.count) return null;
          const meta = INFRA_META[key] || { color: theme.accent };
          return (
            <div key={key} title={`${key}: ${info.count} IPs (${info.percentage}%)`}
              style={{ width: `${info.percentage}%`, backgroundColor: meta.color, opacity: 0.85,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: '10px', fontWeight: '700', color: '#000', overflow: 'hidden', whiteSpace: 'nowrap' }}>
              {info.percentage > 8 ? `${info.percentage}%` : ''}
            </div>
          );
        })}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px' }}>
        {keys.map(key => {
          const info = distribution[key];
          if (!info) return null;
          const meta = INFRA_META[key] || { icon: '❓', label: key, color: theme.accent, desc: '' };
          return (
            <div key={key} style={{ backgroundColor: theme.cardSub, borderRadius: '8px', padding: '14px', border: `1px solid ${meta.color}44` }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <span style={{ fontSize: '18px' }}>{meta.icon}</span>
                <span style={{ fontWeight: '700', fontSize: '13px', color: meta.color }}>{meta.label}</span>
              </div>
              <div style={{ fontSize: '22px', fontWeight: '800', color: theme.textMain, marginBottom: '4px' }}>
                {info.count.toLocaleString()}
                <span style={{ fontSize: '13px', fontWeight: '400', color: theme.textMuted, marginLeft: '6px' }}>({info.percentage}%)</span>
              </div>
              <div style={{ fontSize: '11px', color: theme.textMuted }}>{meta.desc}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ─── Intelligence Modal Sub-components ──────────────────────────────────── */

function MetricCard({ label, value, sub, color, icon }) {
  return (
    <div style={{ backgroundColor: theme.cardSub, padding: '14px', borderRadius: '8px', border: `1px solid ${theme.border}` }}>
      <div style={{ fontSize: '10px', color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>{icon} {label}</div>
      <div style={{ fontSize: '20px', fontWeight: '800', color: color || theme.textMain }}>{value}</div>
      {sub && <div style={{ fontSize: '10px', color: theme.textMuted, marginTop: '3px' }}>{sub}</div>}
    </div>
  );
}

function SectionHeader({ title, subtitle }) {
  return (
    <div style={{ marginBottom: '14px', paddingBottom: '10px', borderBottom: `1px solid ${theme.border}` }}>
      <div style={{ fontSize: '13px', fontWeight: '700', color: theme.accent }}>{title}</div>
      {subtitle && <div style={{ fontSize: '11px', color: theme.textMuted, marginTop: '3px' }}>{subtitle}</div>}
    </div>
  );
}

function EvidencePill({ text, color }) {
  return (
    <span style={{
      fontSize: '10px', padding: '2px 8px', borderRadius: '10px', fontFamily: 'monospace',
      backgroundColor: `${color || theme.cyan}18`, color: color || theme.cyan,
      border: `1px solid ${color || theme.cyan}44`, whiteSpace: 'nowrap', fontWeight: '600',
    }}>{text}</span>
  );
}

function FindingCard({ finding, defaultExpanded }) {
  const [expanded, setExpanded] = useState(defaultExpanded || false);
  const meta = SEVERITY_META[finding.severity] || SEVERITY_META.INFO;
  return (
    <div style={{
      backgroundColor: meta.bg, borderRadius: '8px', border: `1px solid ${meta.color}44`,
      borderLeft: `3px solid ${meta.color}`, marginBottom: '8px', overflow: 'hidden',
    }}>
      <div
        onClick={() => setExpanded(v => !v)}
        style={{ padding: '12px 14px', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '10px' }}
      >
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span style={{ fontSize: '13px' }}>{meta.icon}</span>
            <span style={{
              fontSize: '10px', padding: '1px 6px', borderRadius: '3px', fontWeight: '700',
              backgroundColor: `${meta.color}22`, color: meta.color,
            }}>{meta.label}</span>
            <span style={{ fontWeight: '700', fontSize: '12px', color: theme.textMain }}>{finding.title}</span>
          </div>
          <div style={{ fontSize: '11px', color: theme.textMuted, lineHeight: '1.5' }}>{finding.description}</div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {finding.value !== undefined && (
            <span style={{ fontFamily: 'monospace', fontWeight: '800', color: meta.color, fontSize: '15px', whiteSpace: 'nowrap' }}>
              {typeof finding.value === 'number' ? `${finding.value}%` : finding.value}
            </span>
          )}
          <span style={{ color: theme.textMuted, fontSize: '12px' }}>{expanded ? '▲' : '▼'}</span>
        </div>
      </div>
      {expanded && finding.evidence && finding.evidence.length > 0 && (
        <div style={{ padding: '10px 14px 12px', borderTop: `1px solid ${meta.color}22` }}>
          <div style={{ fontSize: '10px', color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>
            📋 Evidence ({finding.evidence.length} item{finding.evidence.length > 1 ? 's' : ''})
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
            {finding.evidence.map((ev, i) => {
              const text = ev.prefix
                ? `${ev.prefix} → ${ev.count} IPs${ev.density != null ? ` (${ev.density}%)` : ''}${ev.pct != null ? ` · ${ev.pct}% share` : ''}`
                : ev.category
                  ? `${ev.category}: ${ev.count} IPs (${ev.pct}%)`
                  : ev.country
                    ? `${ev.country}: ${ev.count} IPs (${ev.pct}%)`
                    : ev.categories
                      ? `${ev.prefix} [${ev.categories.join(', ')}]`
                      : ev.note || JSON.stringify(ev);
              return <EvidencePill key={i} text={text} color={meta.color} />;
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function PrefixTable({ prefixes, total }) {
  const [sortCol, setSortCol] = useState('count');
  const [showAll, setShowAll] = useState(false);

  const sorted = useMemo(() => {
    return [...prefixes].sort((a, b) => {
      if (sortCol === 'count') return b.threat_ip_count - a.threat_ip_count;
      if (sortCol === 'density') return (b.threat_density_pct ?? -1) - (a.threat_density_pct ?? -1);
      if (sortCol === 'prefix') return a.prefix.localeCompare(b.prefix);
      return 0;
    });
  }, [prefixes, sortCol]);

  const displayed = showAll ? sorted : sorted.slice(0, 15);

  const HeaderCell = ({ col, label, align = 'left' }) => (
    <th
      onClick={() => setSortCol(col)}
      style={{ padding: '8px 10px', textAlign: align, cursor: 'pointer', userSelect: 'none',
        color: sortCol === col ? theme.accent : theme.textMuted,
        fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.5px',
        whiteSpace: 'nowrap', borderBottom: `1px solid ${theme.border}` }}
    >
      {label} {sortCol === col ? '▼' : ''}
    </th>
  );

  return (
    <div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
          <thead>
            <tr>
              <HeaderCell col="prefix" label="Network Prefix" />
              <HeaderCell col="count" label="Threat IPs" align="right" />
              <th style={{ padding: '8px 10px', fontSize: '10px', color: theme.textMuted, textTransform: 'uppercase', borderBottom: `1px solid ${theme.border}` }}>Prefix Size</th>
              <HeaderCell col="density" label="Obs. Density" align="right" />
              <th style={{ padding: '8px 10px', fontSize: '10px', color: theme.textMuted, textTransform: 'uppercase', borderBottom: `1px solid ${theme.border}` }}>Density Class</th>
              <th style={{ padding: '8px 10px', fontSize: '10px', color: theme.textMuted, textTransform: 'uppercase', borderBottom: `1px solid ${theme.border}` }}>Dominant Category</th>
              <th style={{ padding: '8px 10px', fontSize: '10px', color: theme.textMuted, textTransform: 'uppercase', borderBottom: `1px solid ${theme.border}` }}>Categories</th>
              <th style={{ padding: '8px 10px', fontSize: '10px', color: theme.textMuted, textTransform: 'uppercase', borderBottom: `1px solid ${theme.border}` }}>% of ASN</th>
            </tr>
          </thead>
          <tbody>
            {displayed.map((p, idx) => {
              const dm = DENSITY_META[p.density_class] || DENSITY_META.UNKNOWN;
              const pct_of_asn = total > 0 ? ((p.threat_ip_count / total) * 100).toFixed(1) : '0';
              const isUnavailable = p.prefix === 'Prefix Unavailable';
              return (
                <tr key={p.prefix + idx} style={{ borderBottom: `1px solid ${theme.border}22`, backgroundColor: idx % 2 === 0 ? 'transparent' : `${theme.cardSub}55` }}>
                  <td style={{ padding: '10px 10px', fontFamily: 'monospace', fontWeight: '600', color: isUnavailable ? theme.textMuted : theme.cyan, fontSize: '12px' }}>
                    {p.prefix}
                  </td>
                  <td style={{ padding: '10px 10px', textAlign: 'right', fontWeight: '800', color: theme.danger, fontFamily: 'monospace', fontSize: '13px' }}>
                    {p.threat_ip_count.toLocaleString()}
                  </td>
                  <td style={{ padding: '10px 10px', color: theme.textMuted, fontFamily: 'monospace', fontSize: '11px' }}>
                    {isUnavailable ? '—' : p.prefix_size > 0 ? p.prefix_size.toLocaleString() : '—'}
                  </td>
                  <td style={{ padding: '10px 10px', textAlign: 'right', fontFamily: 'monospace', fontWeight: '700', color: dm.color, fontSize: '12px' }}>
                    {p.threat_density_pct != null ? `${p.threat_density_pct.toFixed(2)}%` : '—'}
                  </td>
                  <td style={{ padding: '10px 10px' }}>
                    {p.density_class !== 'UNKNOWN' ? (
                      <span style={{
                        fontSize: '10px', padding: '2px 7px', borderRadius: '4px', fontWeight: '700',
                        backgroundColor: `${dm.color}20`, color: dm.color, border: `1px solid ${dm.color}44`,
                      }}>{dm.label}</span>
                    ) : <span style={{ color: theme.textMuted, fontSize: '11px' }}>—</span>}
                  </td>
                  <td style={{ padding: '10px 10px', textTransform: 'capitalize', fontWeight: '600', fontSize: '11px',
                    color: CATEGORY_COLORS[p.dominant_category] || theme.textMuted }}>
                    {p.dominant_category || '—'}
                  </td>
                  <td style={{ padding: '10px 10px' }}>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '3px' }}>
                      {Object.keys(p.category_counts || {}).slice(0, 3).map(cat => (
                        <span key={cat} style={{
                          fontSize: '9px', padding: '1px 5px', borderRadius: '3px',
                          backgroundColor: `${CATEGORY_COLORS[cat] || '#64748B'}22`,
                          color: CATEGORY_COLORS[cat] || '#64748B',
                          border: `1px solid ${CATEGORY_COLORS[cat] || '#64748B'}44`,
                          fontWeight: '700', textTransform: 'capitalize',
                        }}>{cat}</span>
                      ))}
                    </div>
                  </td>
                  <td style={{ padding: '10px 10px', color: theme.textMuted, fontFamily: 'monospace', fontSize: '11px' }}>
                    {pct_of_asn}%
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {sorted.length > 15 && (
        <button onClick={() => setShowAll(v => !v)} style={{
          marginTop: '10px', padding: '7px 16px', fontSize: '12px', fontWeight: '600',
          backgroundColor: theme.cardSub, color: theme.accent,
          border: `1px solid ${theme.accent}55`, borderRadius: '6px', cursor: 'pointer', width: '100%',
        }}>
          {showAll ? `▲ Show Top 15 Only` : `▼ Show All ${sorted.length} Prefixes`}
        </button>
      )}
    </div>
  );
}

function ConcentrationChart({ concentration, total }) {
  if (!concentration) return null;
  const evidence = concentration.top_prefixes_evidence || [];
  const topK = [1, 3, 5, 10].filter(k => k <= evidence.length);
  const cumulativeCounts = topK.map(k =>
    evidence.slice(0, k).reduce((s, e) => s + e.count, 0)
  );
  const pcts = [concentration.top1, concentration.top3, concentration.top5, concentration.top10];
  const labels = ['Top 1', 'Top 3', 'Top 5', 'Top 10'];

  const classColors = {
    HIGHLY_CONCENTRATED:   theme.danger,
    MODERATELY_CONCENTRATED: theme.warning,
    DISTRIBUTED:           theme.success,
  };
  const classColor = classColors[concentration.classification] || theme.textMuted;

  return (
    <div>
      {/* Classification badge */}
      <div style={{ marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '10px' }}>
        <span style={{
          padding: '4px 12px', borderRadius: '6px', fontWeight: '700', fontSize: '12px',
          backgroundColor: `${classColor}20`, color: classColor, border: `1px solid ${classColor}44`,
        }}>
          {concentration.classification.replace('_', ' ')}
        </span>
        <span style={{ color: theme.textMuted, fontSize: '11px' }}>
          Top-5 concentration: <strong style={{ color: classColor }}>{concentration.top5}%</strong> of {total.toLocaleString()} observed threat IPs
        </span>
      </div>

      {/* Top-K bars */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '18px' }}>
        {labels.map((label, i) => {
          const pct = pcts[i] || 0;
          const barColor = pct >= 75 ? theme.danger : pct >= 50 ? theme.warning : theme.success;
          return (
            <div key={label}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginBottom: '4px' }}>
                <span style={{ color: theme.textMuted, fontWeight: '600' }}>{label} Prefixes</span>
                <span style={{ fontFamily: 'monospace', fontWeight: '800', color: barColor }}>{pct}%</span>
              </div>
              <div style={{ width: '100%', height: '8px', backgroundColor: theme.bg, borderRadius: '4px', overflow: 'hidden' }}>
                <div style={{ width: `${pct}%`, height: '100%', backgroundColor: barColor, borderRadius: '4px', transition: 'width 0.8s ease' }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Evidence table */}
      {evidence.length > 0 && (
        <div>
          <div style={{ fontSize: '11px', color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px', fontWeight: '700' }}>
            Top-{evidence.length} Prefix Evidence
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px' }}>
            <thead>
              <tr style={{ color: theme.textMuted, fontSize: '10px', textTransform: 'uppercase', borderBottom: `1px solid ${theme.border}` }}>
                <th style={{ padding: '6px 8px', textAlign: 'left' }}>Rank</th>
                <th style={{ padding: '6px 8px', textAlign: 'left' }}>Prefix</th>
                <th style={{ padding: '6px 8px', textAlign: 'right' }}>Threat IPs</th>
                <th style={{ padding: '6px 8px', textAlign: 'right' }}>Share of ASN</th>
              </tr>
            </thead>
            <tbody>
              {evidence.map((e, i) => (
                <tr key={i} style={{ borderBottom: `1px solid ${theme.border}22` }}>
                  <td style={{ padding: '7px 8px' }}><RankBadge rank={e.rank} /></td>
                  <td style={{ padding: '7px 8px', fontFamily: 'monospace', color: theme.cyan, fontWeight: '600' }}>{e.prefix}</td>
                  <td style={{ padding: '7px 8px', textAlign: 'right', color: theme.danger, fontWeight: '700', fontFamily: 'monospace' }}>{e.count.toLocaleString()}</td>
                  <td style={{ padding: '7px 8px', textAlign: 'right', color: theme.textMuted, fontFamily: 'monospace' }}>{e.pct}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function CategoryHeatmap({ heatmap }) {
  if (!heatmap || !heatmap.rows || heatmap.rows.length === 0) {
    return <div style={{ color: theme.textMuted, fontSize: '12px' }}>No heatmap data available.</div>;
  }
  const { categories, rows } = heatmap;

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ borderCollapse: 'collapse', fontSize: '11px', width: '100%' }}>
        <thead>
          <tr>
            <th style={{ padding: '8px 10px', textAlign: 'left', fontSize: '10px', color: theme.textMuted, textTransform: 'uppercase', borderBottom: `1px solid ${theme.border}`, minWidth: '150px' }}>
              Prefix
            </th>
            <th style={{ padding: '8px 8px', textAlign: 'right', fontSize: '10px', color: theme.textMuted, textTransform: 'uppercase', borderBottom: `1px solid ${theme.border}`, whiteSpace: 'nowrap' }}>
              IPs
            </th>
            {categories.map(cat => (
              <th key={cat} style={{
                padding: '8px 8px', textAlign: 'center', fontSize: '10px',
                color: CATEGORY_COLORS[cat] || theme.textMuted,
                textTransform: 'capitalize', borderBottom: `1px solid ${theme.border}`,
                whiteSpace: 'nowrap', fontWeight: '700',
              }}>{cat}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={row.prefix} style={{ borderBottom: `1px solid ${theme.border}22` }}>
              <td style={{ padding: '8px 10px', fontFamily: 'monospace', color: row.prefix === 'Prefix Unavailable' ? theme.textMuted : theme.cyan, fontWeight: '600', fontSize: '11px' }}>
                {row.prefix}
              </td>
              <td style={{ padding: '8px 8px', textAlign: 'right', color: theme.danger, fontWeight: '700', fontFamily: 'monospace' }}>
                {row.threat_ip_count}
              </td>
              {categories.map(cat => {
                const cell = row.cells[cat] || { count: 0, pct: 0 };
                const catColor = CATEGORY_COLORS[cat] || '#64748B';
                const intensity = Math.min(cell.pct, 100);
                const bg = intensity > 0 ? `${catColor}${Math.round(intensity * 2.55).toString(16).padStart(2, '0')}` : 'transparent';
                return (
                  <td key={cat} style={{
                    padding: '8px 8px', textAlign: 'center',
                    backgroundColor: bg,
                    color: intensity > 30 ? '#fff' : cell.count > 0 ? catColor : theme.textMuted,
                    fontFamily: 'monospace', fontWeight: cell.count > 0 ? '700' : '400', fontSize: '11px',
                    borderLeft: `1px solid ${theme.border}22`,
                  }}
                    title={`${cat} in ${row.prefix}: ${cell.count} IPs (${cell.pct}%)`}
                  >
                    {cell.count > 0 ? `${cell.pct}%` : '—'}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ fontSize: '10px', color: theme.textMuted, marginTop: '10px', fontStyle: 'italic' }}>
        Cell color intensity corresponds to category percentage within each prefix.
        Values are empirical category proportions, not probabilities.
      </div>
    </div>
  );
}

function GeographyBars({ geoData }) {
  if (!geoData || geoData.length === 0) {
    return <div style={{ color: theme.textMuted, fontSize: '12px' }}>No geographic data available.</div>;
  }
  const maxCount = geoData[0].count;
  const topShown = geoData.slice(0, 15);

  return (
    <div>
      <div style={{ fontSize: '10px', color: theme.textMuted, marginBottom: '12px', fontStyle: 'italic' }}>
        Note: Geographic location reflects IP registration or infrastructure geolocation, not attacker origin.
      </div>
      {topShown.map((item, i) => (
        <div key={item.country} style={{ marginBottom: '8px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginBottom: '3px' }}>
            <span style={{ color: i < 3 ? theme.textMain : theme.textMuted, fontWeight: i < 3 ? '700' : '400' }}>
              {item.country}
            </span>
            <span style={{ fontFamily: 'monospace', color: theme.accent, fontWeight: '700' }}>
              {item.count.toLocaleString()} <span style={{ color: theme.textMuted, fontWeight: '400' }}>({item.pct}%)</span>
            </span>
          </div>
          <div style={{ width: '100%', height: '6px', backgroundColor: theme.bg, borderRadius: '3px', overflow: 'hidden' }}>
            <div style={{
              width: `${(item.count / maxCount) * 100}%`, height: '100%',
              backgroundColor: i === 0 ? theme.danger : i < 3 ? theme.warning : theme.accent,
              borderRadius: '3px', transition: 'width 0.8s ease',
            }} />
          </div>
        </div>
      ))}
      {geoData.length > 15 && (
        <div style={{ fontSize: '11px', color: theme.textMuted, marginTop: '8px', fontStyle: 'italic' }}>
          +{geoData.length - 15} more countries
        </div>
      )}
    </div>
  );
}

function TemporalAnalysis({ temporal }) {
  if (!temporal) return null;
  if (!temporal.available) {
    return (
      <div style={{ padding: '20px', backgroundColor: theme.cardSub, borderRadius: '8px', border: `1px solid ${theme.border}` }}>
        <div style={{ color: theme.textMuted, fontSize: '13px' }}>
          📅 {temporal.reason || 'Historical persistence analysis unavailable for this dataset.'}
        </div>
      </div>
    );
  }

  const bars = [
    { label: 'Persistent (>30 days)', count: temporal.persistent_count, pct: temporal.persistent_pct, color: theme.danger },
    { label: 'Short-term (7–30 days)', count: temporal.short_term_count, pct: temporal.short_term_pct, color: theme.warning },
    { label: 'Transient (<7 days)', count: temporal.transient_count, pct: temporal.transient_pct, color: theme.success },
  ];

  return (
    <div>
      <div style={{ fontSize: '10px', color: theme.textMuted, marginBottom: '14px', lineHeight: '1.5', fontStyle: 'italic', padding: '10px', backgroundColor: theme.cardSub, borderRadius: '6px', border: `1px solid ${theme.border}` }}>
        📅 <strong>Note:</strong> {temporal.note}
        {temporal.median_age_days != null && (
          <span style={{ marginLeft: '6px' }}>· Median age: <strong style={{ color: theme.accent }}>{temporal.median_age_days} days</strong></span>
        )}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {bars.map(bar => (
          <div key={bar.label}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}>
              <span style={{ color: theme.textMuted }}>{bar.label}</span>
              <span style={{ fontFamily: 'monospace', fontWeight: '800', color: bar.color }}>
                {bar.count.toLocaleString()} <span style={{ color: theme.textMuted, fontSize: '10px' }}>({bar.pct}%)</span>
              </span>
            </div>
            <div style={{ width: '100%', height: '10px', backgroundColor: theme.bg, borderRadius: '5px', overflow: 'hidden' }}>
              <div style={{ width: `${bar.pct}%`, height: '100%', backgroundColor: bar.color, borderRadius: '5px', transition: 'width 0.8s ease' }} />
            </div>
          </div>
        ))}
      </div>
      <div style={{ marginTop: '12px', fontSize: '11px', color: theme.textMuted }}>
        Analysed: {temporal.total_timestamped.toLocaleString()} IPs with timestamps
        {temporal.no_timestamp_count > 0 && ` · ${temporal.no_timestamp_count} IPs missing timestamp`}
        {temporal.as_of && ` · As of ${temporal.as_of}`}
      </div>
    </div>
  );
}

function CategoryDistribution({ catDist, total }) {
  if (!catDist || catDist.length === 0) return null;
  return (
    <div>
      <div style={{ fontSize: '10px', color: theme.textMuted, marginBottom: '12px', fontStyle: 'italic' }}>
        Observed category share = observed IPs in category / total observed threat IPs for this ASN.
        This is an empirical proportion, not a predictive probability.
      </div>
      {catDist.map(item => {
        const color = CATEGORY_COLORS[item.category] || '#64748B';
        return (
          <div key={item.category} style={{ backgroundColor: theme.cardSub, padding: '10px 14px', borderRadius: '6px', border: `1px solid ${theme.border}`, marginBottom: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px', fontSize: '12px' }}>
              <span style={{ fontWeight: '700', textTransform: 'capitalize', color: color }}>
                {item.category}
              </span>
              <span style={{ color: theme.textMain, fontWeight: '700' }}>
                {item.count.toLocaleString()} IPs <span style={{ color: theme.textMuted, fontWeight: '400' }}>({item.share_pct}%)</span>
              </span>
            </div>
            <div style={{ width: '100%', height: '6px', backgroundColor: theme.bg, borderRadius: '3px', overflow: 'hidden' }}>
              <div style={{ width: `${item.share_pct}%`, height: '100%', backgroundColor: color, borderRadius: '3px' }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function InfraDistribution({ infraDist }) {
  if (!infraDist || infraDist.length === 0) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      {infraDist.map(item => {
        const meta = INFRA_META[item.infra_key] || { icon: '❓', label: item.label || item.infra_key, color: theme.accent, desc: '' };
        return (
          <div key={item.infra_key} style={{ backgroundColor: theme.cardSub, padding: '14px', borderRadius: '8px', border: `1px solid ${meta.color}44` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '18px' }}>{meta.icon}</span>
                <div>
                  <div style={{ fontWeight: '700', fontSize: '13px', color: meta.color }}>{meta.label}</div>
                  <div style={{ fontSize: '10px', color: theme.textMuted, marginTop: '2px' }}>{meta.desc}</div>
                </div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontWeight: '800', fontSize: '20px', color: theme.textMain }}>{item.count.toLocaleString()}</div>
                <div style={{ fontSize: '12px', color: theme.textMuted }}>({item.pct}%)</div>
              </div>
            </div>
            <div style={{ width: '100%', height: '6px', backgroundColor: theme.bg, borderRadius: '3px', overflow: 'hidden' }}>
              <div style={{ width: `${item.pct}%`, height: '100%', backgroundColor: meta.color, borderRadius: '3px' }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ─── Full ASN Threat Intelligence Modal ─────────────────────────────────── */
function ASNThreatIntelModal({ asn, onClose, totalClassified }) {
  const [tiData, setTiData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('summary');
  const scrollRef = useRef(null);

  useEffect(() => {
    if (!asn) return;
    setLoading(true);
    setError(null);
    setTiData(null);
    axios.get(`http://127.0.0.1:8000/api/asn/${asn.asn}/threat-intelligence`)
      .then(res => {
        setTiData(res.data);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message || 'Failed to load threat intelligence');
        setLoading(false);
      });
  }, [asn]);

  if (!asn) return null;

  const isDatacenter = asn.infra_key === 'DATACENTER';
  const infraMeta = INFRA_META[asn.infra_key] || { icon: '🌐', label: 'Network', color: theme.accent };
  const percentOfTotal = totalClassified > 0 ? ((asn.total_threat_ips / totalClassified) * 100).toFixed(2) : '0';

  const tabs = [
    { id: 'summary',      label: '📋 Executive Summary' },
    { id: 'findings',     label: '🔍 Intelligence Findings' },
    { id: 'prefix',       label: '🌐 Prefix Analysis' },
    { id: 'concentration',label: '📊 Concentration' },
    { id: 'heatmap',      label: '🔥 Category Heatmap' },
    { id: 'category',     label: '📈 Category Distribution' },
    { id: 'infra',        label: '🏢 Infrastructure' },
    { id: 'geo',          label: '🗺️ Geographic' },
    { id: 'temporal',     label: '📅 Temporal' },
  ];

  const summary = tiData?.summary;
  const hasData = tiData?.status === 'success';

  return (
    <div
      style={{
        position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
        backgroundColor: 'rgba(2, 6, 23, 0.90)', backdropFilter: 'blur(8px)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        zIndex: 9999, padding: '12px',
      }}
      onClick={onClose}
    >
      <div
        ref={scrollRef}
        style={{
          backgroundColor: theme.card,
          border: `1px solid ${theme.purple}`,
          borderRadius: '14px',
          width: '100%',
          maxWidth: '1100px',
          maxHeight: '92vh',
          overflowY: 'auto',
          boxShadow: '0 30px 60px -12px rgba(0,0,0,0.8)',
          display: 'flex',
          flexDirection: 'column',
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* ── Modal Header ────────────────────────────────────────────────── */}
        <div style={{
          padding: '20px 24px 16px',
          background: 'linear-gradient(135deg, #0F172A 0%, #1E1B4B 60%, #0F172A 100%)',
          borderBottom: `1px solid ${theme.border}`,
          position: 'sticky', top: 0, zIndex: 10,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              {/* ASN + infra badge */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', marginBottom: '6px' }}>
                <span style={{
                  fontFamily: 'monospace', fontSize: '20px', fontWeight: '900', color: theme.accent,
                  backgroundColor: '#0B1223', padding: '4px 12px', borderRadius: '6px', border: `1px solid ${theme.accent}66`,
                }}>{asn.asn}</span>
                <span style={{
                  fontSize: '11px', padding: '3px 10px', borderRadius: '4px', fontWeight: '700',
                  backgroundColor: isDatacenter ? '#450a0a' : '#0B1223',
                  color: isDatacenter ? theme.danger : infraMeta.color,
                  border: `1px solid ${infraMeta.color}66`,
                }}>{infraMeta.icon} {infraMeta.label}</span>
                <span style={{
                  fontSize: '10px', padding: '2px 8px', borderRadius: '4px', fontWeight: '600',
                  backgroundColor: '#1E1B4B', color: theme.purple, border: `1px solid ${theme.purple}55`,
                }}>🔍 THREAT INTELLIGENCE ANALYTICS</span>
              </div>
              <div style={{ fontSize: '16px', fontWeight: '700', color: theme.textMain }}>{asn.org}</div>
              <div style={{ fontSize: '12px', color: theme.textMuted, marginTop: '2px' }}>
                📍 {asn.country || 'Global'} &nbsp;·&nbsp;
                <span style={{ color: theme.danger }}>
                  {asn.total_threat_ips.toLocaleString()} observed threat IPs
                </span> &nbsp;·&nbsp;
                <span style={{ color: theme.textMuted }}>{percentOfTotal}% of dataset</span>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              {loading && (
                <span style={{ fontSize: '12px', color: theme.textMuted }}>
                  ⟳ Computing intelligence…
                </span>
              )}
              <button onClick={onClose} style={{
                background: 'transparent', border: `1px solid ${theme.border}`,
                color: theme.textMuted, borderRadius: '6px', padding: '7px 14px',
                cursor: 'pointer', fontSize: '13px', fontWeight: '700',
              }}>✕ Close</button>
            </div>
          </div>

          {/* Summary metrics strip */}
          {hasData && summary && (
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '14px' }}>
              {[
                { label: 'Threat IPs', value: summary.total_threat_ips.toLocaleString(), color: theme.danger },
                { label: 'Prefixes', value: summary.unique_prefixes, color: theme.cyan },
                { label: 'Countries', value: summary.unique_countries, color: theme.accent },
                { label: 'Categories', value: summary.n_categories, color: theme.purple },
                { label: 'Top-5 Concentration', value: `${summary.top5_concentration}%`, color: summary.top5_concentration >= 75 ? theme.danger : summary.top5_concentration >= 50 ? theme.warning : theme.success },
                { label: 'Dominant Category', value: summary.dominant_category || '—', color: CATEGORY_COLORS[summary.dominant_category] || theme.textMuted },
              ].map(m => (
                <div key={m.label} style={{
                  backgroundColor: '#0B1223', padding: '6px 12px', borderRadius: '6px',
                  border: `1px solid ${theme.border}`, display: 'flex', flexDirection: 'column', alignItems: 'center',
                }}>
                  <div style={{ fontSize: '9px', color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px' }}>{m.label}</div>
                  <div style={{ fontWeight: '800', color: m.color, fontSize: '14px', textTransform: 'capitalize', fontFamily: 'monospace' }}>{m.value}</div>
                </div>
              ))}
            </div>
          )}

          {/* Tab bar */}
          <div style={{ display: 'flex', gap: '4px', marginTop: '14px', flexWrap: 'wrap' }}>
            {tabs.map(tab => (
              <button key={tab.id} onClick={() => { setActiveTab(tab.id); scrollRef.current?.scrollTo({ top: 0 }); }}
                style={{
                  padding: '6px 12px', fontSize: '12px', fontWeight: '600',
                  backgroundColor: activeTab === tab.id ? theme.purple : theme.cardSub,
                  color: activeTab === tab.id ? '#fff' : theme.textMuted,
                  border: `1px solid ${activeTab === tab.id ? theme.purple : theme.border}`,
                  borderRadius: '5px', cursor: 'pointer', transition: 'all 0.15s',
                }}>
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* ── Modal Body ───────────────────────────────────────────────────── */}
        <div style={{ padding: '22px 24px', flex: 1 }}>

          {/* Loading */}
          {loading && (
            <div style={{ textAlign: 'center', padding: '60px 0' }}>
              <div style={{ fontSize: '36px', marginBottom: '14px' }}>⟳</div>
              <div style={{ fontWeight: '700', color: theme.purple, fontSize: '15px', marginBottom: '6px' }}>
                Computing Deep Threat Intelligence…
              </div>
              <div style={{ fontSize: '12px', color: theme.textMuted }}>
                Scanning DynamoDB for all {asn.asn} IPs, clustering by BGP prefix,
                running analytics pipeline. This may take 10–60 seconds the first time.
              </div>
            </div>
          )}

          {/* Error */}
          {!loading && error && (
            <div style={{ padding: '18px', backgroundColor: '#450a0a', border: `1px solid ${theme.danger}`, borderRadius: '8px', color: theme.danger }}>
              ⚠️ {error}
            </div>
          )}

          {/* Insufficient data */}
          {!loading && tiData?.status === 'insufficient_data' && (
            <div style={{ padding: '24px', backgroundColor: theme.cardSub, borderRadius: '8px', border: `1px solid ${theme.border}` }}>
              <div style={{ color: theme.warning, fontWeight: '700', marginBottom: '8px' }}>⚠️ Insufficient Data</div>
              <div style={{ color: theme.textMuted, fontSize: '13px' }}>{tiData.message}</div>
              <div style={{ color: theme.textMuted, fontSize: '12px', marginTop: '8px', fontStyle: 'italic' }}>{tiData.reason}</div>
            </div>
          )}

          {/* ── Data Tabs ───────────────────────────────────────────────────── */}
          {!loading && hasData && (
            <>
              {/* ── Executive Summary ──────────────────────────────────────── */}
              {activeTab === 'summary' && (
                <div>
                  <SectionHeader
                    title="Executive Summary"
                    subtitle="Aggregated threat intelligence derived from observed OSINT data."
                  />

                  {/* Key metrics grid */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '10px', marginBottom: '20px' }}>
                    <MetricCard label="Total Threat IPs" value={summary.total_threat_ips.toLocaleString()} color={theme.danger} icon="🛡️" />
                    <MetricCard label="Unique BGP Prefixes" value={summary.unique_prefixes} sub={summary.unavailable_prefix_ips > 0 ? `+${summary.unavailable_prefix_ips} IPs without prefix data` : undefined} color={theme.cyan} icon="🌐" />
                    <MetricCard label="Countries" value={summary.unique_countries} color={theme.accent} icon="🗺️" />
                    <MetricCard label="Threat Categories" value={summary.n_categories} color={theme.purple} icon="📊" />
                    <MetricCard label="Top-5 Concentration" value={`${summary.top5_concentration}%`} sub={summary.concentration_class?.replace(/_/g, ' ')} color={summary.top5_concentration >= 75 ? theme.danger : summary.top5_concentration >= 50 ? theme.warning : theme.success} icon="📍" />
                    <MetricCard label="Dominant Category" value={(summary.dominant_category || '—')} sub={summary.dominant_category_share ? `${summary.dominant_category_share}% share` : undefined} color={CATEGORY_COLORS[summary.dominant_category] || theme.textMuted} icon="🎯" />
                  </div>

                  {/* Top prefix callout */}
                  {summary.top_prefix && summary.top_prefix !== 'Prefix Unavailable' && (
                    <div style={{ backgroundColor: '#0B132B', borderRadius: '8px', padding: '16px', border: `1px solid ${theme.accent}44`, marginBottom: '20px' }}>
                      <div style={{ fontSize: '11px', color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>
                        🔥 Highest-Activity Prefix
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
                        <div>
                          <span style={{ fontFamily: 'monospace', fontWeight: '800', fontSize: '16px', color: theme.cyan }}>{summary.top_prefix}</span>
                          <span style={{ color: theme.textMuted, marginLeft: '10px', fontSize: '12px' }}>{summary.top_prefix_count} observed threat IPs</span>
                        </div>
                        {summary.top_prefix_density != null && (
                          <div>
                            <span style={{ fontSize: '11px', color: theme.textMuted }}>Observed Density: </span>
                            <span style={{ fontFamily: 'monospace', fontWeight: '800', color: summary.top_prefix_density >= 25 ? theme.danger : summary.top_prefix_density >= 10 ? theme.warning : theme.accent }}>
                              {summary.top_prefix_density.toFixed(2)}%
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Methodology note */}
                  <div style={{ backgroundColor: '#082030', borderRadius: '8px', padding: '14px', border: `1px solid ${theme.cyan}33` }}>
                    <div style={{ fontSize: '11px', color: theme.textMuted, lineHeight: '1.6' }}>
                      <strong style={{ color: theme.cyan }}>Observed Data vs. Derived Analysis:</strong> All metrics are derived from IPs observed
                      in the OSINT scan dataset. Prefix mapping uses BGP-announced CIDRs from the RIPEstat API (stored per IP in the database).
                      Threat density = (observed threat IPs) / (total prefix address space). Category shares are empirical proportions, not predictive probabilities.
                    </div>
                  </div>
                </div>
              )}

              {/* ── Intelligence Findings ────────────────────────────────────── */}
              {activeTab === 'findings' && (
                <div>
                  <SectionHeader
                    title="Intelligence Findings"
                    subtitle="Auto-generated evidence-backed findings from deterministic rules. Every finding links to source data."
                  />
                  {tiData.findings.length === 0 ? (
                    <div style={{ color: theme.textMuted, padding: '20px', textAlign: 'center', fontSize: '13px' }}>
                      No significant findings generated. Dataset may be too small for pattern detection.
                    </div>
                  ) : (
                    tiData.findings.map((f, i) => (
                      <FindingCard key={f.id || i} finding={f} defaultExpanded={i === 0} />
                    ))
                  )}
                  <div style={{ marginTop: '16px', padding: '12px', backgroundColor: theme.cardSub, borderRadius: '8px', border: `1px solid ${theme.border}`, fontSize: '11px', color: theme.textMuted, lineHeight: '1.5' }}>
                    <strong style={{ color: theme.textMain }}>Finding Generation Methodology:</strong> Findings are generated by deterministic threshold-based rules
                    applied to computed statistics. No machine learning is used. Every finding references
                    specific data points from the observed dataset and can be fully traced to source records.
                    These are observed patterns — not proof of malicious activity.
                  </div>
                </div>
              )}

              {/* ── Prefix Analysis ──────────────────────────────────────────── */}
              {activeTab === 'prefix' && (
                <div>
                  <SectionHeader
                    title="CIDR / Network Prefix Analysis"
                    subtitle="Observed threat IPs grouped by BGP-announced network prefix. Prefix source: RIPEstat API (authoritative BGP data)."
                  />
                  <div style={{ marginBottom: '14px', display: 'flex', gap: '10px', flexWrap: 'wrap', fontSize: '12px' }}>
                    <EvidencePill text={`${summary.unique_prefixes} unique prefixes`} color={theme.cyan} />
                    {summary.unavailable_prefix_ips > 0 && (
                      <EvidencePill text={`${summary.unavailable_prefix_ips} IPs with no prefix data`} color={theme.warning} />
                    )}
                    <span style={{ color: theme.textMuted, fontSize: '11px', alignSelf: 'center' }}>
                      Observed Threat Density = (Threat IPs / Prefix Size) × 100
                    </span>
                  </div>
                  <PrefixTable prefixes={tiData.prefix_analysis} total={summary.total_threat_ips} />
                </div>
              )}

              {/* ── Concentration ────────────────────────────────────────────── */}
              {activeTab === 'concentration' && (
                <div>
                  <SectionHeader
                    title="Threat Concentration Analysis"
                    subtitle="How concentrated are observed threat IPs within a small number of prefixes?"
                  />
                  <ConcentrationChart concentration={tiData.concentration} total={summary.total_threat_ips} />
                </div>
              )}

              {/* ── Category Heatmap ─────────────────────────────────────────── */}
              {activeTab === 'heatmap' && (
                <div>
                  <SectionHeader
                    title="Prefix × Threat Category Heatmap"
                    subtitle="Category distribution across top-10 prefixes. Color intensity = percentage share within prefix."
                  />
                  <CategoryHeatmap heatmap={tiData.category_heatmap} />
                </div>
              )}

              {/* ── Category Distribution ────────────────────────────────────── */}
              {activeTab === 'category' && (
                <div>
                  <SectionHeader
                    title="Threat Category Distribution"
                    subtitle="Observed category share across all IPs in this ASN. Values are empirical proportions, not predictive probabilities."
                  />
                  <CategoryDistribution catDist={tiData.category_distribution} total={summary.total_threat_ips} />
                </div>
              )}

              {/* ── Infrastructure ───────────────────────────────────────────── */}
              {activeTab === 'infra' && (
                <div>
                  <SectionHeader
                    title="Infrastructure Type Distribution"
                    subtitle="Threat IP distribution across infrastructure classifications. Derived from BGP/ASN profiling."
                  />
                  <InfraDistribution infraDist={tiData.infrastructure_distribution} />
                </div>
              )}

              {/* ── Geographic ───────────────────────────────────────────────── */}
              {activeTab === 'geo' && (
                <div>
                  <SectionHeader
                    title="Geographic Distribution"
                    subtitle="Threat IP count mapped to geographic location. GeoIP reflects IP registration/infrastructure location, not attacker origin."
                  />
                  <GeographyBars geoData={tiData.geographic_distribution} />
                </div>
              )}

              {/* ── Temporal ─────────────────────────────────────────────────── */}
              {activeTab === 'temporal' && (
                <div>
                  <SectionHeader
                    title="Temporal / Persistence Analysis"
                    subtitle="Time-based classification of observed threat IPs in the dataset."
                  />
                  <TemporalAnalysis temporal={tiData.temporal_analysis} />
                </div>
              )}

              {/* Computed-at footer */}
              <div style={{ marginTop: '20px', paddingTop: '12px', borderTop: `1px solid ${theme.border}22`, fontSize: '10px', color: theme.textMuted, display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '6px' }}>
                <span>Intelligence computed: {tiData.computed_at} ({tiData.computation_ms}ms)</span>
                <span>Observed data only — not ground truth. Use for analytical context.</span>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

/* ─── Original Simple Dossier Modal (fallback, kept for safety) ──────────── */
function ASNDossierModal({ asn, onClose, totalClassified }) {
  if (!asn) return null;
  const isDatacenter = asn.infra_key === 'DATACENTER';
  const meta = INFRA_META[asn.infra_key] || { icon: '🌐', label: 'Network', color: theme.accent };
  const percentOfTotal = totalClassified > 0 ? ((asn.total_threat_ips / totalClassified) * 100).toFixed(2) : '0';

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      backgroundColor: 'rgba(2, 6, 23, 0.85)', backdropFilter: 'blur(6px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      zIndex: 9999, padding: '20px',
    }} onClick={onClose}>
      <div style={{
        backgroundColor: theme.card, border: `1px solid ${theme.purple}`, borderRadius: '12px',
        width: '100%', maxWidth: '650px', maxHeight: '90vh', overflowY: 'auto',
        boxShadow: '0 25px 50px -12px rgba(0,0,0,0.7)', padding: '24px',
      }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '18px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{
                fontFamily: 'monospace', fontSize: '18px', fontWeight: '900', color: theme.accent,
                backgroundColor: '#0B1223', padding: '4px 10px', borderRadius: '6px', border: `1px solid ${theme.accent}66`,
              }}>{asn.asn}</span>
              <span style={{
                fontSize: '11px', padding: '3px 8px', borderRadius: '4px', fontWeight: '700',
                backgroundColor: isDatacenter ? '#450a0a' : '#0B1223',
                color: isDatacenter ? theme.danger : meta.color, border: `1px solid ${meta.color}66`,
              }}>{meta.icon} {meta.label}</span>
            </div>
            <div style={{ fontSize: '16px', fontWeight: '700', color: theme.textMain, marginTop: '8px' }}>{asn.org}</div>
            <div style={{ fontSize: '12px', color: theme.textMuted, marginTop: '2px' }}>📍 Country: <strong style={{ color: theme.accent }}>{asn.country || 'Global / Unassigned'}</strong></div>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: `1px solid ${theme.border}`, color: theme.textMuted, borderRadius: '6px', padding: '6px 12px', cursor: 'pointer', fontSize: '14px', fontWeight: '700' }}>✕ Close</button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px', marginBottom: '20px' }}>
          <div style={{ backgroundColor: theme.cardSub, padding: '12px', borderRadius: '8px', border: `1px solid ${theme.border}` }}>
            <div style={{ fontSize: '11px', color: theme.textMuted, textTransform: 'uppercase' }}>Threat IPs</div>
            <div style={{ fontSize: '20px', fontWeight: '800', color: theme.danger, marginTop: '4px' }}>{asn.total_threat_ips.toLocaleString()}</div>
            <div style={{ fontSize: '10px', color: theme.textMuted, marginTop: '2px' }}>{percentOfTotal}% of dataset</div>
          </div>
          <div style={{ backgroundColor: theme.cardSub, padding: '12px', borderRadius: '8px', border: `1px solid ${theme.border}` }}>
            <div style={{ fontSize: '11px', color: theme.textMuted, textTransform: 'uppercase' }}>Primary Threat</div>
            <div style={{ fontSize: '15px', fontWeight: '800', textTransform: 'capitalize', color: CATEGORY_COLORS[asn.primary_threat] || theme.warning, marginTop: '6px' }}>{asn.primary_threat || 'Clean / None'}</div>
            <div style={{ fontSize: '10px', color: theme.textMuted, marginTop: '2px' }}>Top observed vector</div>
          </div>
          <div style={{ backgroundColor: theme.cardSub, padding: '12px', borderRadius: '8px', border: `1px solid ${theme.border}` }}>
            <div style={{ fontSize: '11px', color: theme.textMuted, textTransform: 'uppercase' }}>Infra Type</div>
            <div style={{ fontSize: '13px', fontWeight: '700', color: meta.color, marginTop: '6px' }}>{meta.icon} {meta.label}</div>
          </div>
        </div>

        <div style={{ marginBottom: '20px' }}>
          <div style={{ fontSize: '13px', fontWeight: '700', color: theme.textMain, marginBottom: '10px' }}>📊 Threat Category Breakdown</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {Object.entries(asn.category_counts || {}).sort((a, b) => b[1] - a[1]).map(([cat, count]) => {
              const pct = asn.category_percentages?.[cat] ?? 0;
              const color = CATEGORY_COLORS[cat] || '#64748B';
              return (
                <div key={cat} style={{ backgroundColor: theme.cardSub, padding: '10px 14px', borderRadius: '6px', border: `1px solid ${theme.border}` }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px', fontSize: '12px' }}>
                    <span style={{ fontWeight: '700', textTransform: 'capitalize', color: color }}>{cat}</span>
                    <span style={{ color: theme.textMain, fontWeight: '700' }}>{count.toLocaleString()} IPs <span style={{ color: theme.textMuted, fontWeight: '400' }}>({pct}%)</span></span>
                  </div>
                  <div style={{ width: '100%', height: '6px', backgroundColor: theme.bg, borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', backgroundColor: color, borderRadius: '3px' }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div style={{ backgroundColor: '#0B132B', border: '1px solid #1E293B', borderRadius: '8px', padding: '12px', fontSize: '11px', color: theme.textMuted, lineHeight: '1.5' }}>
          💡 <b>Analyst Note:</b> {isDatacenter
            ? 'This ASN is classified as datacenter / VPS fleet. Threat detections here typically indicate automated vulnerability scanners, brute-force bots, and reverse-proxy nodes.'
            : 'This ASN represents residential / ISP routing. Threat activity indicates infected subscriber hosts, IoT botnet propagation, or residential proxy abuse.'}
        </div>
      </div>
    </div>
  );
}

/* ─── Main Component ─────────────────────────────────────────────────────── */
export default function ASNIntelligence() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [computing, setComputing] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('search_all');
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [pollCount, setPollCount] = useState(0);

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedInfra, setSelectedInfra] = useState('ALL');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [sortBy, setSortBy] = useState('threats_desc');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 20;

  const [selectedAsn, setSelectedAsn] = useState(null);
  const [dossierMode, setDossierMode] = useState('simple'); // 'simple' | 'intel'

  const fetchData = useCallback(async () => {
    try {
      const res = await axios.get('http://127.0.0.1:8000/api/analytics/asn-intelligence');
      if (res.data.status === 'success') {
        setData(res.data.data);
        setLoading(false);
        setError(null);
        return true;
      }
      return false;
    } catch (err) {
      setError(err.message || 'Backend unreachable');
      setLoading(false);
      return false;
    }
  }, []);

  const triggerRecompute = async () => {
    setComputing(true);
    setError(null);
    try {
      await axios.post('http://127.0.0.1:8000/api/analytics/recompute');
      let attempts = 0;
      const poll = setInterval(async () => {
        attempts++;
        setPollCount(attempts);
        const ok = await fetchData();
        if (ok || attempts >= 30) {
          clearInterval(poll);
          setComputing(false);
          setPollCount(0);
        }
      }, 4000);
    } catch (err) {
      setError('Failed to trigger recompute: ' + (err.message || 'Unknown'));
      setComputing(false);
    }
  };

  useEffect(() => {
    fetchData().then(ok => {
      if (!ok) triggerRecompute();
    });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const tabs = [
    { id: 'search_all',    label: '🔍 ASN Search & Explorer' },
    { id: 'worst_asns',    label: '⚠️ Top 25 Worst ASNs' },
    { id: 'dirty_hosters', label: '🏢 Dirty Hosters' },
    { id: 'infra',         label: '📊 Infra Distribution' },
  ];

  const totalAnalyzed = data?.total_analyzed_ips ?? 0;
  const totalItems    = data?.total_table_items ?? 0;
  const sampleSize    = data?.sample_size ?? 0;
  const totalAsns     = data?.total_asns ?? (data?.worst_asns?.length ?? 0);
  const updatedAt     = data?.updated_at ?? '';

  const allAsnList = useMemo(() => {
    if (!data) return [];
    return data.all_asns && data.all_asns.length > 0 ? data.all_asns : (data.worst_asns || []);
  }, [data]);

  const filteredAsns = useMemo(() => {
    if (!allAsnList || allAsnList.length === 0) return [];
    const q = searchQuery.trim().toLowerCase();
    return allAsnList.filter(item => {
      if (q) {
        const asnMatch = (item.asn || '').toLowerCase().includes(q);
        const orgMatch = (item.org || '').toLowerCase().includes(q);
        const countryMatch = (item.country || '').toLowerCase().includes(q);
        if (!asnMatch && !orgMatch && !countryMatch) return false;
      }
      if (selectedInfra !== 'ALL' && item.infra_key !== selectedInfra) return false;
      if (selectedCategory !== 'ALL' && (!item.category_counts || !item.category_counts[selectedCategory])) return false;
      return true;
    }).sort((a, b) => {
      if (sortBy === 'threats_desc') return (b.total_threat_ips || 0) - (a.total_threat_ips || 0);
      if (sortBy === 'threats_asc') return (a.total_threat_ips || 0) - (b.total_threat_ips || 0);
      if (sortBy === 'asn_asc') return (a.asn || '').localeCompare(b.asn || '', undefined, { numeric: true });
      if (sortBy === 'org_asc') return (a.org || '').localeCompare(b.org || '');
      return 0;
    });
  }, [allAsnList, searchQuery, selectedInfra, selectedCategory, sortBy]);

  const totalPages = Math.ceil(filteredAsns.length / pageSize) || 1;
  const paginatedAsns = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredAsns.slice(start, start + pageSize);
  }, [filteredAsns, currentPage, pageSize]);

  useEffect(() => { setCurrentPage(1); }, [searchQuery, selectedInfra, selectedCategory, sortBy]);

  const openDossier = (asn) => { setSelectedAsn(asn); setDossierMode('simple'); };
  const openIntel   = (asn) => { setSelectedAsn(asn); setDossierMode('intel'); };

  return (
    <div style={{ backgroundColor: theme.card, borderRadius: '12px', border: `1px solid ${theme.border}`, marginBottom: '30px', overflow: 'hidden' }}>

      {/* Dossier Modals */}
      {selectedAsn && dossierMode === 'intel' && (
        <ASNThreatIntelModal
          asn={selectedAsn}
          totalClassified={totalAnalyzed}
          onClose={() => setSelectedAsn(null)}
        />
      )}
      {selectedAsn && dossierMode === 'simple' && (
        <ASNDossierModal
          asn={selectedAsn}
          totalClassified={totalAnalyzed}
          onClose={() => setSelectedAsn(null)}
        />
      )}

      {/* ── Header ────────────────────────────────────────────────────────── */}
      <div
        onClick={() => setIsCollapsed(v => !v)}
        style={{
          padding: '18px 24px',
          background: 'linear-gradient(135deg, #0F172A 0%, #1E1B4B 100%)',
          borderBottom: isCollapsed ? 'none' : `1px solid ${theme.border}`,
          cursor: 'pointer', userSelect: 'none',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '22px' }}>🔍</span>
          <div>
            <div style={{ fontWeight: '700', fontSize: '16px', color: theme.textMain }}>
              ASN & Hosting Provider Threat Intelligence
            </div>
            <div style={{ fontSize: '12px', color: theme.textMuted, marginTop: '2px' }}>
              Search {allAsnList.length > 0 ? allAsnList.length : 650}+ ASNs · Prefix Analytics · Intelligence Findings
            </div>
          </div>

          {data && (
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {totalItems > 0 && (
                <span style={{ fontSize: '11px', padding: '3px 10px', borderRadius: '4px', fontWeight: '700', backgroundColor: '#06283D', color: theme.cyan, border: `1px solid ${theme.cyan}66` }}>
                  🗄️ {totalItems.toLocaleString()} DynamoDB Records
                </span>
              )}
              <span style={{ fontSize: '11px', padding: '3px 10px', borderRadius: '4px', fontWeight: '700', backgroundColor: '#1E1B4B', color: theme.purple, border: `1px solid ${theme.purple}` }}>
                ⚡ {sampleSize.toLocaleString()} Scanned
              </span>
              <span style={{ fontSize: '11px', padding: '3px 10px', borderRadius: '4px', fontWeight: '700', backgroundColor: '#0B1223', color: theme.accent, border: `1px solid ${theme.accent}` }}>
                🛡️ {totalAnalyzed.toLocaleString()} Classified IPs
              </span>
              <span style={{ fontSize: '11px', padding: '3px 10px', borderRadius: '4px', fontWeight: '700', backgroundColor: '#1B2E1E', color: theme.success, border: `1px solid ${theme.success}66` }}>
                🌐 {totalAsns} ASNs
              </span>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {updatedAt && <span style={{ fontSize: '11px', color: theme.textMuted }}>Updated: {updatedAt}</span>}
          <button
            onClick={e => { e.stopPropagation(); triggerRecompute(); }}
            disabled={computing}
            style={{
              padding: '6px 14px', fontSize: '12px', fontWeight: '600',
              backgroundColor: computing ? theme.cardSub : '#1E1B4B',
              color: computing ? theme.textMuted : theme.purple,
              border: `1px solid ${computing ? theme.border : theme.purple}`,
              borderRadius: '6px', cursor: computing ? 'default' : 'pointer',
            }}
          >
            {computing ? `⟳ Computing… (${pollCount * 4}s)` : '⟳ Recompute'}
          </button>
          <span style={{ color: theme.textMuted, fontSize: '12px' }}>{isCollapsed ? '▼' : '▲'}</span>
        </div>
      </div>

      {isCollapsed ? null : (
        <div style={{ padding: '20px 24px' }}>

          {/* Loading */}
          {loading && !computing && (
            <div style={{ textAlign: 'center', padding: '40px', color: theme.textMuted }}>
              <div style={{ fontSize: '32px', marginBottom: '12px' }}>⏳</div>
              Loading ASN intelligence data…
            </div>
          )}

          {computing && !data && (
            <div style={{ textAlign: 'center', padding: '40px', color: theme.purple }}>
              <div style={{ fontSize: '32px', marginBottom: '12px' }}>⟳</div>
              <div style={{ fontWeight: '700', fontSize: '15px', marginBottom: '8px' }}>Computing ASN Intelligence…</div>
              <div style={{ fontSize: '13px', color: theme.textMuted }}>
                Scanning your scanned IP database and aggregating by ASN.
                {pollCount > 0 && ` Polling… (${pollCount * 4}s elapsed)`}
              </div>
            </div>
          )}

          {error && (
            <div style={{ padding: '14px', backgroundColor: '#450a0a', border: `1px solid ${theme.danger}`, borderRadius: '8px', color: theme.danger, fontSize: '13px', marginBottom: '16px' }}>
              ⚠️ {error}
            </div>
          )}

          {data && (
            <>
              {/* KPI Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '12px', marginBottom: '16px' }}>
                <div style={{ padding: '12px 16px', borderRadius: '8px', backgroundColor: theme.cardSub, border: `1px solid ${theme.border}` }}>
                  <div style={{ fontSize: '11px', color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>🗄️ AWS DynamoDB Table</div>
                  <div style={{ fontSize: '18px', fontWeight: '800', color: theme.cyan }}>
                    {totalItems > 0 ? totalItems.toLocaleString() : '50,000+'}
                    <span style={{ fontSize: '12px', fontWeight: '400', color: theme.textMuted, marginLeft: '6px' }}>total IPs</span>
                  </div>
                  <div style={{ fontSize: '10px', color: theme.textMuted, marginTop: '3px' }}>Live Table: <code style={{ color: theme.accent }}>researchProject01</code></div>
                </div>

                <div style={{ padding: '12px 16px', borderRadius: '8px', backgroundColor: theme.cardSub, border: `1px solid ${theme.border}` }}>
                  <div style={{ fontSize: '11px', color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>⚡ Database Coverage</div>
                  <div style={{ fontSize: '18px', fontWeight: '800', color: theme.purple }}>
                    {sampleSize.toLocaleString()}
                    <span style={{ fontSize: '12px', fontWeight: '400', color: theme.textMuted, marginLeft: '6px' }}>
                      {sampleSize >= totalItems && totalItems > 0 ? '100% Full DB' : 'scanned'}
                    </span>
                  </div>
                  <div style={{ fontSize: '10px', color: theme.textMuted, marginTop: '3px' }}>Parallel 8-segment scan (Cached)</div>
                </div>

                <div style={{ padding: '12px 16px', borderRadius: '8px', backgroundColor: theme.cardSub, border: `1px solid ${theme.border}` }}>
                  <div style={{ fontSize: '11px', color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>🛡️ Classified Threat IPs</div>
                  <div style={{ fontSize: '18px', fontWeight: '800', color: theme.accent }}>
                    {totalAnalyzed.toLocaleString()}
                    <span style={{ fontSize: '12px', fontWeight: '400', color: theme.textMuted, marginLeft: '6px' }}>IPs</span>
                  </div>
                  <div style={{ fontSize: '10px', color: theme.textMuted, marginTop: '3px' }}>Across {totalAsns} autonomous systems</div>
                </div>

                <div style={{ padding: '12px 16px', borderRadius: '8px', backgroundColor: theme.cardSub, border: `1px solid ${theme.border}` }}>
                  <div style={{ fontSize: '11px', color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>🔄 Real-time Status</div>
                  <div style={{ fontSize: '14px', fontWeight: '700', color: theme.success, display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px' }}>
                    <span style={{ display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', backgroundColor: theme.success }}></span>
                    Synchronized & Cached
                  </div>
                  <div style={{ fontSize: '10px', color: theme.textMuted, marginTop: '4px' }}>Click <b>Recompute</b> to refresh</div>
                </div>
              </div>

              {/* Tab bar */}
              <div style={{ display: 'flex', gap: '4px', marginBottom: '16px', flexWrap: 'wrap' }}>
                {tabs.map(tab => (
                  <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                    style={{
                      padding: '8px 16px', fontSize: '13px', fontWeight: '600',
                      backgroundColor: activeTab === tab.id ? theme.purple : theme.cardSub,
                      color: activeTab === tab.id ? '#fff' : theme.textMuted,
                      border: `1px solid ${activeTab === tab.id ? theme.purple : theme.border}`,
                      borderRadius: '6px', cursor: 'pointer', transition: 'all 0.15s',
                    }}>
                    {tab.label}
                  </button>
                ))}
              </div>

              {/* ── ASN Search & Explorer ────────────────────────────────────── */}
              {activeTab === 'search_all' && (
                <div>
                  {/* Filters */}
                  <div style={{ backgroundColor: theme.cardSub, borderRadius: '8px', padding: '14px 16px', border: `1px solid ${theme.border}`, marginBottom: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'center' }}>
                      <div style={{ flex: '1 1 280px', position: 'relative' }}>
                        <input
                          type="text"
                          value={searchQuery}
                          onChange={e => setSearchQuery(e.target.value)}
                          placeholder="Search ASN (e.g. AS16509), Provider (e.g. Amazon, OVH), or Country..."
                          style={{ width: '100%', boxSizing: 'border-box', padding: '10px 14px 10px 36px', backgroundColor: theme.bg, border: `1px solid ${theme.border}`, borderRadius: '6px', color: theme.textMain, fontSize: '13px', outline: 'none' }}
                        />
                        <span style={{ position: 'absolute', left: '12px', top: '10px', color: theme.textMuted }}>🔍</span>
                        {searchQuery && (
                          <button onClick={() => setSearchQuery('')} style={{ position: 'absolute', right: '10px', top: '8px', background: 'none', border: 'none', color: theme.textMuted, cursor: 'pointer', fontSize: '13px' }}>✕</button>
                        )}
                      </div>
                      {[
                        { state: selectedInfra, set: setSelectedInfra, options: [['ALL', 'All Infrastructure Types'], ['DATACENTER', '🏢 Datacenter / Hosting'], ['RESIDENTIAL', '🏠 Residential / ISP'], ['ANYCAST_CDN', '🌐 Anycast CDN / Edge']] },
                        { state: selectedCategory, set: setSelectedCategory, options: [['ALL', 'All Threat Categories'], ['attacks', 'Attacks / Exploits'], ['malware', 'Malware / C2'], ['abuse', 'Abuse / Scanners'], ['anonymizers', 'Anonymizers / Proxies'], ['spam', 'Spam Feeds'], ['reputation', 'Reputation Flags']] },
                        { state: sortBy, set: setSortBy, options: [['threats_desc', 'Sort: Threat IPs (High → Low)'], ['threats_asc', 'Sort: Threat IPs (Low → High)'], ['asn_asc', 'Sort: ASN Number (Asc)'], ['org_asc', 'Sort: Provider Name (A-Z)']] },
                      ].map((sel, i) => (
                        <select key={i} value={sel.state} onChange={e => sel.set(e.target.value)}
                          style={{ padding: '10px 12px', backgroundColor: theme.bg, border: `1px solid ${theme.border}`, borderRadius: '6px', color: theme.textMain, fontSize: '12px', cursor: 'pointer' }}>
                          {sel.options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                        </select>
                      ))}
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px', color: theme.textMuted }}>
                      <div>Found <strong style={{ color: theme.accent }}>{filteredAsns.length}</strong> matching ASNs out of <strong>{allAsnList.length}</strong> total.</div>
                      <div style={{ fontStyle: 'italic', fontSize: '11px' }}>
                        💡 Click <strong style={{ color: theme.purple }}>Dossier</strong> for category breakdown · <strong style={{ color: theme.cyan }}>Intelligence ↗</strong> for deep analytics
                      </div>
                    </div>
                  </div>

                  {/* Results Table */}
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                      <thead>
                        <tr style={{ borderBottom: `1px solid ${theme.border}`, color: theme.textMuted, fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                          <th style={{ padding: '8px 10px', textAlign: 'left' }}>#</th>
                          <th style={{ padding: '8px 10px', textAlign: 'left' }}>ASN / Provider</th>
                          <th style={{ padding: '8px 10px', textAlign: 'left' }}>Country</th>
                          <th style={{ padding: '8px 10px', textAlign: 'left' }}>Infra Type</th>
                          <th style={{ padding: '8px 10px', textAlign: 'right', whiteSpace: 'nowrap' }}>Threat IPs</th>
                          <th style={{ padding: '8px 10px', textAlign: 'left', minWidth: '180px' }}>Category Breakdown</th>
                          <th style={{ padding: '8px 10px', textAlign: 'center', whiteSpace: 'nowrap' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {paginatedAsns.map((asn, idx) => {
                          const isDatacenter = asn.infra_key === 'DATACENTER';
                          const globalIdx = (currentPage - 1) * pageSize + idx + 1;
                          return (
                            <tr key={asn.asn}
                              onClick={() => openIntel(asn)}
                              style={{ borderBottom: `1px solid ${theme.border}22`, backgroundColor: idx % 2 === 0 ? 'transparent' : `${theme.cardSub}55`, cursor: 'pointer', transition: 'background 0.15s ease' }}
                              onMouseEnter={e => e.currentTarget.style.backgroundColor = `${theme.purple}15`}
                              onMouseLeave={e => e.currentTarget.style.backgroundColor = idx % 2 === 0 ? 'transparent' : `${theme.cardSub}55`}
                            >
                              <td style={{ padding: '10px 10px', color: theme.textMuted, fontFamily: 'monospace' }}>{globalIdx}</td>
                              <td style={{ padding: '10px 10px' }}>
                                <div style={{ fontWeight: '700', color: theme.accent, fontFamily: 'monospace', fontSize: '12px' }}>{asn.asn}</div>
                                <div style={{ color: theme.textMain, fontSize: '11px', marginTop: '2px', maxWidth: '220px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{asn.org}</div>
                              </td>
                              <td style={{ padding: '10px 10px', color: theme.textMuted, fontSize: '12px' }}>{asn.country || '—'}</td>
                              <td style={{ padding: '10px 10px' }}>
                                <span style={{ fontSize: '10px', padding: '2px 7px', borderRadius: '4px', fontWeight: '700', backgroundColor: isDatacenter ? '#450a0a' : '#0B1223', color: isDatacenter ? theme.danger : theme.cyan, border: `1px solid ${isDatacenter ? theme.danger : theme.cyan}55`, whiteSpace: 'nowrap' }}>
                                  {asn.infra_key === 'ANYCAST_CDN' ? 'Anycast' : asn.infra_key === 'DATACENTER' ? 'Datacenter' : 'Residential'}
                                </span>
                              </td>
                              <td style={{ padding: '10px 10px', textAlign: 'right', fontWeight: '800', color: theme.danger, fontFamily: 'monospace', fontSize: '14px' }}>
                                {(asn.total_threat_ips ?? 0).toLocaleString()}
                              </td>
                              <td style={{ padding: '10px 10px', minWidth: '180px' }}>
                                <CategoryBar counts={asn.category_counts} percentages={asn.category_percentages} />
                              </td>
                              <td style={{ padding: '10px 10px', textAlign: 'center' }}>
                                <div style={{ display: 'flex', gap: '5px', justifyContent: 'center', flexWrap: 'nowrap' }}>
                                  <button
                                    onClick={e => { e.stopPropagation(); openDossier(asn); }}
                                    style={{ padding: '4px 8px', fontSize: '10px', fontWeight: '600', backgroundColor: '#1E1B4B', color: theme.purple, border: `1px solid ${theme.purple}66`, borderRadius: '4px', cursor: 'pointer', whiteSpace: 'nowrap' }}
                                  >Dossier</button>
                                  <button
                                    onClick={e => { e.stopPropagation(); openIntel(asn); }}
                                    style={{ padding: '4px 8px', fontSize: '10px', fontWeight: '600', backgroundColor: '#082030', color: theme.cyan, border: `1px solid ${theme.cyan}66`, borderRadius: '4px', cursor: 'pointer', whiteSpace: 'nowrap' }}
                                  >Intelligence ↗</button>
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                    {filteredAsns.length === 0 && (
                      <div style={{ textAlign: 'center', padding: '40px', color: theme.textMuted }}>No ASNs match &ldquo;{searchQuery}&rdquo;.</div>
                    )}
                  </div>

                  {/* Pagination */}
                  {totalPages > 1 && (
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '16px', paddingTop: '12px', borderTop: `1px solid ${theme.border}` }}>
                      <div style={{ fontSize: '12px', color: theme.textMuted }}>Page <strong style={{ color: theme.textMain }}>{currentPage}</strong> of <strong>{totalPages}</strong></div>
                      <div style={{ display: 'flex', gap: '6px' }}>
                        {[['← Previous', -1], ['Next →', 1]].map(([label, dir]) => (
                          <button key={label}
                            disabled={(dir === -1 && currentPage === 1) || (dir === 1 && currentPage === totalPages)}
                            onClick={() => setCurrentPage(p => Math.max(1, Math.min(totalPages, p + dir)))}
                            style={{ padding: '6px 12px', fontSize: '12px', backgroundColor: theme.cardSub, color: theme.textMain, border: `1px solid ${theme.border}`, borderRadius: '4px', cursor: 'pointer' }}>
                            {label}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ── Worst ASNs Tab ───────────────────────────────────────────── */}
              {activeTab === 'worst_asns' && (
                <div>
                  <div style={{ fontSize: '12px', color: theme.textMuted, marginBottom: '12px' }}>
                    Top 25 organizations with the highest number of flagged threat IPs. Click any row for deep intelligence.
                  </div>
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                      <thead>
                        <tr style={{ borderBottom: `1px solid ${theme.border}`, color: theme.textMuted, fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                          <th style={{ padding: '8px 10px', textAlign: 'left' }}>Rank</th>
                          <th style={{ padding: '8px 10px', textAlign: 'left' }}>ASN / Organization</th>
                          <th style={{ padding: '8px 10px', textAlign: 'left' }}>Country</th>
                          <th style={{ padding: '8px 10px', textAlign: 'left' }}>Infra Type</th>
                          <th style={{ padding: '8px 10px', textAlign: 'right', whiteSpace: 'nowrap' }}>Threat IPs</th>
                          <th style={{ padding: '8px 10px', textAlign: 'left', minWidth: '200px' }}>Category Breakdown</th>
                          <th style={{ padding: '8px 10px', textAlign: 'center' }}>Intelligence</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(data.worst_asns ?? []).map((asn, idx) => {
                          const isDatacenter = asn.infra_key === 'DATACENTER';
                          return (
                            <tr key={asn.asn}
                              onClick={() => openIntel(asn)}
                              style={{ borderBottom: `1px solid ${theme.border}22`, backgroundColor: idx % 2 === 0 ? 'transparent' : `${theme.cardSub}55`, cursor: 'pointer', transition: 'background 0.1s' }}
                              onMouseEnter={e => e.currentTarget.style.backgroundColor = `${theme.purple}15`}
                              onMouseLeave={e => e.currentTarget.style.backgroundColor = idx % 2 === 0 ? 'transparent' : `${theme.cardSub}55`}
                            >
                              <td style={{ padding: '10px 10px' }}><RankBadge rank={idx + 1} /></td>
                              <td style={{ padding: '10px 10px' }}>
                                <div style={{ fontWeight: '700', color: theme.textMain, fontFamily: 'monospace', fontSize: '12px' }}>{asn.asn}</div>
                                <div style={{ color: theme.textMuted, fontSize: '11px', marginTop: '2px', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{asn.org}</div>
                              </td>
                              <td style={{ padding: '10px 10px', color: theme.accent, fontSize: '12px' }}>{asn.country || '—'}</td>
                              <td style={{ padding: '10px 10px' }}>
                                <span style={{ fontSize: '10px', padding: '2px 7px', borderRadius: '4px', fontWeight: '700', backgroundColor: isDatacenter ? '#450a0a' : '#0B1223', color: isDatacenter ? theme.danger : theme.cyan, border: `1px solid ${isDatacenter ? theme.danger : theme.cyan}55`, whiteSpace: 'nowrap' }}>
                                  {asn.infra_key === 'ANYCAST_CDN' ? 'Anycast' : asn.infra_key === 'DATACENTER' ? 'Datacenter' : 'Residential'}
                                </span>
                              </td>
                              <td style={{ padding: '10px 10px', textAlign: 'right', fontWeight: '800', color: theme.danger, fontFamily: 'monospace', fontSize: '14px' }}>
                                {(asn.total_threat_ips ?? 0).toLocaleString()}
                              </td>
                              <td style={{ padding: '10px 10px', minWidth: '200px' }}>
                                <CategoryBar counts={asn.category_counts} percentages={asn.category_percentages} />
                              </td>
                              <td style={{ padding: '10px 10px', textAlign: 'center' }}>
                                <button onClick={e => { e.stopPropagation(); openIntel(asn); }}
                                  style={{ padding: '4px 10px', fontSize: '11px', fontWeight: '600', backgroundColor: '#082030', color: theme.cyan, border: `1px solid ${theme.cyan}66`, borderRadius: '4px', cursor: 'pointer' }}>
                                  Analytics ↗
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* ── Dirty Hosters ────────────────────────────────────────────── */}
              {activeTab === 'dirty_hosters' && (
                <div>
                  <div style={{ fontSize: '12px', color: theme.textMuted, marginBottom: '16px' }}>
                    Top 10 most abused <strong style={{ color: theme.danger }}>Datacenter / VPN / Hosting</strong> providers.
                    Click any card to view deep threat intelligence analytics.
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {(data.dirty_hosters ?? []).map((h, idx) => {
                      const maxIps = data.dirty_hosters[0]?.total_threat_ips ?? 1;
                      const barWidth = Math.max(4, Math.round((h.total_threat_ips / maxIps) * 100));
                      const primaryColor = CATEGORY_COLORS[h.primary_threat] || theme.danger;
                      return (
                        <div key={h.asn} onClick={() => openIntel(h)}
                          style={{ backgroundColor: theme.cardSub, borderRadius: '8px', padding: '14px 16px', border: `1px solid ${theme.border}`, borderLeft: `3px solid ${primaryColor}`, cursor: 'pointer' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '10px', flexWrap: 'wrap', gap: '8px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                              <RankBadge rank={idx + 1} />
                              <div>
                                <span style={{ fontFamily: 'monospace', fontWeight: '800', color: theme.textMain, fontSize: '13px' }}>{h.asn}</span>
                                <span style={{ color: theme.textMuted, fontSize: '12px', marginLeft: '8px' }}>{h.org}</span>
                              </div>
                              <span style={{ fontSize: '10px', padding: '2px 7px', borderRadius: '4px', fontWeight: '700', backgroundColor: `${primaryColor}22`, color: primaryColor, border: `1px solid ${primaryColor}55`, textTransform: 'capitalize' }}>
                                Primary: {h.primary_threat}
                              </span>
                            </div>
                            <div style={{ textAlign: 'right' }}>
                              <span style={{ fontFamily: 'monospace', fontWeight: '800', color: theme.danger, fontSize: '18px' }}>{(h.total_threat_ips ?? 0).toLocaleString()}</span>
                              <div style={{ fontSize: '10px', color: theme.textMuted }}>threat IPs</div>
                            </div>
                          </div>
                          <div style={{ width: '100%', backgroundColor: theme.bg, borderRadius: '3px', height: '8px', marginBottom: '8px', overflow: 'hidden' }}>
                            <div style={{ width: `${barWidth}%`, height: '100%', background: `linear-gradient(90deg, ${primaryColor}, ${primaryColor}88)`, borderRadius: '3px', transition: 'width 0.6s ease' }} />
                          </div>
                          <CategoryBar counts={h.category_counts} percentages={h.category_percentages} />
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* ── Infrastructure Distribution ───────────────────────────────── */}
              {activeTab === 'infra' && (
                <div>
                  <div style={{ fontSize: '12px', color: theme.textMuted, marginBottom: '16px' }}>
                    Threat IP distribution across infrastructure types. Datacenter-hosted threats are typically scanners, exploit kits, and botnet C2.
                    Residential threats are predominantly botnet agents and IoT malware.
                  </div>
                  <InfraMeterBar distribution={data.infra_distribution} />
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
