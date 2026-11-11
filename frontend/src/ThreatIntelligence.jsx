import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';

/* ─── Theme Variables (Consistent with OSINT Dashboard) ─────────────────────── */
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
  orange:    '#F97316',
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

const SAMPLE_DEMO_IPS = [
  { ip: '198.51.100.25', label: 'Cluster Demo (Doc)', type: 'Subnet Cluster' },
  { ip: '185.220.101.5', label: 'Tor / Scanner (DE)', type: 'Anonymizer Fleet' },
  { ip: '45.154.255.88', label: 'Datacenter Brute-force', type: 'High Density /24' },
  { ip: '1.1.1.1', label: 'Cloudflare Edge (US)', type: 'Anycast CDN' },
  { ip: '8.8.8.8', label: 'Google Public DNS', type: 'Clean Edge' },
];

export default function ThreatIntelligence({ defaultIP = '', onNavigateToSearch }) {
  const [targetIP, setTargetIP] = useState(defaultIP || '198.51.100.25');
  const [intelData, setIntelData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [showComparison, setShowComparison] = useState(true);

  const fetchThreatIntelligence = useCallback(async (ipToAnalyze, force = false) => {
    const query = (ipToAnalyze || targetIP).trim();
    if (!query) return;
    setLoading(true);
    setError(null);
    try {
      const url = `http://127.0.0.1:8000/api/threat-intelligence?ip=${encodeURIComponent(query)}${force ? '&force_refresh=true' : ''}`;
      const res = await axios.get(url);
      if (res.data?.status === 'success') {
        setIntelData(res.data);
      } else {
        setError(res.data?.message || 'Failed to generate threat intelligence report.');
      }
    } catch (err) {
      console.error('Threat intelligence fetch failed:', err);
      setError(err.response?.data?.message || err.message || 'Error communicating with intelligence engine');
    } finally {
      setLoading(false);
    }
  }, [targetIP]);

  // Initial load on mount
  useEffect(() => {
    fetchThreatIntelligence(targetIP);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchThreatIntelligence(targetIP);
  };

  const handleSampleClick = (sampleIp) => {
    setTargetIP(sampleIp);
    fetchThreatIntelligence(sampleIp);
  };

  const pred = intelData?.predictive_risk || {};
  const prob = pred.future_misbehavior_probability ?? 0;
  const riskLevel = pred.risk_level || 'LOW';
  const riskColor = pred.risk_color || T.success;
  const subnet = intelData?.subnet_intelligence || {};
  const asn = intelData?.asn_intelligence || {};
  const trend = intelData?.trend_analysis || {};
  const report = intelData?.actionable_report || {};

  return (
    <div style={{ padding: '24px 32px', maxWidth: 1400, margin: '0 auto' }}>

      {/* ── Paradigm Callout: Information vs Threat Intelligence ────────── */}
      <div style={{
        backgroundColor: T.cardSub,
        border: `1px solid ${T.purple}44`,
        borderRadius: 12,
        padding: '18px 22px',
        marginBottom: 24,
        background: 'linear-gradient(135deg, rgba(30,27,75,0.4) 0%, rgba(15,23,42,0.9) 100%)',
        position: 'relative',
        overflow: 'hidden'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: showComparison ? 12 : 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 22 }}>🧠</span>
            <div>
              <div style={{ fontWeight: 800, fontSize: 15, color: T.textMain, letterSpacing: '-0.2px' }}>
                Information vs. Actionable Threat Intelligence (NERD Methodology)
              </div>
              <div style={{ fontSize: 12, color: T.textMuted }}>
                Answering: <em>What happened</em>, <em>Why it matters</em>, <em>What may happen next</em>, and <em>What an analyst should do</em>.
              </div>
            </div>
          </div>
          <button
            onClick={() => setShowComparison(v => !v)}
            style={{
              background: 'transparent',
              border: `1px solid ${T.border}`,
              color: T.accent,
              padding: '4px 10px',
              borderRadius: 6,
              fontSize: 11,
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            {showComparison ? 'Hide Architecture Note ▲' : 'Explain to Professor ▼'}
          </button>
        </div>

        {showComparison && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 14, marginTop: 12, fontSize: 12 }}>
            <div style={{ backgroundColor: 'rgba(15, 23, 42, 0.7)', padding: '12px 16px', borderRadius: 8, border: `1px solid ${T.border}44` }}>
              <div style={{ color: T.textMuted, fontWeight: 700, textTransform: 'uppercase', fontSize: 10, marginBottom: 6 }}>
                ❌ Traditional OSINT Display (Static Facts)
              </div>
              <div style={{ fontFamily: 'monospace', color: T.textMuted, lineHeight: 1.6 }}>
                <div>• IP: {intelData?.ip || '198.51.100.25'}</div>
                <div>• ASN: {asn.asn || 'AS64500'}</div>
                <div>• BGP Visibility: 95%</div>
                <div>• Threat Score: 82%</div>
              </div>
              <div style={{ marginTop: 8, color: '#f87171', fontSize: 11, fontStyle: 'italic' }}>
                Professor's critique: "Is information se security analyst ko kya actionable intelligence mili?"
              </div>
            </div>

            <div style={{ backgroundColor: 'rgba(5, 46, 22, 0.4)', padding: '12px 16px', borderRadius: 8, border: `1px solid ${T.success}55` }}>
              <div style={{ color: T.success, fontWeight: 800, textTransform: 'uppercase', fontSize: 10, marginBottom: 6 }}>
                ✅ Predictive Risk & Actionable Intelligence Engine
              </div>
              <div style={{ color: T.textMain, lineHeight: 1.6 }}>
                <div>• <strong>Subnet Cluster:</strong> Same /24 subnet has <strong>{subnet.total_threats_in_subnet || 0} reported threat IPs</strong></div>
                <div>• <strong>Activity Focus:</strong> Concentrated in <strong>{subnet.dominant_category || 'scanning / attacks'}</strong></div>
                <div>• <strong>7-Day Trend:</strong> Reports <strong>{trend.trend_direction?.toLowerCase() || 'tracked'}</strong> across neighborhood</div>
                <div>• <strong>Future Risk:</strong> <strong>{prob}% probability</strong> of further malicious reports (Calibrated NERD)</div>
                <div>• <strong>Analyst Action:</strong> Prioritize investigation of /24 subnet range, not just isolated host</div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Search Bar & Target Selector ─────────────────────────────────── */}
      <div style={{
        backgroundColor: T.cardSub,
        borderRadius: 12,
        padding: '20px 24px',
        border: `1px solid ${T.border}`,
        marginBottom: 24
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, flexWrap: 'wrap', gap: 8 }}>
          <div style={{ fontSize: 12, fontWeight: 800, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            🎯 Target IP Intelligence Query
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, color: T.textMuted }}>Sample Scenarios:</span>
            {SAMPLE_DEMO_IPS.map(s => (
              <button
                key={s.ip}
                onClick={() => handleSampleClick(s.ip)}
                style={{
                  backgroundColor: targetIP === s.ip ? `${T.accent}22` : T.card,
                  color: targetIP === s.ip ? T.accent : T.textMuted,
                  border: `1px solid ${targetIP === s.ip ? T.accent : T.border}`,
                  borderRadius: 6,
                  padding: '4px 9px',
                  fontSize: 11,
                  fontFamily: 'monospace',
                  cursor: 'pointer',
                  transition: 'all 0.15s'
                }}
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        <form onSubmit={handleSearchSubmit} style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <input
            type="text"
            placeholder="Enter IPv4 address for Threat Intelligence analysis (e.g. 198.51.100.25)"
            value={targetIP}
            onChange={e => setTargetIP(e.target.value)}
            style={{
              flex: '1 1 320px',
              padding: '13px 18px',
              backgroundColor: T.bg,
              border: `1px solid ${T.border}`,
              borderRadius: 8,
              color: T.textMain,
              fontSize: 15,
              fontFamily: 'monospace',
              outline: 'none',
              transition: 'border-color 0.2s'
            }}
            onFocus={e => e.target.style.borderColor = T.accent}
            onBlur={e => e.target.style.borderColor = T.border}
          />
          <button
            type="submit"
            disabled={loading}
            style={{
              padding: '13px 26px',
              backgroundColor: T.accent,
              color: '#020617',
              border: 'none',
              borderRadius: 8,
              cursor: loading ? 'not-allowed' : 'pointer',
              fontWeight: 800,
              fontSize: 14,
              letterSpacing: '0.3px',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              opacity: loading ? 0.7 : 1
            }}
          >
            {loading ? '⟳ Analyzing Pipeline…' : '⚡ Run Predictive Intelligence'}
          </button>
          <button
            type="button"
            onClick={() => fetchThreatIntelligence(targetIP, true)}
            disabled={loading}
            style={{
              padding: '13px 18px',
              backgroundColor: T.card,
              color: T.cyan,
              border: `1px solid ${T.cyan}44`,
              borderRadius: 8,
              cursor: 'pointer',
              fontWeight: 600,
              fontSize: 13
            }}
            title="Recompute fresh intelligence and subnet scan"
          >
            🔄 Refresh
          </button>
        </form>
      </div>

      {/* ── Loading Spinner ──────────────────────────────────────────────── */}
      {loading && (
        <div style={{ textAlign: 'center', padding: '60px 0', color: T.textMuted }}>
          <div style={{ fontSize: 36, marginBottom: 14, animation: 'spin 1s linear infinite', display: 'inline-block' }}>⟳</div>
          <div style={{ fontSize: 16, fontWeight: 700, color: T.accent, marginBottom: 6 }}>
            Generating Threat Intelligence Profile for {targetIP}…
          </div>
          <div style={{ fontSize: 13 }}>
            Correlating /24 subnet clusters · Computing ASN density · Calibrating 8-feature predictive model
          </div>
        </div>
      )}

      {/* ── Error Banner ─────────────────────────────────────────────────── */}
      {!loading && error && (
        <div style={{
          backgroundColor: '#450a0a',
          color: '#fca5a5',
          border: '1px solid #ef4444',
          borderRadius: 8,
          padding: '16px 20px',
          marginBottom: 20
        }}>
          <strong>⚠️ Intelligence Analysis Notice:</strong> {error}
        </div>
      )}

      {/* ── Master Results View ──────────────────────────────────────────── */}
      {!loading && intelData && (
        <div>

          {/* 1. Executive Banner & Predictive Risk Score ─────────────────────── */}
          <div style={{
            backgroundColor: T.cardSub,
            borderRadius: 12,
            border: `1px solid ${riskColor}55`,
            padding: '24px 28px',
            marginBottom: 24,
            display: 'grid',
            gridTemplateColumns: 'auto 1fr',
            gap: 28,
            alignItems: 'center',
            background: `linear-gradient(135deg, ${riskColor}10 0%, ${T.cardSub} 70%)`
          }}>
            {/* Circular Risk Gauge */}
            <div style={{ textAlign: 'center', minWidth: 140 }}>
              <div style={{
                width: 120,
                height: 120,
                borderRadius: '50%',
                margin: '0 auto 10px',
                background: `conic-gradient(${riskColor} ${prob * 3.6}deg, rgba(255,255,255,0.08) 0deg)`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                position: 'relative'
              }}>
                <div style={{
                  width: 94,
                  height: 94,
                  borderRadius: '50%',
                  backgroundColor: T.card,
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <div style={{ fontSize: 26, fontWeight: 900, color: riskColor, lineHeight: 1 }}>{prob}%</div>
                  <div style={{ fontSize: 9, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginTop: 2 }}>
                    Future Risk
                  </div>
                </div>
              </div>
              <div style={{
                padding: '4px 12px',
                borderRadius: 6,
                fontWeight: 800,
                fontSize: 12,
                backgroundColor: `${riskColor}22`,
                color: riskColor,
                border: `1px solid ${riskColor}66`,
                display: 'inline-block'
              }}>
                {riskLevel} RISK
              </div>
            </div>

            {/* Narrative & High-Level Finding */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8, flexWrap: 'wrap' }}>
                <span style={{ fontFamily: 'monospace', fontWeight: 900, fontSize: 22, color: T.accent }}>
                  {intelData.ip}
                </span>
                <span style={{ fontSize: 12, color: T.textMuted }}>·</span>
                <span style={{ fontFamily: 'monospace', fontSize: 13, color: T.cyan, fontWeight: 700 }}>
                  {asn.asn || 'ASUnknown'}
                </span>
                <span style={{ fontSize: 12, color: T.textMuted }}>({asn.org_name || 'Autonomous System'})</span>
                <span style={{
                  fontSize: 10,
                  padding: '2px 8px',
                  borderRadius: 4,
                  fontWeight: 700,
                  backgroundColor: '#1E1B4B',
                  color: T.purple,
                  border: `1px solid ${T.purple}55`
                }}>
                  {pred.confidence || 'MEDIUM'} CONFIDENCE
                </span>
              </div>

              <div style={{
                fontSize: 14,
                color: T.textMain,
                lineHeight: 1.6,
                marginBottom: 14,
                backgroundColor: 'rgba(0,0,0,0.2)',
                padding: '12px 16px',
                borderRadius: 8,
                borderLeft: `4px solid ${riskColor}`
              }}>
                <strong>Executive Finding: </strong>
                {report.executive_narrative || 'Analysis completed.'}
              </div>

              {/* Key Quick Indicators */}
              <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', fontSize: 12 }}>
                <div>
                  <span style={{ color: T.textMuted }}>Subnet /24 Threats: </span>
                  <strong style={{ color: subnet.total_threats_in_subnet > 0 ? T.danger : T.success, fontFamily: 'monospace' }}>
                    {subnet.total_threats_in_subnet || 0} IPs
                  </strong>
                  <span style={{ color: T.textMuted }}> ({subnet.threat_density_pct || 0}% concentration)</span>
                </div>
                <div>
                  <span style={{ color: T.textMuted }}>ASN Threat Rate: </span>
                  <strong style={{ color: asn.threat_rate_pct > 15 ? T.danger : T.cyan, fontFamily: 'monospace' }}>
                    {asn.threat_rate_pct || 0}%
                  </strong>
                  <span style={{ color: T.textMuted }}> ({asn.rate_classification || 'NORMAL'})</span>
                </div>
                <div>
                  <span style={{ color: T.textMuted }}>7-Day Trajectory: </span>
                  <strong style={{ color: trend.trend_direction === 'INCREASING' ? T.danger : T.success }}>
                    {trend.trend_direction === 'INCREASING' ? '▲ INCREASING' : '● ' + (trend.trend_direction || 'STABLE')}
                  </strong>
                </div>
              </div>
            </div>
          </div>

          {/* 2. Two-Column Layout: Evidence Matrix & Analyst Playbook ────────── */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: 24, marginBottom: 24 }}>

            {/* A. "Why Is This IP Suspicious?" Evidence Matrix */}
            <div style={{
              backgroundColor: T.cardSub,
              borderRadius: 12,
              padding: '22px 24px',
              border: `1px solid ${T.border}`
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  🔎 Why Is This IP Suspicious? (Evidence Matrix)
                </div>
                <span style={{ fontSize: 11, color: T.cyan, fontWeight: 600 }}>Multi-Layered Corroboration</span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {report.why_suspicious && report.why_suspicious.map((item, idx) => {
                  const borderCol = item.severity === 'HIGH' ? T.danger : (item.severity === 'MEDIUM' ? T.warning : T.cyan);
                  return (
                    <div
                      key={idx}
                      style={{
                        backgroundColor: T.card,
                        padding: '12px 16px',
                        borderRadius: 8,
                        borderLeft: `4px solid ${borderCol}`,
                        borderTop: `1px solid ${T.border}33`,
                        borderRight: `1px solid ${T.border}33`,
                        borderBottom: `1px solid ${T.border}33`
                      }}
                    >
                      <div style={{ fontWeight: 700, fontSize: 13, color: T.textMain, marginBottom: 4 }}>
                        {item.title}
                      </div>
                      <div style={{ fontSize: 12, color: T.textMuted, lineHeight: 1.5 }}>
                        {item.detail}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* B. Actionable Security Analyst Playbook */}
            <div style={{
              backgroundColor: T.cardSub,
              borderRadius: 12,
              padding: '22px 24px',
              border: `1px solid ${T.border}`
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  🛡️ Security Analyst Playbook & Recommended Actions
                </div>
                <span style={{
                  fontSize: 10,
                  padding: '2px 8px',
                  borderRadius: 4,
                  fontWeight: 800,
                  backgroundColor: '#052e16',
                  color: T.success,
                  border: `1px solid ${T.success}44`
                }}>
                  ACTIONABLE INTEL
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {report.recommended_actions && report.recommended_actions.map((act, idx) => {
                  const isP1 = act.priority.includes('P1');
                  const pColor = isP1 ? T.danger : (act.priority.includes('P2') ? T.warning : T.accent);
                  return (
                    <div
                      key={idx}
                      style={{
                        backgroundColor: T.card,
                        padding: '12px 16px',
                        borderRadius: 8,
                        border: `1px solid ${pColor}33`,
                        position: 'relative'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                        <span style={{
                          fontSize: 10,
                          padding: '2px 7px',
                          borderRadius: 3,
                          fontWeight: 800,
                          backgroundColor: `${pColor}18`,
                          color: pColor,
                          border: `1px solid ${pColor}55`
                        }}>
                          {act.priority}
                        </span>
                        <span style={{ fontSize: 10, color: T.textMuted, textTransform: 'uppercase', fontFamily: 'monospace' }}>
                          Scope: {act.scope}
                        </span>
                      </div>
                      <div style={{ fontWeight: 700, fontSize: 13, color: T.textMain, marginBottom: 4 }}>
                        {act.action}
                      </div>
                      <div style={{ fontSize: 12, color: T.textMuted, lineHeight: 1.5 }}>
                        {act.detail}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

          </div>

          {/* 3. Deep Intelligence: Subnet Clustering & ASN Concentration ──────── */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 24, marginBottom: 24 }}>

            {/* Subnet /24 Neighborhood Clustering */}
            <div style={{
              backgroundColor: T.cardSub,
              borderRadius: 12,
              padding: '22px 24px',
              border: `1px solid ${T.border}`
            }}>
              <div style={{ fontSize: 12, fontWeight: 800, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 14 }}>
                🌐 /24 Subnet Neighborhood Clustering
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <div>
                  <div style={{ fontFamily: 'monospace', fontWeight: 800, fontSize: 16, color: T.cyan }}>
                    {subnet.subnet_prefix || 'Unknown /24'}
                  </div>
                  <div style={{ fontSize: 11, color: T.textMuted, marginTop: 2 }}>
                    Density Class: <strong style={{ color: T.textMain }}>{subnet.density_class}</strong>
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: 22, fontWeight: 900, color: subnet.total_threats_in_subnet > 0 ? T.danger : T.success, fontFamily: 'monospace' }}>
                    {subnet.total_threats_in_subnet || 0} / {subnet.total_observed_in_subnet || 1}
                  </div>
                  <div style={{ fontSize: 11, color: T.textMuted }}>Threat IPs in /24</div>
                </div>
              </div>

              {/* Density Bar */}
              <div style={{ width: '100%', height: 8, backgroundColor: T.bg, borderRadius: 4, overflow: 'hidden', marginBottom: 16 }}>
                <div style={{
                  width: `${Math.min(subnet.threat_density_pct || 0, 100)}%`,
                  height: '100%',
                  backgroundColor: subnet.threat_density_pct > 30 ? T.danger : (subnet.threat_density_pct > 10 ? T.warning : T.success),
                  transition: 'width 0.6s ease'
                }} />
              </div>

              {/* Subnet Hypothesis Box */}
              <div style={{ backgroundColor: T.card, padding: '12px', borderRadius: 8, marginBottom: 14, border: `1px solid ${T.border}33`, fontSize: 12 }}>
                <div style={{ color: T.accent, fontWeight: 700, marginBottom: 3 }}>Analyst Subnet Hypothesis:</div>
                <div style={{ color: T.textMuted, lineHeight: 1.5 }}>{subnet.hypothesis}</div>
              </div>

              {/* Sample Neighbor Threat IPs */}
              {subnet.neighbor_threat_ips && subnet.neighbor_threat_ips.length > 0 && (
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: T.textMuted, textTransform: 'uppercase', marginBottom: 8 }}>
                    Sample Observed Threat Hosts in /24 ({subnet.neighbor_threat_ips.length}):
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {subnet.neighbor_threat_ips.map(nIp => (
                      <span
                        key={nIp}
                        onClick={() => handleSampleClick(nIp)}
                        style={{
                          fontFamily: 'monospace',
                          fontSize: 11,
                          padding: '3px 8px',
                          borderRadius: 4,
                          backgroundColor: nIp === targetIP ? `${T.accent}33` : T.card,
                          color: nIp === targetIP ? T.accent : T.textMain,
                          border: `1px solid ${nIp === targetIP ? T.accent : T.border}`,
                          cursor: 'pointer'
                        }}
                        title="Click to pivot intelligence analysis to this host"
                      >
                        {nIp} ↗
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* ASN Threat Concentration Analysis */}
            <div style={{
              backgroundColor: T.cardSub,
              borderRadius: 12,
              padding: '22px 24px',
              border: `1px solid ${T.border}`
            }}>
              <div style={{ fontSize: 12, fontWeight: 800, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 14 }}>
                🏢 ASN Threat Concentration Analysis
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                <div>
                  <div style={{ fontFamily: 'monospace', fontWeight: 800, fontSize: 16, color: T.purple }}>
                    {asn.asn || 'ASUnknown'}
                  </div>
                  <div style={{ fontSize: 12, color: T.textMuted }}>{asn.org_name || 'Network Carrier'}</div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: 24, fontWeight: 900, color: asn.threat_rate_pct > 15 ? T.danger : T.cyan, fontFamily: 'monospace' }}>
                    {asn.threat_rate_pct || 0}%
                  </div>
                  <div style={{ fontSize: 11, color: T.textMuted }}>Observed Concentration</div>
                </div>
              </div>

              {/* Observed vs Global Explanation Card */}
              <div style={{ backgroundColor: T.card, padding: '12px', borderRadius: 8, marginBottom: 14, border: `1px solid ${T.border}33`, fontSize: 12 }}>
                <div style={{ color: T.cyan, fontWeight: 700, marginBottom: 3 }}>Population Context:</div>
                <div style={{ color: T.textMuted, lineHeight: 1.5 }}>
                  {asn.total_threats?.toLocaleString()} reported threat IPs out of {asn.total_observed?.toLocaleString()} observed IPs.
                  <span style={{ display: 'block', marginTop: 4, fontSize: 11, color: T.textMuted }}>
                    * Denominator represents the observed population in our intelligence dataset, not every IP globally owned by this carrier.
                  </span>
                </div>
              </div>

              {/* Dominant ASN Categories */}
              {asn.dominant_categories && asn.dominant_categories.length > 0 && (
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: T.textMuted, textTransform: 'uppercase', marginBottom: 8 }}>
                    Top Threat Categories in this ASN:
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {asn.dominant_categories.slice(0, 4).map(c => (
                      <div key={c.category} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12 }}>
                        <span style={{ textTransform: 'capitalize', color: CATEGORY_COLORS[c.category] || T.textMain, fontWeight: 600 }}>
                          ● {c.category}
                        </span>
                        <span style={{ fontFamily: 'monospace', color: T.textMuted }}>
                          {c.count} IPs ({c.share_pct}%)
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* 7-Day Threat Trend & Snapshot Engine */}
            <div style={{
              backgroundColor: T.cardSub,
              borderRadius: 12,
              padding: '22px 24px',
              border: `1px solid ${T.border}`
            }}>
              <div style={{ fontSize: 12, fontWeight: 800, color: T.textMuted, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 14 }}>
                📈 7-Day Threat Trend & Snapshot Engine
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                <div>
                  <div style={{ fontWeight: 800, fontSize: 14, color: T.textMain }}>
                    Report Velocity ({trend.subnet_prefix || 'Subnet'})
                  </div>
                  <div style={{ fontSize: 11, color: T.textMuted }}>Daily snapshot persistence</div>
                </div>
                <span style={{
                  padding: '4px 10px',
                  borderRadius: 6,
                  fontWeight: 800,
                  fontSize: 12,
                  backgroundColor: trend.trend_direction === 'INCREASING' ? '#450a0a' : '#052e16',
                  color: trend.trend_direction === 'INCREASING' ? T.danger : T.success,
                  border: `1px solid ${trend.trend_direction === 'INCREASING' ? T.danger : T.success}44`
                }}>
                  {trend.trend_direction === 'INCREASING' ? '▲ INCREASING' : '● ' + (trend.trend_direction || 'STABLE')}
                </span>
              </div>

              {/* Sparkline / Bar Graph */}
              {trend.history_7d && trend.history_7d.length > 0 && (
                <div style={{ marginBottom: 14 }}>
                  <div style={{
                    display: 'flex',
                    alignItems: 'flex-end',
                    gap: 8,
                    height: 80,
                    backgroundColor: T.card,
                    padding: '12px 14px',
                    borderRadius: 8,
                    border: `1px solid ${T.border}33`
                  }}>
                    {trend.history_7d.map((pt, i) => {
                      const maxVal = Math.max(...trend.history_7d.map(p => p.count), 1);
                      const barHeight = Math.max(12, Math.round((pt.count / maxVal) * 56));
                      return (
                        <div key={i} style={{ flex: 1, textAlign: 'center' }}>
                          <div style={{ fontSize: 10, color: T.textMuted, marginBottom: 4, fontFamily: 'monospace' }}>
                            {pt.count}
                          </div>
                          <div style={{
                            height: barHeight,
                            backgroundColor: i === trend.history_7d.length - 1 ? T.accent : `${T.purple}aa`,
                            borderRadius: 3,
                            transition: 'height 0.3s'
                          }} />
                          <div style={{ fontSize: 9, color: T.textMuted, marginTop: 4 }}>
                            {pt.label}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              <div style={{ fontSize: 12, color: T.textMuted, lineHeight: 1.5 }}>
                {trend.summary}
              </div>
            </div>

          </div>

          {/* 4. 8-Feature Vector Transparency Matrix (NERD Aligned) ───────────── */}
          {pred.feature_breakdown && (
            <div style={{
              backgroundColor: T.cardSub,
              borderRadius: 12,
              padding: '22px 24px',
              border: `1px solid ${T.border}`,
              marginBottom: 24
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 800, color: T.textMain }}>
                    🔬 8-Feature Intelligence Model Vector (Predictive Future Misbehavior)
                  </div>
                  <div style={{ fontSize: 11, color: T.textMuted }}>
                    Model extracts individual activity and network neighborhood features (NERDS research methodology)
                  </div>
                </div>
                <span style={{ fontSize: 11, color: T.accent, fontFamily: 'monospace' }}>
                  Calibrated Sigmoid Output
                </span>
              </div>

              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead>
                    <tr style={{ borderBottom: `1px solid ${T.border}`, textAlign: 'left', color: T.textMuted, fontSize: 11, textTransform: 'uppercase' }}>
                      <th style={{ padding: '8px 12px' }}>Feature</th>
                      <th style={{ padding: '8px 12px' }}>Weight</th>
                      <th style={{ padding: '8px 12px' }}>Score</th>
                      <th style={{ padding: '8px 12px' }}>Observed Evidence & Neighborhood Extraction</th>
                      <th style={{ padding: '8px 12px' }}>Risk Impact</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pred.feature_breakdown.map((f, i) => (
                      <tr key={f.feature_id} style={{ borderBottom: `1px solid ${T.border}33`, backgroundColor: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)' }}>
                        <td style={{ padding: '10px 12px', fontWeight: 700, color: T.textMain }}>
                          {i + 1}. {f.feature_name}
                        </td>
                        <td style={{ padding: '10px 12px', fontFamily: 'monospace', color: T.textMuted }}>
                          {f.weight_pct}%
                        </td>
                        <td style={{ padding: '10px 12px', fontFamily: 'monospace', fontWeight: 700, color: f.score > 60 ? T.danger : (f.score > 30 ? T.warning : T.success) }}>
                          {f.score}
                        </td>
                        <td style={{ padding: '10px 12px', color: T.textMuted }}>
                          {f.evidence}
                        </td>
                        <td style={{ padding: '10px 12px' }}>
                          <span style={{
                            padding: '2px 7px',
                            borderRadius: 4,
                            fontSize: 10,
                            fontWeight: 800,
                            backgroundColor: f.impact === 'HIGH' ? '#450a0a' : (f.impact === 'MEDIUM' ? '#422006' : '#052e16'),
                            color: f.impact === 'HIGH' ? T.danger : (f.impact === 'MEDIUM' ? T.warning : T.success)
                          }}>
                            {f.impact}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div style={{ marginTop: 14, fontSize: 11, color: T.textMuted, fontStyle: 'italic', borderTop: `1px solid ${T.border}33`, paddingTop: 10 }}>
                💡 {pred.scientific_disclaimer}
              </div>
            </div>
          )}

        </div>
      )}

    </div>
  );
}
