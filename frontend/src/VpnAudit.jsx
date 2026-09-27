import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';

const PRESETS = [
  { label: "Google DNS (Anycast)", ip: "8.8.8.8" },
  { label: "Cloudflare (Anycast)", ip: "1.1.1.1" },
  { label: "Hetzner EU (Datacenter)", ip: "168.119.1.1" },
  { label: "Vultr US (Datacenter)", ip: "108.61.5.83" },
];

const theme = {
  bg:       "#020617",
  card:     "#0F172A",
  cardSub:  "#1E293B",
  border:   "#334155",
  textMain: "#F8FAFC",
  textMuted:"#94A3B8",
  accent:   "#38BDF8",
  cyan:     "#06B6D4",
  success:  "#10B981",
  danger:   "#EF4444",
  warning:  "#F59E0B",
  purple:   "#8B5CF6",
};

function VerdictBadge({ verdict }) {
  let color = theme.textMuted;
  let icon = "🔍";
  let bg = theme.card;
  let border = theme.border;

  if (verdict?.includes("ANYCAST")) {
    color = theme.cyan;
    icon = "🌐";
    bg = "#083344";
    border = "#06b6d4";
  } else if (verdict?.includes("DATACENTER") || verdict?.includes("HOSTING")) {
    color = "#A78BFA";
    icon = "🏢";
    bg = "#2e1065";
    border = "#8b5cf6";
  } else if (verdict?.includes("RESIDENTIAL") || verdict?.includes("ISP")) {
    color = theme.success;
    icon = "🏠";
    bg = "#052e16";
    border = "#10b981";
  } else if (verdict?.includes("DISCREPANCY") || verdict?.includes("DISPUTED")) {
    color = theme.warning;
    icon = "⚠️";
    bg = "#451a03";
    border = "#f59e0b";
  } else if (verdict?.includes("FIREWALLED") || verdict?.includes("UNVERIFIABLE")) {
    color = theme.textMuted;
    icon = "❓";
    bg = "#1e293b";
    border = "#64748b";
  }

  return (
    <div style={{
      display: "inline-flex", alignItems: "center", gap: "10px",
      padding: "10px 18px", borderRadius: "8px",
      backgroundColor: bg, border: `2px solid ${border}`,
      color: color, fontWeight: "800", fontSize: "15px", letterSpacing: "0.5px"
    }}>
      <span style={{ fontSize: "20px" }}>{icon}</span>
      {verdict}
    </div>
  );
}

function ConsensusConfidenceMeter({ score, matchingCount, totalDatabases }) {
  let color = theme.success;
  if (score < 60) color = theme.warning;
  if (score < 40) color = theme.danger;

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "4px", minWidth: "240px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "10px", width: "100%" }}>
        <div style={{ flex: 1, height: "8px", backgroundColor: theme.bg, borderRadius: "4px", overflow: "hidden", border: `1px solid ${theme.border}` }}>
          <div style={{ width: `${score}%`, height: "100%", backgroundColor: color, transition: "width 0.6s ease" }} />
        </div>
        <span style={{ fontSize: "15px", fontWeight: "800", color, fontFamily: "monospace" }}>
          {score}%
        </span>
      </div>
      <span style={{ fontSize: "11px", color: theme.textMuted, fontWeight: "600" }}>
        Geographic Consensus ({matchingCount}/{totalDatabases} Feeds Agree)
      </span>
    </div>
  );
}

function PhysicsCard({ physics }) {
  if (!physics) return null;
  const { geodesic_distance_km, measured_rtt_ms, theoretical_min_rtt_ms, expected_transit_window_ms, physics_violation, vantage_point } = physics;

  return (
    <div style={{ backgroundColor: theme.bg, padding: "18px", borderRadius: "8px", border: `1px solid ${theme.border}` }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
        <div style={{ fontSize: "11px", color: theme.textMuted, textTransform: "uppercase", letterSpacing: "1px", fontWeight: "700" }}>
          🔬 Speed-of-Light & Physics Propagation
        </div>
        <span style={{
          fontSize: "11px", fontWeight: "700", padding: "3px 8px", borderRadius: "4px",
          backgroundColor: physics_violation ? "#450a0a" : "#052e16",
          color: physics_violation ? theme.danger : theme.success,
          border: `1px solid ${physics_violation ? theme.danger : theme.success}`
        }}>
          {physics_violation ? "🚨 Latency Anomaly" : "✅ Physics Compliant"}
        </span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "12px", fontSize: "13px" }}>
        <div>
          <span style={{ color: theme.textMuted }}>Geodesic Distance:</span>{" "}
          <strong style={{ color: theme.textMain }}>{geodesic_distance_km?.toLocaleString()} km</strong>
        </div>
        <div>
          <span style={{ color: theme.textMuted }}>Measured Latency:</span>{" "}
          <strong style={{ color: theme.accent }}>{measured_rtt_ms ? `${measured_rtt_ms} ms` : "N/A"}</strong>
        </div>
        <div>
          <span style={{ color: theme.textMuted }}>Theoretical Min RTT (Fiber):</span>{" "}
          <strong style={{ color: theme.purple }}>{theoretical_min_rtt_ms} ms</strong>
        </div>
        <div>
          <span style={{ color: theme.textMuted }}>Expected Transit Window:</span>{" "}
          <strong style={{ color: theme.cyan }}>{expected_transit_window_ms}</strong>
        </div>
      </div>

      {vantage_point && (
        <div style={{ marginTop: "10px", fontSize: "11px", color: theme.textMuted, borderTop: `1px solid ${theme.border}`, paddingTop: "8px" }}>
          📍 Vantage Point: <strong style={{ color: theme.textMain }}>{vantage_point.label}, {vantage_point.country}</strong> ({vantage_point.lat.toFixed(2)}, {vantage_point.lon.toFixed(2)})
        </div>
      )}
    </div>
  );
}

function ConsensusCard({ consensus, detectedCountry }) {
  if (!consensus) return null;
  const { consensus_percentage, matching_count, total_databases, records, conflicts } = consensus;

  return (
    <div style={{ backgroundColor: theme.bg, padding: "18px", borderRadius: "8px", border: `1px solid ${theme.border}` }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
        <div style={{ fontSize: "11px", color: theme.textMuted, textTransform: "uppercase", letterSpacing: "1px", fontWeight: "700" }}>
          🏛️ Multi-Provider Geolocation Consensus
        </div>
        <span style={{
          fontSize: "11px", fontWeight: "700", padding: "3px 8px", borderRadius: "4px",
          backgroundColor: consensus_percentage >= 70 ? "#052e16" : consensus_percentage >= 50 ? "#451a03" : "#450a0a",
          color: consensus_percentage >= 70 ? theme.success : consensus_percentage >= 50 ? theme.warning : theme.danger,
        }}>
          {matching_count}/{total_databases} Providers Agree ({consensus_percentage}%)
        </span>
      </div>

      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "10px" }}>
        {records && Object.entries(records).map(([db, country]) => {
          const isMatch = country.toLowerCase() === detectedCountry.toLowerCase();
          return (
            <span key={db} style={{
              padding: "5px 12px", borderRadius: "6px", fontSize: "12px",
              backgroundColor: isMatch ? "#064e3b" : "#451a03",
              color: isMatch ? "#6ee7b7" : theme.warning,
              border: `1px solid ${isMatch ? theme.success : theme.warning}`
            }}>
              <strong>{db.toUpperCase()}:</strong> {country} {isMatch ? "✓" : "⚠️"}
            </span>
          );
        })}
      </div>

      {conflicts && conflicts.length > 0 ? (
        <div style={{ fontSize: "12px", color: theme.warning, marginTop: "6px" }}>
          ⚠️ Feed Discrepancy: {conflicts.join(", ")}
        </div>
      ) : (
        <div style={{ fontSize: "12px", color: theme.success, marginTop: "6px" }}>
          ✅ 100% Unanimous Agreement across all IP intelligence feeds.
        </div>
      )}
    </div>
  );
}

function BgpCard({ bgp }) {
  if (!bgp) return null;
  const isAnycast = bgp.infra_type?.includes("ANYCAST");
  const isDatacenter = bgp.infra_type?.includes("DATACENTER");

  return (
    <div style={{ backgroundColor: theme.bg, padding: "18px", borderRadius: "8px", border: `1px solid ${theme.border}` }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
        <div style={{ fontSize: "11px", color: theme.textMuted, textTransform: "uppercase", letterSpacing: "1px", fontWeight: "700" }}>
          🏢 BGP Autonomous System & Infrastructure
        </div>
        <span style={{
          fontSize: "11px", fontWeight: "700", padding: "3px 8px", borderRadius: "4px",
          backgroundColor: isAnycast ? "#083344" : isDatacenter ? "#312e81" : "#052e16",
          color: isAnycast ? theme.cyan : isDatacenter ? "#a5b4fc" : theme.success,
          border: `1px solid ${isAnycast ? theme.cyan : isDatacenter ? "#6366f1" : theme.success}`
        }}>
          {bgp.infra_type}
        </span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", fontSize: "13px" }}>
        <div><span style={{ color: theme.textMuted }}>Organization:</span> <strong style={{ color: theme.textMain }}>{bgp.org}</strong></div>
        <div><span style={{ color: theme.textMuted }}>ASN:</span> <strong style={{ color: theme.accent, fontFamily: "monospace" }}>{bgp.asn}</strong></div>
        <div><span style={{ color: theme.textMuted }}>Registered Location:</span> <strong style={{ color: theme.textMain }}>{bgp.city}, {bgp.country}</strong></div>
        <div><span style={{ color: theme.textMuted }}>Hostname:</span> <strong style={{ color: theme.textMain, fontFamily: "monospace" }}>{bgp.hostname}</strong></div>
      </div>
    </div>
  );
}

function HopsTable({ hops }) {
  if (!hops || hops.length === 0) return (
    <p style={{ color: theme.textMuted, fontStyle: "italic" }}>No traceroute hops captured.</p>
  );

  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", fontFamily: "monospace" }}>
        <thead>
          <tr style={{ borderBottom: `1px solid ${theme.border}` }}>
            {["Hop", "IP Address", "PTR Hostname", "RTT", "Detected Transit Hub / Router Location"].map(h => (
              <th key={h} style={{
                padding: "8px 10px", textAlign: "left", color: theme.textMuted,
                fontFamily: "'Inter', sans-serif", fontWeight: "600", fontSize: "11px",
                textTransform: "uppercase", letterSpacing: "0.5px"
              }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {hops.map((hop, i) => (
            <tr key={i} style={{
              borderBottom: `1px solid ${theme.border}`,
              backgroundColor: hop.detected_location ? "#0c1a2e" : "transparent",
            }}>
              <td style={{ padding: "8px 10px", color: theme.textMuted }}>{hop.hop}</td>
              <td style={{ padding: "8px 10px", color: hop.ip === "*" ? theme.textMuted : theme.accent }}>
                {hop.ip}
              </td>
              <td style={{ padding: "8px 10px", color: theme.textMain, maxWidth: "260px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {hop.hostname !== hop.ip ? hop.hostname : <span style={{ color: theme.textMuted }}>—</span>}
              </td>
              <td style={{ padding: "8px 10px", color: hop.rtt_ms != null ? theme.success : theme.textMuted }}>
                {hop.rtt_ms != null ? `${hop.rtt_ms} ms` : "*"}
              </td>
              <td style={{ padding: "8px 10px" }}>
                {hop.detected_location
                  ? <span style={{
                      color: theme.warning, fontWeight: "700",
                      fontFamily: "'Inter', sans-serif", fontSize: "11px",
                      padding: "2px 8px", borderRadius: "4px", backgroundColor: "#451a0380"
                    }}>
                      📍 {hop.detected_location}
                    </span>
                  : <span style={{ color: theme.textMuted }}>—</span>
                }
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function VpnAudit({ triggerIp, triggerTarget }) {
  const [ip, setIp]                 = useState(triggerTarget?.ip || triggerIp || "");
  const [isAuditing, setIsAuditing] = useState(false);
  const [results, setResults]       = useState(null);
  const [error, setError]           = useState(null);

  const [prevTrigger, setPrevTrigger] = useState(triggerTarget || triggerIp);
  const currentTrigger = triggerTarget || triggerIp;
  if (currentTrigger !== prevTrigger) {
    setPrevTrigger(currentTrigger);
    const newIp = triggerTarget?.ip || (typeof triggerIp === 'string' ? triggerIp : "");
    if (newIp) {
      setIp(newIp);
    }
  }

  const executeAudit = useCallback(async (targetIp, forceRefresh = false) => {
    const finalIp = targetIp || ip;
    if (!finalIp) return;

    setIsAuditing(true);
    setResults(null);
    setError(null);

    try {
      const url = `http://127.0.0.1:8000/api/audit-vpn?ip=${finalIp}${forceRefresh ? '&force_refresh=true' : ''}`;
      const res = await axios.get(url, { timeout: 90000 });
      if (res.data.status === "success") {
        setResults(res.data.results);
      } else {
        setError(res.data.message || "Audit probe failed");
      }
    } catch (err) {
      setError(err.message || "Backend unreachable");
    } finally {
      setIsAuditing(false);
    }
  }, [ip]);

  useEffect(() => {
    if (triggerTarget && triggerTarget.ip) {
      executeAudit(triggerTarget.ip, triggerTarget.forceRefresh);
    } else if (triggerIp && typeof triggerIp === 'string') {
      executeAudit(triggerIp, false);
    }
  }, [triggerTarget, triggerIp, executeAudit]);

  const handleFormSubmit = (e) => {
    e.preventDefault();
    executeAudit(ip, false);
  };

  const applyPreset = (preset) => {
    setIp(preset.ip);
    executeAudit(preset.ip, false);
  };

  return (
    <div style={{
      backgroundColor: theme.card, padding: "24px", borderRadius: "12px",
      marginBottom: "30px", border: `1px solid ${theme.border}`
    }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px", flexWrap: "wrap", gap: "12px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{ fontSize: "28px" }}>🔬</div>
          <div>
            <h3 style={{ margin: 0, color: theme.textMain, fontSize: "19px", fontWeight: "700" }}>
              IP & Infrastructure Forensic Auditor
            </h3>
            <p style={{ margin: "4px 0 0 0", color: theme.textMuted, fontSize: "13px" }}>
              Automated Route Analysis · Multi-Provider Geographic Consensus · Physics & Infrastructure Classification
            </p>
          </div>
        </div>

        {/* Quick Presets */}
        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", alignItems: "center" }}>
          <span style={{ fontSize: "11px", color: theme.textMuted, textTransform: "uppercase", marginRight: "4px" }}>Quick Test:</span>
          {PRESETS.map((p, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => applyPreset(p)}
              disabled={isAuditing}
              style={{
                padding: "5px 10px", fontSize: "11px", fontWeight: "600",
                backgroundColor: theme.cardSub, color: theme.accent,
                border: `1px solid ${theme.border}`, borderRadius: "4px",
                cursor: isAuditing ? "not-allowed" : "pointer"
              }}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Form */}
      <form onSubmit={handleFormSubmit} style={{ display: "flex", gap: "12px", flexWrap: "wrap", alignItems: "center" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: "6px", flex: 1, maxWidth: "450px" }}>
          <label style={{ fontSize: "11px", color: theme.textMuted, textTransform: "uppercase", letterSpacing: "0.5px" }}>
            Target IP Address
          </label>
          <input
            type="text"
            placeholder="Enter IPv4 Address (e.g. 8.8.8.8, 1.1.1.1, 168.119.1.1)"
            value={ip}
            onChange={e => setIp(e.target.value)}
            style={{
              padding: "12px 16px", width: "100%", boxSizing: "border-box", borderRadius: "6px",
              border: `1px solid ${theme.border}`, backgroundColor: theme.bg,
              color: theme.textMain, outline: "none", fontSize: "14px", fontFamily: "monospace"
            }}
          />
        </div>

        <button
          type="submit"
          disabled={isAuditing || !ip}
          style={{
            padding: "12px 32px", backgroundColor: isAuditing ? theme.border : "#7C3AED",
            color: theme.textMain, border: "none", borderRadius: "6px",
            cursor: isAuditing || !ip ? "not-allowed" : "pointer",
            fontWeight: "700", fontSize: "14px", alignSelf: "flex-end"
          }}
        >
          {isAuditing ? "⏳ Tracing & Auditing..." : "🔍 Run Forensic Audit"}
        </button>

        {results && (
          <button
            type="button"
            onClick={() => executeAudit(ip, true)}
            disabled={isAuditing}
            style={{
              padding: "12px 20px", backgroundColor: theme.cardSub, color: theme.cyan,
              border: `1px solid ${theme.cyan}`, borderRadius: "6px",
              cursor: isAuditing ? "not-allowed" : "pointer",
              fontWeight: "600", fontSize: "13px", alignSelf: "flex-end"
            }}
            title="Bypass MongoDB cache and force live multi-hop traceroute and ping probes"
          >
            🔄 Force Re-Audit Live
          </button>
        )}
      </form>

      {isAuditing && (
        <div style={{ marginTop: "16px", padding: "14px 16px", backgroundColor: theme.bg, borderRadius: "8px", border: `1px solid ${theme.border}`, color: theme.accent, fontSize: "13px" }}>
          ⏳ Probing IP telemetry, executing multi-hop traceroute, and verifying 5 independent geographic feeds... Please wait.
        </div>
      )}

      {error && (
        <div style={{ marginTop: "16px", padding: "14px 16px", backgroundColor: "#450a0a", borderRadius: "8px", border: `1px solid ${theme.danger}`, color: theme.danger, fontSize: "13px" }}>
          ❌ {error}
        </div>
      )}

      {results && (
        <div style={{ marginTop: "24px", display: "flex", flexDirection: "column", gap: "18px" }}>
          {/* Verdict Banner */}
          <div style={{
            padding: "18px 20px", backgroundColor: theme.bg, borderRadius: "10px",
            border: `1px solid ${theme.border}`, display: "flex", flexDirection: "column", gap: "14px"
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "14px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
                <VerdictBadge verdict={results.verdict} />
                <span style={{
                  padding: "8px 14px", borderRadius: "8px", fontSize: "14px", fontWeight: "700",
                  backgroundColor: theme.cardSub, color: theme.textMain, border: `1px solid ${theme.border}`
                }}>
                  📍 Detected Location: <strong style={{ color: theme.accent }}>{results.detected_country}</strong>
                </span>
                {results._from_cache && (
                  <span style={{
                    fontSize: "12px", fontWeight: "700", padding: "6px 12px", borderRadius: "6px",
                    backgroundColor: "#052e16", color: theme.success, border: `1px solid ${theme.success}`
                  }}>
                    ⚡ Database Cached ({results._cached_at || 'Recent'})
                  </span>
                )}
              </div>
              <ConsensusConfidenceMeter
                score={results.confidence_score}
                matchingCount={results.database_consensus?.matching_count}
                totalDatabases={results.database_consensus?.total_databases}
              />
            </div>

            <p style={{ margin: 0, color: theme.textMain, fontSize: "14px", lineHeight: "1.6" }}>
              {results.verdict_detail}
            </p>

            {/* Evidence Tags */}
            {results.evidence_tags && results.evidence_tags.length > 0 && (
              <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                {results.evidence_tags.map((tag, idx) => (
                  <span key={idx} style={{
                    padding: "4px 12px", borderRadius: "12px", fontSize: "11px", fontWeight: "600",
                    backgroundColor: theme.cardSub, color: theme.accent, border: `1px solid ${theme.border}`
                  }}>
                    🏷️ {tag}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Evidence Grid */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
            <ConsensusCard consensus={results.database_consensus} detectedCountry={results.detected_country} />
            <BgpCard bgp={results.bgp_info} />
          </div>

          {/* Physics Card */}
          <PhysicsCard physics={results.physics} />

          {/* Transit Path Pills */}
          {results.transit_locations && results.transit_locations.length > 0 && (
            <div style={{ backgroundColor: theme.bg, padding: "16px", borderRadius: "8px", border: `1px solid ${theme.border}` }}>
              <div style={{ fontSize: "11px", color: theme.textMuted, textTransform: "uppercase", letterSpacing: "1px", marginBottom: "8px", fontWeight: "700" }}>
                🛣️ Detected Router Transit Journey
              </div>
              <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                {results.transit_locations.map((loc, idx) => (
                  <span key={idx} style={{
                    padding: "4px 12px", borderRadius: "20px",
                    backgroundColor: "#2d1f00", border: `1px solid ${theme.warning}`,
                    color: theme.warning, fontSize: "12px", fontWeight: "600"
                  }}>
                    {idx + 1}. {loc}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Traceroute Table */}
          <div style={{ backgroundColor: theme.bg, padding: "16px", borderRadius: "8px", border: `1px solid ${theme.border}` }}>
            <div style={{ fontSize: "11px", color: theme.textMuted, textTransform: "uppercase", letterSpacing: "1px", marginBottom: "10px", fontWeight: "700" }}>
              📡 Multi-Hop Traceroute Route — {results.total_hops} Hops ({results.responsive_hops} Responsive)
            </div>
            <HopsTable hops={results.hops} />
          </div>
        </div>
      )}
    </div>
  );
}

export default VpnAudit;


