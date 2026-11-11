import React, { useState, useCallback } from "react";
import { ComposableMap, Geographies, Geography, Sphere, Graticule } from "react-simple-maps";
import { Tooltip } from "react-tooltip";
import 'react-tooltip/dist/react-tooltip.css';

const geoUrl = "https://unpkg.com/world-atlas@2.0.2/countries-50m.json";

// Threat Level Color Palette
const COLORS = {
  empty: "#1E293B",     // Deep Slate (Safe / No Data)
  low: "#3B82F6",       // Blue (1 - 1,000)
  medium: "#EAB308",    // Yellow (1,001 - 10,000)
  high: "#F97316",      // Orange (10,001 - 50,000)
  critical: "#EF4444"   // Red (50,000+)
};

const MapChart = ({ data, onCountrySelect }) => {
  const [rotation, setRotation] = useState([-10, -30, 0]);
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState([0, 0]);

  const handleMouseDown = (e) => {
    setIsDragging(true);
    setDragStart([e.clientX, e.clientY]);
  };

  const handleMouseMove = useCallback(
    (e) => {
      if (isDragging) {
        const dx = e.clientX - dragStart[0];
        const dy = e.clientY - dragStart[1];
        setRotation((r) => [r[0] + dx * 0.5, r[1] - dy * 0.5, r[2]]);
        setDragStart([e.clientX, e.clientY]);
      }
    },
    [isDragging, dragStart]
  );

  const handleMouseUp = () => {
    setIsDragging(false);
  };
  
  const getColor = (countryName) => {
    if (!data || data.length === 0) return COLORS.empty;
    const countryInfo = data.find(d => d.country === countryName);
    if (!countryInfo || countryInfo.indicator_count === 0) return COLORS.empty;
    
    const count = countryInfo.indicator_count;
    if (count > 50000) return COLORS.critical;
    if (count > 10000) return COLORS.high;
    if (count > 1000) return COLORS.medium;
    return COLORS.low;
  };

  return (
    <div 
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
      style={{ width: "100%", position: "relative", backgroundColor: "#0F172A", borderRadius: "8px", overflow: "hidden", cursor: isDragging ? "grabbing" : "grab" }}
    >
      
      {/* FLOATING LEGEND */}
      <div style={{
        position: "absolute",
        bottom: "20px",
        left: "20px",
        backgroundColor: "rgba(30, 41, 59, 0.8)",
        backdropFilter: "blur(4px)",
        padding: "15px",
        borderRadius: "8px",
        border: "1px solid #334155",
        boxShadow: "0 4px 6px rgba(0,0,0,0.3)",
        zIndex: 10,
        color: "#F8FAFC",
        fontSize: "12px",
        fontFamily: "monospace"
      }}>
        <strong style={{ display: "block", marginBottom: "10px", color: "#94A3B8" }}>DENSITY (IPs)</strong>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
          <div style={{ width: "12px", height: "12px", backgroundColor: COLORS.critical, borderRadius: "2px" }}></div> 50,000+ (Critical)
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
          <div style={{ width: "12px", height: "12px", backgroundColor: COLORS.high, borderRadius: "2px" }}></div> 10,000 - 50k (High)
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
          <div style={{ width: "12px", height: "12px", backgroundColor: COLORS.medium, borderRadius: "2px" }}></div> 1,000 - 10k (Medium)
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
          <div style={{ width: "12px", height: "12px", backgroundColor: COLORS.low, borderRadius: "2px" }}></div> 1 - 1k (Low)
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <div style={{ width: "12px", height: "12px", backgroundColor: COLORS.empty, borderRadius: "2px" }}></div> 0 (Clean)
        </div>
      </div>

      <ComposableMap projection="geoOrthographic" projectionConfig={{ scale: 220, rotate: rotation }} style={{ width: "100%", height: "auto" }}>
          <Sphere stroke="#334155" strokeWidth={0.5} />
          <Graticule stroke="#1E293B" strokeWidth={0.5} />
          <Geographies geography={geoUrl}>
            {({ geographies }) =>
              geographies.map((geo) => {
                const countryName = geo.properties.name;
                const countryData = data && data.length > 0 ? data.find(d => d.country === countryName) : null;
                const ipCount = countryData ? countryData.indicator_count.toLocaleString() : "0";

                return (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill={getColor(countryName)}
                    stroke="#0F172A"
                    strokeWidth={0.5}
                    data-tooltip-id="map-tooltip"
                    data-tooltip-content={`${countryName} • ${ipCount} `}
                    onClick={() => onCountrySelect(countryName)}
                    style={{
                      default: { outline: "none", transition: "fill 0.2s" },
                      hover: { fill: "#38BDF8", outline: "none", strokeWidth: 1 },
                      pressed: { outline: "none" },
                    }}
                  />
                );
              })
            }
          </Geographies>
      </ComposableMap>
      <Tooltip id="map-tooltip" style={{ backgroundColor: "#1E293B", color: "#F8FAFC", borderRadius: "6px", padding: "8px 12px", fontSize: "14px", fontWeight: "600", zIndex: 1000, border: "1px solid #334155" }} />
    </div>
  );
};

export default MapChart;