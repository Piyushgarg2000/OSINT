with open('./frontend/src/App.jsx', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace(
    "badge={asnStats ? ${(asnStats.total_analyzed_ips ?? 0).toLocaleString()} Threat IPs Tracked : undefined}",
    "badge={asnStats ? ${(asnStats.global_total_threats ?? 0).toLocaleString()} Threat IPs Tracked : undefined}"
)

with open('./frontend/src/App.jsx', 'w', encoding='utf-8') as f:
    f.write(content)
