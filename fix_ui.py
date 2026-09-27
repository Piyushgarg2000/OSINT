with open('./frontend/src/App.jsx', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace(
    "label: 'Classified Threat IPs', value: (asnStats.total_analyzed_ips ?? 0).toLocaleString(), sub: 'With behavioral flags'",
    "label: 'Total Threat IPs', value: (asnStats.global_total_threats ?? 0).toLocaleString(), sub: 'With behavioral flags'"
)
content = content.replace(
    "label: 'Autonomous Systems',  value: (asnStats.total_asns ?? 0).toString(),   sub: 'Unique ASNs observed'",
    "label: 'Analyzed ASNs (BGP)',  value: (asnStats.total_analyzed_ips ?? 0).toLocaleString(),   sub: 'IPs with valid routing'"
)

with open('./frontend/src/App.jsx', 'w', encoding='utf-8') as f:
    f.write(content)
