
with open('frontend/src/App.jsx', encoding='utf-8') as f:
    code = f.read()
code = code.replace('value: (asnStats.total_analyzed_ips ?? 0).toLocaleString(),   sub: \'IPs with valid routing\'', 'value: (asnStats.total_asns ?? 0).toLocaleString(),   sub: \'Unique Autonomous Systems\'')
with open('frontend/src/App.jsx', 'w', encoding='utf-8') as f:
    f.write(code)
print('Done')
