import urllib.request, json, time

# Wait for data to load in background thread
time.sleep(15)

# 1. Get all country names from backend behavioral_stats
res = urllib.request.urlopen("http://127.0.0.1:8000/api/map-data", timeout=10)
data = json.loads(res.read())
backend_behavior = data["behavior"]
backend_combined = {d["country"] for d in data["data"]["combined"]}
backend_names = set(backend_behavior.keys())

# 2. Get all country names from world-atlas (the map frontend uses)
res2 = urllib.request.urlopen("https://unpkg.com/world-atlas@2.0.2/countries-110m.json")
atlas = json.loads(res2.read())
atlas_names = set()
for geo in atlas["objects"]["countries"]["geometries"]:
    atlas_names.add(geo["properties"]["name"])

# 3. Find mismatches
in_atlas_not_backend = sorted(atlas_names - backend_names)

print("=== WORLD-ATLAS countries NOT in backend behavioral_stats ===")
if in_atlas_not_backend:
    for n in in_atlas_not_backend:
        print(f"  MISSING: {repr(n)}")
else:
    print("  NONE! All map countries have behavioral data!")

print()
print(f"Atlas countries: {len(atlas_names)}")
print(f"Backend behavioral_stats countries: {len(backend_names)}")
print(f"Backend combined map countries: {len(backend_combined)}")
print(f"Missing from backend: {len(in_atlas_not_backend)}")

# 4. Verify specific problem countries
print()
print("=== Verifying previously broken countries ===")
test_countries = [
    "Turkey", "Iran", "South Korea", "Vietnam", "Bolivia", "Syria",
    "Taiwan", "Moldova", "Venezuela", "Laos", "Dem. Rep. Congo",
    "Bosnia and Herz.", "North Korea", "Dominican Rep.", "Brunei",
    "Central African Rep.", "Eq. Guinea", "eSwatini", "Kosovo",
    "Macedonia", "Falkland Is.", "Solomon Is.", "S. Sudan",
    "Czechia", "Palestine"
]
for c in test_countries:
    if c in backend_names:
        print(f"  OK  {c}")
    else:
        print(f"  FAIL  {c}")
