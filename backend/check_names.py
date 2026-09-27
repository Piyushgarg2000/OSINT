import pycountry

tr = pycountry.countries.get(alpha_2="TR")
print("TR:", repr(tr.name))

ci = pycountry.countries.get(alpha_2="CI")
print("CI:", repr(ci.name))

sz = pycountry.countries.get(alpha_2="SZ")
print("SZ:", repr(sz.name))

# Check all countries that have files in the repo
import os, glob

repo = os.path.join(os.path.dirname(__file__), "..", "firehol_repo", "geolite2_country")
codes_seen = set()
for fp in glob.glob(os.path.join(repo, "*.*set")):
    bn = os.path.basename(fp)
    parts = bn.split("_")
    if len(parts) >= 2:
        code = parts[-1].split(".")[0].upper()
        if len(code) == 2:
            codes_seen.add(code)

# Now check which ones pycountry can't resolve
print("\nCodes with no pycountry match:")
for code in sorted(codes_seen):
    c = pycountry.countries.get(alpha_2=code)
    if c is None:
        print(f"  {code}: None")
