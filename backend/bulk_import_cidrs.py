import os
import glob
import ipaddress
import time
from database import get_db
import pycountry

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPO_DIR = os.path.join(BASE_DIR, "firehol_repo")

# ISO 2-letter code to Country Name map
COUNTRY_NAME_MAP = {
    "us": "United States of America", "in": "India", "de": "Germany", "gb": "United Kingdom",
    "uk": "United Kingdom", "fr": "France", "cn": "China", "ru": "Russia", "jp": "Japan",
    "br": "Brazil", "ca": "Canada", "au": "Australia", "sg": "Singapore", "nl": "Netherlands",
    "it": "Italy", "es": "Spain", "se": "Sweden", "ch": "Switzerland", "za": "South Africa"
}

def resolve_country(code: str) -> str:
    code_lower = code.lower().strip()
    if code_lower in COUNTRY_NAME_MAP:
        return COUNTRY_NAME_MAP[code_lower]
    try:
        match = pycountry.countries.get(alpha_2=code_lower.upper())
        if match:
            return match.name
    except Exception:
        pass
    return code.upper()

def main():
    print("=== Starting Global CIDR Bulk Import to MongoDB Atlas ===")
    db = get_db()
    if db is None:
        print("Error: Could not connect to MongoDB Atlas. Please check .env MONGO_URI.")
        return

    collection = db.cidr_geolocations
    print("Resetting cidr_geolocations collection...")
    collection.drop()

    print("Creating Index on (start_ip, end_ip)...")
    collection.create_index([("start_ip", 1), ("end_ip", 1)])
    collection.create_index("country")

    geo_folders = ["geolite2_country", "ip2location_country", "ipdeny_country", "ipip_country"]
    
    total_inserted = 0
    batch_size = 20000
    batch = []
    t_start = time.time()

    for gf in geo_folders:
        gpath = os.path.join(REPO_DIR, gf)
        if not os.path.isdir(gpath):
            continue

        files = glob.glob(os.path.join(gpath, "*.netset")) + glob.glob(os.path.join(gpath, "*.ipset"))
        print(f"\n[Provider: {gf}] Processing {len(files)} country files...")

        for f in files:
            fname = os.path.basename(f)
            cc = fname.split(".")[0].split("_")[-1].lower()
            country_name = resolve_country(cc)

            with open(f, "r", encoding="utf-8", errors="ignore") as fp:
                for line in fp:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                        start_int = int(net.network_address)
                        end_int = int(net.broadcast_address)
                        
                        batch.append({
                            "start_ip": start_int,
                            "end_ip": end_int,
                            "cidr": line,
                            "country": country_name,
                            "provider": gf
                        })

                        if len(batch) >= batch_size:
                            collection.insert_many(batch, ordered=False)
                            total_inserted += len(batch)
                            print(f"  -> Inserted {total_inserted:,} CIDR blocks... ({time.time() - t_start:.1f}s)", end="\r")
                            batch = []
                    except Exception:
                        pass

    if batch:
        collection.insert_many(batch, ordered=False)
        total_inserted += len(batch)

    t_end = time.time()
    print(f"\n\n=======================================================")
    print(f"SUCCESS! Total {total_inserted:,} CIDR Blocks Imported to MongoDB Atlas!")
    print(f"Total Time Taken: {t_end - t_start:.1f} seconds")
    print(f"Total Collection Count: {collection.count_documents({}):,}")
    print(f"=======================================================\n")

if __name__ == "__main__":
    main()
