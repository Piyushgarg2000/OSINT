import pickle
import os

filepath = 'backend/threat_model_v1.pkl'
if os.path.exists(filepath):
    with open(filepath, 'rb') as f:
        data = pickle.load(f)
        meta = data.get('meta', {})
        print(f"Total Preprocessed IPs used (n_records): {meta.get('n_records')}")
        print(f"Total Threats: {meta.get('n_threats')}")
        print(f"Total Clean: {meta.get('n_clean')}")
else:
    print("Model file not found.")
