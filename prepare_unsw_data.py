"""
Prepare UNSW-NB15 dataset by adding headers to the numbered files.
The numbered files (UNSW-NB15_1.csv to _4.csv) contain the actual network traffic data.
"""

import pandas as pd

# Define column names based on NUSW-NB15_features.csv
# Only keeping the columns we need for analysis
columns = [
    'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes',
    'sttl', 'dttl', 'sloss', 'dloss', 'service', 'sload', 'dload', 'spkts', 'dpkts',
    'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 
    'res_bdy_len', 'sjit', 'djit', 'stime', 'ltime', 'sintpkt', 'dintpkt',
    'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd',
    'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm',
    'ct_src_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
    'attack_cat', 'label'
]

print("📂 Preparing UNSW-NB15 dataset...")
print(f"   Combining files: UNSW-NB15_1.csv to UNSW-NB15_4.csv")

# Read and combine all 4 files
dfs = []
for i in range(1, 5):
    filename = f'network_bouncer/UNSW-NB15_{i}.csv'
    print(f"   Reading {filename}...")
    df = pd.read_csv(filename, header=None, names=columns, low_memory=False)
    dfs.append(df)
    print(f"   ✅ Loaded {len(df)} records")

# Combine all dataframes
print("\n🔗 Combining all files...")
combined_df = pd.concat(dfs, ignore_index=True)

# Save with headers
output_file = 'unsw_nb15_full.csv'
combined_df.to_csv(output_file, index=False)

print(f"\n✅ Dataset prepared successfully!")
print(f"   Output file: {output_file}")
print(f"   Total records: {len(combined_df):,}")
print(f"   Columns: {len(combined_df.columns)}")
print(f"\n🚀 Ready to run analysis with:")
print(f"   python -m network_bouncer.main {output_file}")
