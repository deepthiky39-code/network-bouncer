"""
Create a demonstration dataset with time-window burst attacks.

This script generates a sample UNSW-NB15 format CSV file that demonstrates:
1. Normal traffic patterns
2. Burst attack (120 connections in 60 seconds)
3. Port scanning behavior
4. Network reconnaissance
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta

def create_demo_dataset():
    """Create demonstration dataset with burst attacks."""
    
    records = []
    base_time = datetime(2024, 1, 1, 10, 45, 0)
    
    # 1. Normal traffic from legitimate IP
    print("Creating normal traffic...")
    for i in range(50):
        records.append({
            'srcip': '10.0.0.100',
            'dstip': f'192.168.1.{i % 10}',
            'dsport': np.random.choice([80, 443, 22]),
            'proto': 'tcp',
            'state': 'FIN',
            'label': 0,
            'stime': base_time + timedelta(minutes=i),  # Spread over 50 minutes
            'sport': np.random.randint(40000, 60000)
        })
    
    # 2. BURST ATTACK - 120 connections in 60 seconds
    print("Creating burst attack (HIGH ALERT expected)...")
    attacker_ip = '203.0.113.50'
    for i in range(120):
        records.append({
            'srcip': attacker_ip,
            'dstip': f'192.168.1.{i % 80}',  # Scanning 80 different targets
            'dsport': np.random.choice([21, 22, 23, 80, 443, 3389, 8080]),
            'proto': 'tcp',
            'state': 'INT',
            'label': 1,
            'stime': base_time + timedelta(seconds=i * 0.5),  # 0.5 seconds apart = 2 conn/sec
            'sport': np.random.randint(40000, 60000)
        })
    
    # 3. Port scanning - spread over 10 minutes (slower attack)
    print("Creating port scan attack...")
    scanner_ip = '198.51.100.75'
    for i in range(150):
        records.append({
            'srcip': scanner_ip,
            'dstip': '192.168.1.5',  # Same target
            'dsport': 1000 + i,  # Sequential port scan
            'proto': 'tcp',
            'state': 'REQ',
            'label': 1,
            'stime': base_time + timedelta(seconds=i * 4),  # 4 seconds apart
            'sport': np.random.randint(40000, 60000)
        })
    
    # 4. Network reconnaissance - probing many IPs
    print("Creating network reconnaissance...")
    recon_ip = '172.16.0.200'
    for i in range(140):
        records.append({
            'srcip': recon_ip,
            'dstip': f'10.0.0.{i}',  # Different IP each time
            'dsport': np.random.choice([80, 443]),
            'proto': 'tcp',
            'state': 'INT',
            'label': 1,
            'stime': base_time + timedelta(seconds=i * 2),
            'sport': np.random.randint(40000, 60000)
        })
    
    # Create DataFrame
    df = pd.DataFrame(records)
    
    # Save to CSV
    output_file = 'demo_burst_attacks.csv'
    df.to_csv(output_file, index=False)
    print(f"\n✅ Demo dataset created: {output_file}")
    print(f"   Total records: {len(df)}")
    print(f"   Normal traffic: 50 records from 10.0.0.100")
    print(f"   BURST ATTACK: 120 records in 60 seconds from {attacker_ip}")
    print(f"   Port scan: 150 records from {scanner_ip}")
    print(f"   Reconnaissance: 140 records from {recon_ip}")
    print(f"\nRun: python network_bouncer/main.py {output_file}")
    print("Expected output: Burst alert for", attacker_ip)
    
    return output_file

if __name__ == "__main__":
    create_demo_dataset()
