"""Property-based tests for feature extraction module.

Tests Property 3: Aggregation Invariants
Validates Requirements: 2.1, 2.2, 2.3, 2.4, 2.5
"""

import pandas as pd
import pytest
from hypothesis import given, strategies as st, settings
from hypothesis.extra.pandas import data_frames, column

from network_bouncer.extractor import extract_features


# Hypothesis strategy for generating IP addresses
ip_addresses = st.from_regex(r'^(\d{1,3}\.){3}\d{1,3}$', fullmatch=True)

# Hypothesis strategy for generating valid port numbers
valid_ports = st.integers(min_value=1, max_value=65535)

# Hypothesis strategy for generating connection records
connection_strategy = data_frames(
    [
        column('srcip', elements=ip_addresses),
        column('dstip', elements=ip_addresses),
        column('dsport', elements=valid_ports),
    ],
    index=st.just(pd.RangeIndex(0, 0))
)


# Feature: network-bouncer, Property 3: Aggregation Invariants
@given(connection_strategy)
@settings(max_examples=100)
def test_property_3_aggregation_invariants(df):
    """
    Property 3: Aggregation Invariants
    
    For any set of connection records grouped by source IP, the following 
    invariants SHALL hold:
    - The sum of connection counts across all source IPs equals the total 
      number of input records
    - For each source IP, unique_destinations ≤ total_connections
    - For each source IP, unique_ports ≤ total_connections
    - The output DataFrame contains exactly the required columns
    
    Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5
    """
    # Skip empty dataframes
    if len(df) == 0:
        return
    
    # Extract features
    features = extract_features(df)
    
    # Invariant 1: Sum of connection counts equals total input records
    assert features['total_connections'].sum() == len(df), \
        f"Sum of connections {features['total_connections'].sum()} != input records {len(df)}"
    
    # Invariant 2: unique_destinations ≤ total_connections for each IP
    assert (features['unique_destinations'] <= features['total_connections']).all(), \
        "Some IPs have more unique destinations than total connections"
    
    # Invariant 3: unique_ports ≤ total_connections for each IP
    assert (features['unique_ports'] <= features['total_connections']).all(), \
        "Some IPs have more unique ports than total connections"
    
    # Invariant 4: Output contains exactly the required columns
    expected_columns = {'srcip', 'total_connections', 'unique_destinations', 'unique_ports'}
    actual_columns = set(features.columns)
    assert actual_columns == expected_columns, \
        f"Column mismatch. Expected: {expected_columns}, Got: {actual_columns}"


# Feature: network-bouncer, Property 3: Aggregation Invariants (Edge Cases)
@given(
    srcip=ip_addresses,
    num_connections=st.integers(min_value=1, max_value=100)
)
@settings(max_examples=100)
def test_property_3_single_source_ip(srcip, num_connections):
    """
    Property 3: Aggregation Invariants (Single Source IP)
    
    Test aggregation for a single source IP with multiple connections.
    Verifies that grouping logic correctly handles single-group scenarios.
    """
    # Generate connections from single source IP
    df = pd.DataFrame({
        'srcip': [srcip] * num_connections,
        'dstip': [f"10.0.0.{i % 255}" for i in range(num_connections)],
        'dsport': [i % 65535 + 1 for i in range(num_connections)]
    })
    
    features = extract_features(df)
    
    # Should have exactly one row
    assert len(features) == 1, f"Expected 1 row, got {len(features)}"
    
    # Should have correct source IP
    assert features.iloc[0]['srcip'] == srcip
    
    # Should have correct total connections
    assert features.iloc[0]['total_connections'] == num_connections
    
    # Unique destinations/ports should be ≤ total connections
    assert features.iloc[0]['unique_destinations'] <= num_connections
    assert features.iloc[0]['unique_ports'] <= num_connections


# Feature: network-bouncer, Property 3: Aggregation Invariants (Multiple IPs)
@given(
    num_ips=st.integers(min_value=1, max_value=20),
    connections_per_ip=st.integers(min_value=1, max_value=50)
)
@settings(max_examples=100)
def test_property_3_multiple_source_ips(num_ips, connections_per_ip):
    """
    Property 3: Aggregation Invariants (Multiple Source IPs)
    
    Test aggregation with multiple source IPs, each having multiple connections.
    Verifies that grouping correctly separates different source IPs.
    """
    # Generate data with multiple distinct source IPs
    data = []
    for ip_idx in range(num_ips):
        srcip = f"192.168.{ip_idx // 255}.{ip_idx % 255}"
        for conn_idx in range(connections_per_ip):
            data.append({
                'srcip': srcip,
                'dstip': f"10.0.{conn_idx // 255}.{conn_idx % 255}",
                'dsport': (conn_idx % 65535) + 1
            })
    
    df = pd.DataFrame(data)
    features = extract_features(df)
    
    # Should have one row per unique source IP
    assert len(features) == num_ips, \
        f"Expected {num_ips} rows, got {len(features)}"
    
    # Each source IP should have correct connection count
    assert (features['total_connections'] == connections_per_ip).all(), \
        f"Not all IPs have {connections_per_ip} connections"
    
    # Total connections should equal total input records
    assert features['total_connections'].sum() == len(df)
