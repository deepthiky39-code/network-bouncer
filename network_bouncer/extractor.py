"""Feature extraction module for Network Bouncer.

This module provides functionality to aggregate network connection statistics
by source IP address for threat detection analysis.
"""

import pandas as pd
import numpy as np


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract aggregated features grouped by source IP.
    
    Performs statistical aggregation on network connection records to identify
    patterns such as high connection volumes, network scanning, and port scanning.
    
    Args:
        df: DataFrame with network connection records. Must contain columns:
            - srcip: Source IP address
            - dstip: Destination IP address
            - dsport: Destination port number
            
    Returns:
        DataFrame with columns:
        - srcip: Source IP address
        - total_connections: Total connection count from this source IP
        - unique_destinations: Count of unique destination IPs contacted
        - unique_ports: Count of unique destination ports accessed
        
    Example:
        >>> df = pd.DataFrame({
        ...     'srcip': ['192.168.1.1', '192.168.1.1', '10.0.0.1'],
        ...     'dstip': ['10.0.0.5', '10.0.0.6', '172.16.0.1'],
        ...     'dsport': [80, 443, 22]
        ... })
        >>> features = extract_features(df)
        >>> features.columns.tolist()
        ['srcip', 'total_connections', 'unique_destinations', 'unique_ports']
    """
    features = df.groupby('srcip').agg(
        total_connections=('srcip', 'count'),
        unique_destinations=('dstip', 'nunique'),
        unique_ports=('dsport', 'nunique')
    ).reset_index()
    
    return features


def extract_time_window_features(df: pd.DataFrame, window_size: str = '1min') -> pd.DataFrame:
    """
    Extract features within time windows to detect burst attacks.
    
    Groups connections by source IP and time window to identify rapid-fire attacks
    that occur in short time periods. This is critical for detecting:
    - DDoS attacks (burst of connections)
    - Automated scanning tools (rapid probing)
    - Time-based attack patterns
    
    Args:
        df: DataFrame with network connection records. Must contain columns:
            - srcip: Source IP address
            - dstip: Destination IP address
            - dsport: Destination port number
            - stime: Timestamp column (will be converted to datetime)
        window_size: Time window for aggregation. Options:
            - '1min': 1-minute windows (default, best for burst detection)
            - '5min': 5-minute windows
            - '10min': 10-minute windows
            
    Returns:
        DataFrame with columns:
        - srcip: Source IP address
        - time_window: Start of time window
        - total_connections: Connections within this time window
        - unique_destinations: Unique destinations within window
        - unique_ports: Unique ports within window
        - connections_per_second: Rate of connections (burst indicator)
        
    Example:
        >>> df = pd.DataFrame({
        ...     'srcip': ['192.168.1.1'] * 120,
        ...     'dstip': ['10.0.0.' + str(i) for i in range(120)],
        ...     'dsport': [80] * 120,
        ...     'stime': pd.date_range('2024-01-01', periods=120, freq='500ms')
        ... })
        >>> features = extract_time_window_features(df, '1min')
        >>> features.iloc[0]['connections_per_second']
        120.0
    """
    # Check if timestamp column exists
    if 'stime' not in df.columns:
        # Return empty dataframe with expected columns
        return pd.DataFrame(columns=[
            'srcip', 'time_window', 'total_connections',
            'unique_destinations', 'unique_ports', 'connections_per_second'
        ])
    
    # Convert timestamp to datetime if needed
    df_copy = df.copy()
    df_copy['stime'] = pd.to_datetime(df_copy['stime'], errors='coerce')
    
    # Drop rows with invalid timestamps
    df_copy = df_copy.dropna(subset=['stime'])
    
    if len(df_copy) == 0:
        return pd.DataFrame(columns=[
            'srcip', 'time_window', 'total_connections',
            'unique_destinations', 'unique_ports', 'connections_per_second'
        ])
    
    # Group by source IP and time window
    df_copy = df_copy.set_index('stime')
    
    # Calculate window duration in seconds for rate calculation
    window_seconds = {
        '1min': 60,
        '5min': 300,
        '10min': 600
    }.get(window_size, 60)
    
    # Aggregate by source IP and time window
    features = df_copy.groupby([
        'srcip',
        pd.Grouper(freq=window_size)
    ]).agg(
        total_connections=('srcip', 'count'),
        unique_destinations=('dstip', 'nunique'),
        unique_ports=('dsport', 'nunique')
    ).reset_index()
    
    # Rename time index column
    features.rename(columns={features.columns[1]: 'time_window'}, inplace=True)
    
    # Calculate connections per second (burst rate indicator)
    features['connections_per_second'] = features['total_connections'] / window_seconds
    
    return features


def get_max_window_activity(time_window_df: pd.DataFrame) -> pd.DataFrame:
    """
    Get maximum activity across all time windows for each source IP.
    
    For each source IP, finds the time window with the highest activity.
    This identifies the "worst" burst period for each attacker.
    
    Args:
        time_window_df: DataFrame from extract_time_window_features
        
    Returns:
        DataFrame with one row per source IP showing their peak activity window:
        - srcip: Source IP address
        - peak_time_window: Time when peak activity occurred
        - max_connections_in_window: Maximum connections in any window
        - max_destinations_in_window: Maximum destinations in any window
        - max_ports_in_window: Maximum ports in any window
        - max_burst_rate: Maximum connections per second
        
    Example:
        >>> # If IP had 120 connections in first minute, 50 in second minute
        >>> # Result shows the first minute (peak activity)
    """
    if len(time_window_df) == 0:
        return pd.DataFrame(columns=[
            'srcip', 'peak_time_window', 'max_connections_in_window',
            'max_destinations_in_window', 'max_ports_in_window', 'max_burst_rate'
        ])
    
    # Find the time window with maximum connections for each IP
    idx = time_window_df.groupby('srcip')['total_connections'].idxmax()
    peak_windows = time_window_df.loc[idx].copy()
    
    # Also get overall maximums per IP across all windows
    max_stats = time_window_df.groupby('srcip').agg(
        max_connections_in_window=('total_connections', 'max'),
        max_destinations_in_window=('unique_destinations', 'max'),
        max_ports_in_window=('unique_ports', 'max'),
        max_burst_rate=('connections_per_second', 'max')
    ).reset_index()
    
    # Merge to get peak time information
    result = peak_windows[['srcip', 'time_window']].merge(
        max_stats, on='srcip', how='left'
    )
    result.rename(columns={'time_window': 'peak_time_window'}, inplace=True)
    
    return result
