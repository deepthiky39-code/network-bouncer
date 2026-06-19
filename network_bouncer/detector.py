"""Detection engine module for Network Bouncer.

This module provides rule-based threat detection functionality that identifies
suspicious network behavior based on threshold-based detection rules.
"""

import pandas as pd

# Trusted IPs that should be whitelisted (legitimate servers)
TRUSTED_IPS = [
    # Add your trusted infrastructure IPs here
    # Example: DNS servers, web servers, database servers
    # "192.168.1.1",  # Internal DNS
    # "10.0.0.1",     # Gateway
]

# Detection thresholds (can be adjusted for sensitivity)
CONNECTION_THRESHOLD = 100
DESTINATION_THRESHOLD = 50
PORT_THRESHOLD = 30

# Time-window thresholds for burst detection
BURST_CONNECTION_THRESHOLD = 50  # connections per minute
BURST_RATE_THRESHOLD = 1.0  # connections per second


def apply_detection_rules(features_df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply detection rules and return only suspicious entries.
    
    Evaluates three threshold-based detection rules to identify suspicious IPs:
    1. High connection volume: total_connections > 100
    2. Network scanning: unique_destinations > 50
    3. Port scanning: unique_ports > 30
    
    An IP is marked as suspicious if at least one rule is triggered.
    
    Args:
        features_df: DataFrame with extracted features containing columns:
            - srcip: Source IP address
            - total_connections: Total connection count
            - unique_destinations: Unique destination IP count
            - unique_ports: Unique destination port count
            
    Returns:
        DataFrame filtered to only suspicious IPs (at least one rule triggered).
        Contains the same columns as input, filtered to matching rows.
        
    Example:
        >>> features = pd.DataFrame({
        ...     'srcip': ['192.168.1.1', '10.0.0.1', '172.16.0.1'],
        ...     'total_connections': [150, 50, 80],
        ...     'unique_destinations': [60, 10, 20],
        ...     'unique_ports': [40, 5, 10]
        ... })
        >>> suspicious = apply_detection_rules(features)
        >>> len(suspicious)
        1
        >>> suspicious.iloc[0]['srcip']
        '192.168.1.1'
    """
    # Handle empty DataFrame
    if len(features_df) == 0:
        return features_df.copy()
    
    # False Positive Reduction: Filter out trusted IPs
    features_filtered = features_df[~features_df['srcip'].isin(TRUSTED_IPS)].copy()
    
    # Rule 1: High connection volume
    rule_high_connections = features_filtered['total_connections'] > CONNECTION_THRESHOLD
    
    # Rule 2: Network scanning
    rule_network_scan = features_filtered['unique_destinations'] > DESTINATION_THRESHOLD
    
    # Rule 3: Port scanning
    rule_port_scan = features_filtered['unique_ports'] > PORT_THRESHOLD
    
    # Mark as suspicious if ANY rule is triggered
    suspicious_mask = rule_high_connections | rule_network_scan | rule_port_scan
    
    # Filter to return only suspicious entries
    suspicious_df = features_filtered[suspicious_mask].copy()
    
    return suspicious_df


def calculate_risk_score(features_df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate risk score for each source IP based on triggered detection rules.
    
    The risk score is calculated by counting the number of triggered rules:
    - +1 if total_connections > 100
    - +1 if unique_destinations > 50
    - +1 if unique_ports > 30
    
    Risk scores range from 0 (no rules triggered) to 3 (all rules triggered).
    
    Args:
        features_df: DataFrame with extracted features containing columns:
            - srcip: Source IP address
            - total_connections: Total connection count
            - unique_destinations: Unique destination IP count
            - unique_ports: Unique destination port count
            
    Returns:
        DataFrame with added 'risk_score' column (integer values 0-3).
        Original columns are preserved.
        
    Example:
        >>> features = pd.DataFrame({
        ...     'srcip': ['192.168.1.1', '10.0.0.1'],
        ...     'total_connections': [150, 50],
        ...     'unique_destinations': [60, 10],
        ...     'unique_ports': [40, 5]
        ... })
        >>> scored = calculate_risk_score(features)
        >>> scored.iloc[0]['risk_score']
        3
        >>> scored.iloc[1]['risk_score']
        0
    """
    # Handle empty DataFrame
    if len(features_df) == 0:
        result = features_df.copy()
        result['risk_score'] = pd.Series(dtype='int64')
        return result
    
    # Create a copy to avoid modifying original
    result_df = features_df.copy()
    
    # Vectorized scoring: start with score = 0
    risk_score = 0
    
    # Add 1 if total_connections > threshold
    risk_score = risk_score + (result_df['total_connections'] > CONNECTION_THRESHOLD).astype(int)
    
    # Add 1 if unique_destinations > threshold
    risk_score = risk_score + (result_df['unique_destinations'] > DESTINATION_THRESHOLD).astype(int)
    
    # Add 1 if unique_ports > threshold
    risk_score = risk_score + (result_df['unique_ports'] > PORT_THRESHOLD).astype(int)
    
    # Add risk_score column to result
    result_df['risk_score'] = risk_score
    
    return result_df


def calculate_severity_score(features_df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate numerical severity score (0-100) for professional threat assessment.
    
    Provides a fine-grained numerical score that goes beyond categorical risk levels.
    Higher weights are given to more suspicious behaviors:
    - Connections: 0.2 weight (volume indicator)
    - Unique destinations: 0.5 weight (scanning indicator)
    - Unique ports: 1.0 weight (port scan indicator - highest weight)
    
    The score is capped at 100 for normalization and presentation.
    
    Args:
        features_df: DataFrame with extracted features containing:
            - total_connections: Total connection count
            - unique_destinations: Unique destination IP count
            - unique_ports: Unique destination port count
            
    Returns:
        DataFrame with added 'severity_score' column (integer 0-100).
        Original columns are preserved.
        
    Example:
        >>> features = pd.DataFrame({
        ...     'srcip': ['192.168.1.1'],
        ...     'total_connections': [150],
        ...     'unique_destinations': [60],
        ...     'unique_ports': [40]
        ... })
        >>> scored = calculate_severity_score(features)
        >>> scored.iloc[0]['severity_score']  # 150*0.2 + 60*0.5 + 40*1.0 = 100
        100
    """
    # Handle empty DataFrame
    if len(features_df) == 0:
        result = features_df.copy()
        result['severity_score'] = pd.Series(dtype='int64')
        return result
    
    # Create a copy
    result_df = features_df.copy()
    
    # Calculate weighted severity score
    severity = (
        result_df['total_connections'] * 0.2 +
        result_df['unique_destinations'] * 0.5 +
        result_df['unique_ports'] * 1.0
    )
    
    # Cap at 100 and convert to integer
    result_df['severity_score'] = severity.clip(upper=100).astype(int)
    
    return result_df


def classify_risk_level(risk_score: int, severity_score: int = None) -> str:
    """
    Classify risk level based on numerical score and severity.
    
    If severity_score is provided, uses severity-based classification:
    - Severity <= 30 → "Low"
    - Severity <= 70 → "Medium"
    - Severity > 70 → "High"
    
    Otherwise maps risk scores to categorical risk levels:
    - Score 0 → "Normal"
    - Score 1 → "Low"
    - Score 2 → "Medium"
    - Score ≥3 → "High"
    
    Args:
        risk_score: Integer score (0-3) representing threat severity
        severity_score: Optional severity score (0-100) for fine-grained classification
        
    Returns:
        Risk level string: "Normal", "Low", "Medium", or "High"
        
    Example:
        >>> classify_risk_level(2, 100)
        'High'
        >>> classify_risk_level(2, 50)
        'Medium'
        >>> classify_risk_level(1, 20)
        'Low'
        >>> classify_risk_level(0)
        'Normal'
    """
    # If severity score is provided, use severity-based classification
    if severity_score is not None:
        if severity_score <= 30:
            return "Low"
        elif severity_score <= 70:
            return "Medium"
        else:
            return "High"
    
    # Otherwise use risk_score based classification
    if risk_score == 0:
        return "Normal"
    elif risk_score == 1:
        return "Low"
    elif risk_score == 2:
        return "Medium"
    else:  # risk_score >= 3
        return "High"


def identify_threat_type(row: pd.Series) -> str:
    """
    Identify threat type based on behavior patterns.
    
    Evaluates feature values in priority order to classify specific attack patterns:
    1. Potential Backdoor Activity (most specific - all three conditions)
    2. Network Reconnaissance (connections + destinations)
    3. Port Scan (connections + ports)
    4. Normal (no threat pattern matched)
    
    The priority order ensures the most specific pattern is identified first.
    
    Args:
        row: DataFrame row with features including:
            - total_connections: Total connection count
            - unique_destinations: Unique destination IP count
            - unique_ports: Unique destination port count
            
    Returns:
        Threat type string: "Potential Backdoor Activity", "Network Reconnaissance",
        "Port Scan", or "Normal"
        
    Example:
        >>> row = pd.Series({
        ...     'total_connections': 150,
        ...     'unique_destinations': 60,
        ...     'unique_ports': 40
        ... })
        >>> identify_threat_type(row)
        'Potential Backdoor Activity'
        >>> row = pd.Series({
        ...     'total_connections': 150,
        ...     'unique_destinations': 60,
        ...     'unique_ports': 20
        ... })
        >>> identify_threat_type(row)
        'Network Reconnaissance'
    """
    connections = row['total_connections']
    destinations = row['unique_destinations']
    ports = row['unique_ports']
    
    # Check in priority order: most specific pattern first
    
    # 1. Potential Backdoor Activity: all three conditions met
    if connections > CONNECTION_THRESHOLD and destinations > DESTINATION_THRESHOLD and ports > PORT_THRESHOLD:
        return "Potential Backdoor Activity"
    
    # 2. Network Reconnaissance: connections + destinations
    if connections > CONNECTION_THRESHOLD and destinations > DESTINATION_THRESHOLD:
        return "Network Reconnaissance"
    
    # 3. Port Scan: connections + ports
    if connections > CONNECTION_THRESHOLD and ports > PORT_THRESHOLD:
        return "Port Scan"
    
    # 4. Normal: no pattern matched
    return "Normal"


def detect_time_window_threats(time_window_features: pd.DataFrame) -> pd.DataFrame:
    """
    Detect threats based on time-window analysis (burst attacks).
    
    Identifies rapid attacks that occur within short time windows.
    This catches attacks that might be missed by overall aggregation:
    - DDoS bursts (many connections in seconds)
    - Rapid scanning tools
    - Automated attack scripts
    
    Args:
        time_window_features: DataFrame from extract_time_window_features with:
            - srcip: Source IP
            - time_window: Time period
            - total_connections: Connections in this window
            - unique_destinations: Destinations in this window
            - unique_ports: Ports in this window
            - connections_per_second: Burst rate
            
    Returns:
        DataFrame filtered to windows with suspicious burst activity.
        Includes additional 'alert_reason' column explaining the detection.
        
    Example:
        >>> # 120 connections in 1 minute triggers burst alert
        >>> # "HIGH ALERT: 120 connections in 60 seconds"
    """
    if len(time_window_features) == 0:
        result = time_window_features.copy()
        result['alert_reason'] = pd.Series(dtype='str')
        return result
    
    # Filter out trusted IPs
    filtered = time_window_features[
        ~time_window_features['srcip'].isin(TRUSTED_IPS)
    ].copy()
    
    if len(filtered) == 0:
        result = filtered.copy()
        result['alert_reason'] = pd.Series(dtype='str')
        return result
    
    # Detection rules for burst activity
    burst_connections = filtered['total_connections'] > BURST_CONNECTION_THRESHOLD
    high_burst_rate = filtered['connections_per_second'] > BURST_RATE_THRESHOLD
    burst_scan = filtered['unique_destinations'] > (DESTINATION_THRESHOLD / 2)  # Lower threshold for time windows
    burst_port_scan = filtered['unique_ports'] > (PORT_THRESHOLD / 2)
    
    # Mark as suspicious if burst detected
    suspicious_mask = burst_connections | high_burst_rate | burst_scan | burst_port_scan
    suspicious_windows = filtered[suspicious_mask].copy()
    
    # Generate alert reasons
    def generate_alert_reason(row):
        reasons = []
        if row['total_connections'] > BURST_CONNECTION_THRESHOLD:
            reasons.append(f"{int(row['total_connections'])} connections in window")
        if row['connections_per_second'] > BURST_RATE_THRESHOLD:
            reasons.append(f"{row['connections_per_second']:.1f} conn/sec burst rate")
        if row['unique_destinations'] > (DESTINATION_THRESHOLD / 2):
            reasons.append(f"{int(row['unique_destinations'])} destinations scanned")
        if row['unique_ports'] > (PORT_THRESHOLD / 2):
            reasons.append(f"{int(row['unique_ports'])} ports probed")
        return "; ".join(reasons) if reasons else "Suspicious activity"
    
    if len(suspicious_windows) > 0:
        suspicious_windows['alert_reason'] = suspicious_windows.apply(generate_alert_reason, axis=1)
    else:
        suspicious_windows['alert_reason'] = pd.Series(dtype='str')
    
    return suspicious_windows
