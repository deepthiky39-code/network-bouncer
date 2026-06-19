"""Property-based tests for detection engine module.

Feature: network-bouncer
"""

import pandas as pd
import pytest
from hypothesis import given, strategies as st, settings
from hypothesis.extra.pandas import data_frames, column

from network_bouncer.detector import apply_detection_rules


# Hypothesis strategies for feature generation
ip_addresses = st.from_regex(r'^(\d{1,3}\.){3}\d{1,3}$', fullmatch=True)

# Strategy for individual feature records
@st.composite
def feature_records(draw):
    """Generate a list of feature records."""
    n_records = draw(st.integers(min_value=0, max_value=20))
    if n_records == 0:
        # Return empty DataFrame with proper columns
        return pd.DataFrame(columns=['srcip', 'total_connections', 'unique_destinations', 'unique_ports'])
    
    records = []
    for _ in range(n_records):
        records.append({
            'srcip': draw(ip_addresses),
            'total_connections': draw(st.integers(min_value=0, max_value=300)),
            'unique_destinations': draw(st.integers(min_value=0, max_value=150)),
            'unique_ports': draw(st.integers(min_value=0, max_value=100))
        })
    return pd.DataFrame(records)


@given(feature_records())
def test_property_4_threshold_detection_completeness(features_df):
    # Feature: network-bouncer, Property 4: Threshold Detection Completeness
    """
    Test that IPs are marked suspicious if and only if at least one rule triggers.
    
    Property: For any source IP with extracted features, the IP SHALL be marked 
    as suspicious if and only if at least one of the following conditions holds:
    - total_connections > 100
    - unique_destinations > 50
    - unique_ports > 30
    
    Validates: Requirements 3.1, 3.2, 3.3, 3.4
    """
    if len(features_df) == 0:
        # Empty input should return empty output
        result = apply_detection_rules(features_df)
        assert len(result) == 0
        return
    
    # Apply detection rules
    suspicious_df = apply_detection_rules(features_df)
    
    # For each row in original features, check if correctly classified
    for idx, row in features_df.iterrows():
        is_high_connections = row['total_connections'] > 100
        is_network_scan = row['unique_destinations'] > 50
        is_port_scan = row['unique_ports'] > 30
        
        # Should be suspicious if ANY rule is triggered
        should_be_suspicious = is_high_connections or is_network_scan or is_port_scan
        
        # Check if this specific row is in suspicious results by comparing all values
        matching_rows = suspicious_df[
            (suspicious_df['srcip'] == row['srcip']) &
            (suspicious_df['total_connections'] == row['total_connections']) &
            (suspicious_df['unique_destinations'] == row['unique_destinations']) &
            (suspicious_df['unique_ports'] == row['unique_ports'])
        ]
        is_in_suspicious = len(matching_rows) > 0
        
        assert is_in_suspicious == should_be_suspicious, (
            f"IP {row['srcip']} with "
            f"connections={row['total_connections']}, "
            f"destinations={row['unique_destinations']}, "
            f"ports={row['unique_ports']} "
            f"should_be_suspicious={should_be_suspicious} but "
            f"is_in_suspicious={is_in_suspicious}"
        )


@given(
    st.integers(min_value=0, max_value=300),
    st.integers(min_value=0, max_value=150),
    st.integers(min_value=0, max_value=100)
)
def test_property_4_boundary_cases(connections, destinations, ports):
    # Feature: network-bouncer, Property 4: Threshold Detection Completeness (boundary cases)
    """
    Test boundary cases: exactly at threshold, just below, just above.
    
    Validates: Requirements 3.1, 3.2, 3.3, 3.4
    """
    features_df = pd.DataFrame({
        'srcip': ['192.168.1.1'],
        'total_connections': [connections],
        'unique_destinations': [destinations],
        'unique_ports': [ports]
    })
    
    suspicious_df = apply_detection_rules(features_df)
    
    # Determine if should be suspicious based on rules
    should_be_suspicious = (
        connections > 100 or
        destinations > 50 or
        ports > 30
    )
    
    if should_be_suspicious:
        assert len(suspicious_df) == 1, (
            f"Expected suspicious entry for connections={connections}, "
            f"destinations={destinations}, ports={ports}"
        )
        assert suspicious_df.iloc[0]['srcip'] == '192.168.1.1'
    else:
        assert len(suspicious_df) == 0, (
            f"Expected no suspicious entry for connections={connections}, "
            f"destinations={destinations}, ports={ports}"
        )


def test_property_4_rule_independence():
    # Feature: network-bouncer, Property 4: Threshold Detection Completeness (rule independence)
    """
    Test that all three rules are evaluated independently.
    
    Validates: Requirements 3.1, 3.2, 3.3, 3.4
    """
    # Test each rule independently
    test_cases = [
        # Only rule 1 triggers (high connections)
        {'srcip': '10.0.0.1', 'total_connections': 101, 'unique_destinations': 10, 'unique_ports': 10, 'expected': True},
        {'srcip': '10.0.0.2', 'total_connections': 100, 'unique_destinations': 10, 'unique_ports': 10, 'expected': False},
        
        # Only rule 2 triggers (network scan)
        {'srcip': '10.0.0.3', 'total_connections': 50, 'unique_destinations': 51, 'unique_ports': 10, 'expected': True},
        {'srcip': '10.0.0.4', 'total_connections': 50, 'unique_destinations': 50, 'unique_ports': 10, 'expected': False},
        
        # Only rule 3 triggers (port scan)
        {'srcip': '10.0.0.5', 'total_connections': 50, 'unique_destinations': 10, 'unique_ports': 31, 'expected': True},
        {'srcip': '10.0.0.6', 'total_connections': 50, 'unique_destinations': 10, 'unique_ports': 30, 'expected': False},
        
        # Multiple rules trigger
        {'srcip': '10.0.0.7', 'total_connections': 101, 'unique_destinations': 51, 'unique_ports': 10, 'expected': True},
        {'srcip': '10.0.0.8', 'total_connections': 101, 'unique_destinations': 10, 'unique_ports': 31, 'expected': True},
        {'srcip': '10.0.0.9', 'total_connections': 101, 'unique_destinations': 51, 'unique_ports': 31, 'expected': True},
        
        # No rules trigger
        {'srcip': '10.0.0.10', 'total_connections': 100, 'unique_destinations': 50, 'unique_ports': 30, 'expected': False},
    ]
    
    for test_case in test_cases:
        features_df = pd.DataFrame([{
            'srcip': test_case['srcip'],
            'total_connections': test_case['total_connections'],
            'unique_destinations': test_case['unique_destinations'],
            'unique_ports': test_case['unique_ports']
        }])
        
        suspicious_df = apply_detection_rules(features_df)
        
        if test_case['expected']:
            assert len(suspicious_df) == 1, (
                f"Expected {test_case['srcip']} to be suspicious with "
                f"connections={test_case['total_connections']}, "
                f"destinations={test_case['unique_destinations']}, "
                f"ports={test_case['unique_ports']}"
            )
        else:
            assert len(suspicious_df) == 0, (
                f"Expected {test_case['srcip']} to NOT be suspicious with "
                f"connections={test_case['total_connections']}, "
                f"destinations={test_case['unique_destinations']}, "
                f"ports={test_case['unique_ports']}"
            )



# Import the new function
from network_bouncer.detector import calculate_risk_score


@st.composite
def risk_score_features(draw):
    """
    Generate features with all combinations of rule triggers (2^3 = 8 combinations).
    
    This ensures we test all possible risk score values (0-3) systematically.
    """
    # Pick one of 8 combinations for rule triggers
    combo = draw(st.integers(min_value=0, max_value=7))
    
    # Decode binary representation to determine which rules trigger
    # Bit 0: connections rule
    # Bit 1: destinations rule  
    # Bit 2: ports rule
    connections_trigger = (combo & 1) != 0
    destinations_trigger = (combo & 2) != 0
    ports_trigger = (combo & 4) != 0
    
    # Generate values based on whether rule should trigger
    if connections_trigger:
        total_connections = draw(st.integers(min_value=101, max_value=300))
    else:
        total_connections = draw(st.integers(min_value=0, max_value=100))
    
    if destinations_trigger:
        unique_destinations = draw(st.integers(min_value=51, max_value=150))
    else:
        unique_destinations = draw(st.integers(min_value=0, max_value=50))
    
    if ports_trigger:
        unique_ports = draw(st.integers(min_value=31, max_value=100))
    else:
        unique_ports = draw(st.integers(min_value=0, max_value=30))
    
    return {
        'srcip': draw(ip_addresses),
        'total_connections': total_connections,
        'unique_destinations': unique_destinations,
        'unique_ports': unique_ports,
        'expected_score': (1 if connections_trigger else 0) + 
                         (1 if destinations_trigger else 0) +
                         (1 if ports_trigger else 0)
    }


@given(st.lists(risk_score_features(), min_size=1, max_size=20))
@settings(deadline=None)
def test_property_5_risk_score_calculation(feature_list):
    # Feature: network-bouncer, Property 5: Risk Score Calculation
    """
    Test that risk score equals count of triggered rules and is always in range [0, 3].
    
    Property: For any source IP with extracted features, the risk score SHALL equal 
    the count of triggered rules, calculated as:
    - +1 if total_connections > 100
    - +1 if unique_destinations > 50
    - +1 if unique_ports > 30
    
    AND the risk score SHALL always be in the range [0, 3].
    
    Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5
    """
    # Extract expected scores before creating DataFrame
    expected_scores = [f['expected_score'] for f in feature_list]
    
    # Create DataFrame from feature list (excluding expected_score)
    features_df = pd.DataFrame([
        {
            'srcip': f['srcip'],
            'total_connections': f['total_connections'],
            'unique_destinations': f['unique_destinations'],
            'unique_ports': f['unique_ports']
        }
        for f in feature_list
    ])
    
    # Calculate risk scores
    scored_df = calculate_risk_score(features_df)
    
    # Verify the DataFrame has risk_score column
    assert 'risk_score' in scored_df.columns, "risk_score column must be present"
    
    # Verify all risk scores are in valid range [0, 3]
    assert (scored_df['risk_score'] >= 0).all(), "All risk scores must be >= 0"
    assert (scored_df['risk_score'] <= 3).all(), "All risk scores must be <= 3"
    
    # Verify each score matches expected value
    for idx, (actual_score, expected_score) in enumerate(zip(scored_df['risk_score'], expected_scores)):
        assert actual_score == expected_score, (
            f"Row {idx}: Expected score {expected_score} but got {actual_score} "
            f"for IP {scored_df.iloc[idx]['srcip']} with "
            f"connections={scored_df.iloc[idx]['total_connections']}, "
            f"destinations={scored_df.iloc[idx]['unique_destinations']}, "
            f"ports={scored_df.iloc[idx]['unique_ports']}"
        )


@given(
    st.integers(min_value=0, max_value=300),
    st.integers(min_value=0, max_value=150),
    st.integers(min_value=0, max_value=100)
)
def test_property_5_individual_rule_scoring(connections, destinations, ports):
    # Feature: network-bouncer, Property 5: Risk Score Calculation (individual rules)
    """
    Test scoring logic for each individual rule.
    
    Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5
    """
    features_df = pd.DataFrame({
        'srcip': ['192.168.1.1'],
        'total_connections': [connections],
        'unique_destinations': [destinations],
        'unique_ports': [ports]
    })
    
    scored_df = calculate_risk_score(features_df)
    actual_score = scored_df.iloc[0]['risk_score']
    
    # Calculate expected score based on rules
    expected_score = 0
    if connections > 100:
        expected_score += 1
    if destinations > 50:
        expected_score += 1
    if ports > 30:
        expected_score += 1
    
    assert actual_score == expected_score, (
        f"Expected score {expected_score} but got {actual_score} "
        f"for connections={connections}, destinations={destinations}, ports={ports}"
    )
    
    # Verify score is in valid range
    assert 0 <= actual_score <= 3, f"Score {actual_score} is outside valid range [0, 3]"


def test_property_5_all_combinations():
    # Feature: network-bouncer, Property 5: Risk Score Calculation (all combinations)
    """
    Test all 8 possible combinations of rule triggers (2^3).
    
    This ensures complete coverage of the scoring logic.
    
    Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5
    """
    test_cases = [
        # (connections, destinations, ports, expected_score, description)
        (50, 25, 15, 0, "No rules triggered"),
        (150, 25, 15, 1, "Only connections rule"),
        (50, 75, 15, 1, "Only destinations rule"),
        (50, 25, 45, 1, "Only ports rule"),
        (150, 75, 15, 2, "Connections + destinations"),
        (150, 25, 45, 2, "Connections + ports"),
        (50, 75, 45, 2, "Destinations + ports"),
        (150, 75, 45, 3, "All rules triggered"),
    ]
    
    for connections, destinations, ports, expected_score, description in test_cases:
        features_df = pd.DataFrame({
            'srcip': ['test.ip'],
            'total_connections': [connections],
            'unique_destinations': [destinations],
            'unique_ports': [ports]
        })
        
        scored_df = calculate_risk_score(features_df)
        actual_score = scored_df.iloc[0]['risk_score']
        
        assert actual_score == expected_score, (
            f"{description}: Expected score {expected_score} but got {actual_score} "
            f"for connections={connections}, destinations={destinations}, ports={ports}"
        )


def test_property_5_empty_dataframe():
    # Feature: network-bouncer, Property 5: Risk Score Calculation (empty input)
    """
    Test that empty DataFrame is handled correctly.
    
    Validates: Requirements 4.1
    """
    empty_df = pd.DataFrame(columns=['srcip', 'total_connections', 'unique_destinations', 'unique_ports'])
    scored_df = calculate_risk_score(empty_df)
    
    # Should return empty DataFrame with risk_score column
    assert len(scored_df) == 0, "Empty input should produce empty output"
    assert 'risk_score' in scored_df.columns, "risk_score column must be present even for empty DataFrame"


def test_property_5_boundary_values():
    # Feature: network-bouncer, Property 5: Risk Score Calculation (boundary values)
    """
    Test exact threshold boundaries to verify > (not >=) is used.
    
    Validates: Requirements 4.2, 4.3, 4.4
    """
    boundary_cases = [
        # At thresholds - should NOT trigger
        (100, 50, 30, 0, "All at thresholds"),
        (101, 50, 30, 1, "Connections just over threshold"),
        (100, 51, 30, 1, "Destinations just over threshold"),
        (100, 50, 31, 1, "Ports just over threshold"),
        # Just below thresholds - should NOT trigger
        (99, 49, 29, 0, "All below thresholds"),
    ]
    
    for connections, destinations, ports, expected_score, description in boundary_cases:
        features_df = pd.DataFrame({
            'srcip': ['boundary.test'],
            'total_connections': [connections],
            'unique_destinations': [destinations],
            'unique_ports': [ports]
        })
        
        scored_df = calculate_risk_score(features_df)
        actual_score = scored_df.iloc[0]['risk_score']
        
        assert actual_score == expected_score, (
            f"{description}: Expected score {expected_score} but got {actual_score}"
        )


# Import the risk classification function
from network_bouncer.detector import classify_risk_level


@given(st.integers(min_value=0, max_value=10))
def test_property_6_risk_level_classification_mapping(risk_score):
    # Feature: network-bouncer, Property 6: Risk Level Classification Mapping
    """
    Test that risk scores are correctly mapped to risk levels.
    
    Property: For any risk score value, the risk classifier SHALL assign the 
    correct risk level according to the mapping:
    - Score 0 → "Normal"
    - Score 1 → "Low"
    - Score 2 → "Medium"
    - Score ≥ 3 → "High"
    
    **Validates: Requirements 5.1, 5.2, 5.3, 5.4**
    """
    risk_level = classify_risk_level(risk_score)
    
    # Verify the mapping is correct
    if risk_score == 0:
        assert risk_level == "Normal", f"Score {risk_score} should map to 'Normal', got '{risk_level}'"
    elif risk_score == 1:
        assert risk_level == "Low", f"Score {risk_score} should map to 'Low', got '{risk_level}'"
    elif risk_score == 2:
        assert risk_level == "Medium", f"Score {risk_score} should map to 'Medium', got '{risk_level}'"
    else:  # risk_score >= 3
        assert risk_level == "High", f"Score {risk_score} should map to 'High', got '{risk_level}'"


def test_property_6_all_risk_score_values():
    # Feature: network-bouncer, Property 6: Risk Level Classification Mapping (exhaustive)
    """
    Test all possible risk score values (0-3) explicitly.
    
    Ensures the mapping is exhaustive and correct for the valid score range.
    
    **Validates: Requirements 5.1, 5.2, 5.3, 5.4**
    """
    # Test the four valid risk score values from the system
    test_cases = [
        (0, "Normal", "Score 0 should map to Normal"),
        (1, "Low", "Score 1 should map to Low"),
        (2, "Medium", "Score 2 should map to Medium"),
        (3, "High", "Score 3 should map to High"),
    ]
    
    for score, expected_level, description in test_cases:
        actual_level = classify_risk_level(score)
        assert actual_level == expected_level, (
            f"{description} - Expected '{expected_level}', got '{actual_level}'"
        )


def test_property_6_boundary_and_beyond():
    # Feature: network-bouncer, Property 6: Risk Level Classification Mapping (boundaries)
    """
    Test boundary conditions and values beyond normal range.
    
    Ensures ≥3 condition works correctly for any value 3 or higher.
    
    **Validates: Requirements 5.4**
    """
    # Test scores at and beyond the upper boundary
    high_risk_scores = [3, 4, 5, 10, 100]
    
    for score in high_risk_scores:
        risk_level = classify_risk_level(score)
        assert risk_level == "High", (
            f"Score {score} (≥3) should map to 'High', got '{risk_level}'"
        )


def test_property_6_return_type():
    # Feature: network-bouncer, Property 6: Risk Level Classification Mapping (type safety)
    """
    Test that the function always returns a string.
    
    **Validates: Requirements 5.1, 5.2, 5.3, 5.4**
    """
    for score in range(0, 5):
        risk_level = classify_risk_level(score)
        assert isinstance(risk_level, str), (
            f"classify_risk_level should return a string, got {type(risk_level)}"
        )
        # Verify it's one of the valid risk levels
        assert risk_level in ["Normal", "Low", "Medium", "High"], (
            f"Invalid risk level returned: '{risk_level}'"
        )


# Import the threat identification function
from network_bouncer.detector import identify_threat_type


@st.composite
def threat_type_features(draw):
    """
    Generate features covering all threat type patterns.
    
    This ensures we test all possible threat type classifications:
    - Potential Backdoor Activity (all three conditions)
    - Network Reconnaissance (connections + destinations)
    - Port Scan (connections + ports)
    - Normal (no pattern)
    """
    # Pick one of the patterns to generate
    pattern = draw(st.sampled_from(['backdoor', 'reconnaissance', 'port_scan', 'normal']))
    
    if pattern == 'backdoor':
        # All three conditions must be met
        return {
            'srcip': draw(ip_addresses),
            'total_connections': draw(st.integers(min_value=101, max_value=300)),
            'unique_destinations': draw(st.integers(min_value=51, max_value=150)),
            'unique_ports': draw(st.integers(min_value=31, max_value=100)),
            'expected_threat': 'Potential Backdoor Activity'
        }
    elif pattern == 'reconnaissance':
        # Connections + destinations, but NOT ports
        return {
            'srcip': draw(ip_addresses),
            'total_connections': draw(st.integers(min_value=101, max_value=300)),
            'unique_destinations': draw(st.integers(min_value=51, max_value=150)),
            'unique_ports': draw(st.integers(min_value=0, max_value=30)),
            'expected_threat': 'Network Reconnaissance'
        }
    elif pattern == 'port_scan':
        # Connections + ports, but NOT destinations
        return {
            'srcip': draw(ip_addresses),
            'total_connections': draw(st.integers(min_value=101, max_value=300)),
            'unique_destinations': draw(st.integers(min_value=0, max_value=50)),
            'unique_ports': draw(st.integers(min_value=31, max_value=100)),
            'expected_threat': 'Port Scan'
        }
    else:  # normal
        # No pattern should match
        # Normal means we DON'T match any of these patterns:
        # - connections > 100 AND destinations > 50 AND ports > 30 (Backdoor)
        # - connections > 100 AND destinations > 50 (Reconnaissance)
        # - connections > 100 AND ports > 30 (Port Scan)
        # 
        # So we need to ensure that we don't match ANY of these patterns
        # The safest approach: ensure connections <= 100 (all patterns require connections > 100)
        
        return {
            'srcip': draw(ip_addresses),
            'total_connections': draw(st.integers(min_value=0, max_value=100)),
            'unique_destinations': draw(st.integers(min_value=0, max_value=150)),
            'unique_ports': draw(st.integers(min_value=0, max_value=100)),
            'expected_threat': 'Normal'
        }


@given(st.lists(threat_type_features(), min_size=1, max_size=20))
@settings(deadline=None)
def test_property_7_threat_type_pattern_matching(feature_list):
    # Feature: network-bouncer, Property 7: Threat Type Pattern Matching
    """
    Test that threat types are assigned according to priority order.
    
    Property: For any source IP with extracted features, the threat identifier 
    SHALL assign the threat type according to the following priority order:
    1. If total_connections > 100 AND unique_destinations > 50 AND unique_ports > 30 
       → "Potential Backdoor Activity"
    2. Else if total_connections > 100 AND unique_destinations > 50 
       → "Network Reconnaissance"
    3. Else if total_connections > 100 AND unique_ports > 30 
       → "Port Scan"
    4. Else → "Normal"
    
    **Validates: Requirements 6.1, 6.2, 6.3, 6.4**
    """
    # Extract expected threat types before creating DataFrame
    expected_threats = [f['expected_threat'] for f in feature_list]
    
    # Create DataFrame from feature list (excluding expected_threat)
    features_df = pd.DataFrame([
        {
            'srcip': f['srcip'],
            'total_connections': f['total_connections'],
            'unique_destinations': f['unique_destinations'],
            'unique_ports': f['unique_ports']
        }
        for f in feature_list
    ])
    
    # Apply threat identification row-wise
    for idx, (_, row) in enumerate(features_df.iterrows()):
        actual_threat = identify_threat_type(row)
        expected_threat = expected_threats[idx]
        
        assert actual_threat == expected_threat, (
            f"Row {idx}: Expected threat type '{expected_threat}' but got '{actual_threat}' "
            f"for IP {row['srcip']} with "
            f"connections={row['total_connections']}, "
            f"destinations={row['unique_destinations']}, "
            f"ports={row['unique_ports']}"
        )


def test_property_7_priority_order():
    # Feature: network-bouncer, Property 7: Threat Type Pattern Matching (priority order)
    """
    Test that most specific pattern (Backdoor) takes precedence over less specific.
    
    Validates that when all three conditions are met, "Potential Backdoor Activity" 
    is returned, not "Network Reconnaissance" or "Port Scan".
    
    **Validates: Requirements 6.1, 6.2, 6.3, 6.4**
    """
    test_cases = [
        # (connections, destinations, ports, expected_threat, description)
        
        # All three conditions met - should be Backdoor (most specific)
        (150, 60, 40, "Potential Backdoor Activity", "All three conditions met"),
        (101, 51, 31, "Potential Backdoor Activity", "All three at minimum threshold"),
        
        # Connections + destinations (no ports) - should be Reconnaissance
        (150, 60, 30, "Network Reconnaissance", "Connections + destinations only"),
        (101, 51, 0, "Network Reconnaissance", "Connections + destinations, zero ports"),
        
        # Connections + ports (no destinations) - should be Port Scan
        (150, 50, 40, "Port Scan", "Connections + ports only"),
        (101, 0, 31, "Port Scan", "Connections + ports, zero destinations"),
        
        # Only connections (no destinations or ports) - should be Normal
        (150, 50, 30, "Normal", "Only connections, at other thresholds"),
        (101, 0, 0, "Normal", "Only connections, zero others"),
        
        # No conditions met - should be Normal
        (100, 50, 30, "Normal", "All at thresholds"),
        (50, 25, 15, "Normal", "All below thresholds"),
        (0, 0, 0, "Normal", "All zero"),
    ]
    
    for connections, destinations, ports, expected_threat, description in test_cases:
        row = pd.Series({
            'srcip': 'test.ip',
            'total_connections': connections,
            'unique_destinations': destinations,
            'unique_ports': ports
        })
        
        actual_threat = identify_threat_type(row)
        
        assert actual_threat == expected_threat, (
            f"{description}: Expected '{expected_threat}' but got '{actual_threat}' "
            f"for connections={connections}, destinations={destinations}, ports={ports}"
        )


def test_property_7_boundary_cases():
    # Feature: network-bouncer, Property 7: Threat Type Pattern Matching (boundary cases)
    """
    Test boundary cases where only some conditions are met.
    
    Verifies that > (not >=) is used for all threshold comparisons.
    
    **Validates: Requirements 6.1, 6.2, 6.3, 6.4**
    """
    boundary_cases = [
        # Test exact thresholds - should NOT trigger
        (100, 50, 30, "Normal", "All at exact thresholds"),
        (101, 50, 30, "Normal", "Only connections over threshold"),
        (100, 51, 30, "Normal", "Only destinations over threshold"),
        (100, 50, 31, "Normal", "Only ports over threshold"),
        
        # Test just over thresholds
        (101, 51, 30, "Network Reconnaissance", "Connections + destinations over"),
        (101, 50, 31, "Port Scan", "Connections + ports over"),
        (100, 51, 31, "Normal", "Destinations + ports over (no connections)"),
        (101, 51, 31, "Potential Backdoor Activity", "All just over threshold"),
        
        # Test just below thresholds
        (99, 49, 29, "Normal", "All just below thresholds"),
        (150, 49, 40, "Port Scan", "High connections + ports but destinations below"),
        (150, 60, 29, "Network Reconnaissance", "High connections + destinations but ports below"),
    ]
    
    for connections, destinations, ports, expected_threat, description in boundary_cases:
        row = pd.Series({
            'srcip': 'boundary.test',
            'total_connections': connections,
            'unique_destinations': destinations,
            'unique_ports': ports
        })
        
        actual_threat = identify_threat_type(row)
        
        assert actual_threat == expected_threat, (
            f"{description}: Expected '{expected_threat}' but got '{actual_threat}'"
        )


def test_property_7_return_type():
    # Feature: network-bouncer, Property 7: Threat Type Pattern Matching (type safety)
    """
    Test that the function always returns a valid threat type string.
    
    **Validates: Requirements 6.1, 6.2, 6.3, 6.4**
    """
    valid_threat_types = [
        "Potential Backdoor Activity",
        "Network Reconnaissance",
        "Port Scan",
        "Normal"
    ]
    
    # Test a variety of feature combinations
    test_values = [
        (0, 0, 0),
        (50, 25, 15),
        (100, 50, 30),
        (101, 51, 31),
        (150, 60, 40),
        (200, 100, 80),
    ]
    
    for connections, destinations, ports in test_values:
        row = pd.Series({
            'srcip': 'type.test',
            'total_connections': connections,
            'unique_destinations': destinations,
            'unique_ports': ports
        })
        
        threat_type = identify_threat_type(row)
        
        assert isinstance(threat_type, str), (
            f"identify_threat_type should return a string, got {type(threat_type)}"
        )
        assert threat_type in valid_threat_types, (
            f"Invalid threat type returned: '{threat_type}'. "
            f"Must be one of {valid_threat_types}"
        )
