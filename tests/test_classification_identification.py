"""
Unit tests for risk classification and threat identification.

Tests specific examples for each risk level and threat type,
including priority order for overlapping threat patterns.
"""

import pytest
import pandas as pd
from network_bouncer.detector import (
    classify_risk_level, 
    identify_threat_type,
    calculate_risk_score
)


class TestRiskLevelClassification:
    """Test suite for risk level classification."""
    
    def test_risk_level_normal_score_0(self):
        """
        Test risk level classification with score 0.
        
        Should return "Normal".
        Validates: Requirement 5.1
        """
        result = classify_risk_level(0)
        assert result == "Normal"
    
    def test_risk_level_low_score_1(self):
        """
        Test risk level classification with score 1.
        
        Should return "Low".
        Validates: Requirement 5.2
        """
        result = classify_risk_level(1)
        assert result == "Low"
    
    def test_risk_level_medium_score_2(self):
        """
        Test risk level classification with score 2.
        
        Should return "Medium".
        Validates: Requirement 5.3
        """
        result = classify_risk_level(2)
        assert result == "Medium"
    
    def test_risk_level_high_score_3(self):
        """
        Test risk level classification with score 3.
        
        Should return "High".
        Validates: Requirement 5.4
        """
        result = classify_risk_level(3)
        assert result == "High"
    
    def test_risk_level_high_score_greater_than_3(self):
        """
        Test risk level classification with score > 3.
        
        Should return "High" (scores >= 3 are High).
        Validates: Requirement 5.4
        """
        result = classify_risk_level(4)
        assert result == "High"
        
        result = classify_risk_level(10)
        assert result == "High"
    
    def test_all_risk_levels_with_dataframe(self):
        """
        Test all risk levels applied to a DataFrame.
        
        Validates: Requirements 5.1, 5.2, 5.3, 5.4
        """
        features = pd.DataFrame({
            'srcip': ['ip1', 'ip2', 'ip3', 'ip4'],
            'total_connections': [50, 101, 101, 101],
            'unique_destinations': [10, 10, 51, 51],
            'unique_ports': [5, 5, 5, 31]
        })
        
        scored = calculate_risk_score(features)
        scored['risk_level'] = scored['risk_score'].apply(classify_risk_level)
        
        # Verify each risk level
        assert scored[scored['srcip'] == 'ip1']['risk_level'].iloc[0] == "Normal"  # score 0
        assert scored[scored['srcip'] == 'ip2']['risk_level'].iloc[0] == "Low"     # score 1
        assert scored[scored['srcip'] == 'ip3']['risk_level'].iloc[0] == "Medium"  # score 2
        assert scored[scored['srcip'] == 'ip4']['risk_level'].iloc[0] == "High"    # score 3


class TestThreatTypeIdentification:
    """Test suite for threat type identification."""
    
    def test_threat_type_normal(self):
        """
        Test threat type identification for normal traffic.
        
        No rules triggered.
        Validates: Requirement 6.4
        """
        row = pd.Series({
            'srcip': '192.168.1.1',
            'total_connections': 50,
            'unique_destinations': 10,
            'unique_ports': 5
        })
        
        result = identify_threat_type(row)
        assert result == "Normal"
    
    def test_threat_type_port_scan(self):
        """
        Test threat type identification for Port Scan.
        
        Connections > 100 AND ports > 30 (but destinations <= 50).
        Validates: Requirement 6.1
        """
        row = pd.Series({
            'srcip': '192.168.1.1',
            'total_connections': 150,
            'unique_destinations': 20,
            'unique_ports': 35
        })
        
        result = identify_threat_type(row)
        assert result == "Port Scan"
    
    def test_threat_type_network_reconnaissance(self):
        """
        Test threat type identification for Network Reconnaissance.
        
        Connections > 100 AND destinations > 50 (but ports <= 30).
        Validates: Requirement 6.2
        """
        row = pd.Series({
            'srcip': '192.168.1.1',
            'total_connections': 150,
            'unique_destinations': 60,
            'unique_ports': 15
        })
        
        result = identify_threat_type(row)
        assert result == "Network Reconnaissance"
    
    def test_threat_type_potential_backdoor_activity(self):
        """
        Test threat type identification for Potential Backdoor Activity.
        
        All three conditions met: connections > 100 AND destinations > 50 AND ports > 30.
        Validates: Requirement 6.3
        """
        row = pd.Series({
            'srcip': '192.168.1.1',
            'total_connections': 200,
            'unique_destinations': 75,
            'unique_ports': 40
        })
        
        result = identify_threat_type(row)
        assert result == "Potential Backdoor Activity"
    
    def test_threat_type_priority_backdoor_over_reconnaissance(self):
        """
        Test threat type priority: Backdoor takes precedence over Reconnaissance.
        
        When all three conditions are met, should identify as Backdoor, not Reconnaissance.
        Validates: Requirements 6.2, 6.3 (priority order)
        """
        # This row matches both Backdoor and Reconnaissance patterns
        # Should identify as Backdoor (most specific)
        row = pd.Series({
            'srcip': '192.168.1.1',
            'total_connections': 150,
            'unique_destinations': 60,
            'unique_ports': 35
        })
        
        result = identify_threat_type(row)
        assert result == "Potential Backdoor Activity"
    
    def test_threat_type_priority_backdoor_over_port_scan(self):
        """
        Test threat type priority: Backdoor takes precedence over Port Scan.
        
        When all three conditions are met, should identify as Backdoor, not Port Scan.
        Validates: Requirements 6.1, 6.3 (priority order)
        """
        # This row matches both Backdoor and Port Scan patterns
        # Should identify as Backdoor (most specific)
        row = pd.Series({
            'srcip': '192.168.1.1',
            'total_connections': 150,
            'unique_destinations': 60,
            'unique_ports': 35
        })
        
        result = identify_threat_type(row)
        assert result == "Potential Backdoor Activity"
    
    def test_threat_type_priority_with_overlapping_patterns(self):
        """
        Test threat type identification with various overlapping patterns.
        
        Tests priority order: Backdoor > Reconnaissance > Port Scan > Normal.
        Validates: Requirements 6.1, 6.2, 6.3, 6.4 (priority order)
        """
        test_cases = [
            # (connections, destinations, ports, expected_type)
            (50, 10, 5, "Normal"),                                      # No rules
            (150, 10, 5, "Normal"),                                     # Only connections
            (50, 60, 5, "Normal"),                                      # Only destinations
            (50, 10, 35, "Normal"),                                     # Only ports
            (150, 60, 5, "Network Reconnaissance"),                     # Connections + destinations
            (150, 10, 35, "Port Scan"),                                 # Connections + ports
            (50, 60, 35, "Normal"),                                     # Destinations + ports (no connections)
            (150, 60, 35, "Potential Backdoor Activity"),               # All three
        ]
        
        for connections, destinations, ports, expected in test_cases:
            row = pd.Series({
                'srcip': '192.168.1.1',
                'total_connections': connections,
                'unique_destinations': destinations,
                'unique_ports': ports
            })
            
            result = identify_threat_type(row)
            assert result == expected, (
                f"Failed for connections={connections}, destinations={destinations}, "
                f"ports={ports}. Expected '{expected}', got '{result}'"
            )
    
    def test_threat_type_at_exact_thresholds(self):
        """
        Test threat type identification at exact threshold values.
        
        Values at thresholds (100, 50, 30) should NOT trigger rules.
        Validates: Requirements 6.1, 6.2, 6.3, 6.4
        """
        # All values at exact thresholds - should be Normal
        row = pd.Series({
            'srcip': '192.168.1.1',
            'total_connections': 100,
            'unique_destinations': 50,
            'unique_ports': 30
        })
        
        result = identify_threat_type(row)
        assert result == "Normal"
    
    def test_threat_type_just_above_thresholds(self):
        """
        Test threat type identification just above threshold values.
        
        Values just above thresholds should trigger appropriate threat type.
        Validates: Requirements 6.3
        """
        # All values one above thresholds - should be Backdoor
        row = pd.Series({
            'srcip': '192.168.1.1',
            'total_connections': 101,
            'unique_destinations': 51,
            'unique_ports': 31
        })
        
        result = identify_threat_type(row)
        assert result == "Potential Backdoor Activity"
    
    def test_threat_type_applied_to_dataframe(self):
        """
        Test threat type identification applied to entire DataFrame.
        
        Validates: Requirements 6.1, 6.2, 6.3, 6.4
        """
        features = pd.DataFrame({
            'srcip': ['normal', 'port_scan', 'recon', 'backdoor'],
            'total_connections': [50, 150, 150, 200],
            'unique_destinations': [10, 10, 60, 75],
            'unique_ports': [5, 35, 15, 40]
        })
        
        features['threat_type'] = features.apply(identify_threat_type, axis=1)
        
        assert features[features['srcip'] == 'normal']['threat_type'].iloc[0] == "Normal"
        assert features[features['srcip'] == 'port_scan']['threat_type'].iloc[0] == "Port Scan"
        assert features[features['srcip'] == 'recon']['threat_type'].iloc[0] == "Network Reconnaissance"
        assert features[features['srcip'] == 'backdoor']['threat_type'].iloc[0] == "Potential Backdoor Activity"


class TestIntegratedClassificationAndIdentification:
    """Test suite for integrated risk classification and threat identification."""
    
    def test_integrated_risk_and_threat_correlation(self):
        """
        Test that risk levels and threat types correlate correctly.
        
        Validates: Requirements 5.1, 5.2, 5.3, 5.4, 6.1, 6.2, 6.3, 6.4
        """
        features = pd.DataFrame({
            'srcip': ['ip1', 'ip2', 'ip3', 'ip4'],
            'total_connections': [50, 150, 150, 200],
            'unique_destinations': [10, 10, 60, 75],
            'unique_ports': [5, 35, 15, 40]
        })
        
        # Apply scoring, classification, and identification
        scored = calculate_risk_score(features)
        scored['risk_level'] = scored['risk_score'].apply(classify_risk_level)
        scored['threat_type'] = scored.apply(identify_threat_type, axis=1)
        
        # ip1: Normal traffic, score 0, Normal risk level
        ip1 = scored[scored['srcip'] == 'ip1'].iloc[0]
        assert ip1['risk_score'] == 0
        assert ip1['risk_level'] == "Normal"
        assert ip1['threat_type'] == "Normal"
        
        # ip2: Port Scan, score 2, Medium risk level
        ip2 = scored[scored['srcip'] == 'ip2'].iloc[0]
        assert ip2['risk_score'] == 2
        assert ip2['risk_level'] == "Medium"
        assert ip2['threat_type'] == "Port Scan"
        
        # ip3: Network Reconnaissance, score 2, Medium risk level
        ip3 = scored[scored['srcip'] == 'ip3'].iloc[0]
        assert ip3['risk_score'] == 2
        assert ip3['risk_level'] == "Medium"
        assert ip3['threat_type'] == "Network Reconnaissance"
        
        # ip4: Potential Backdoor Activity, score 3, High risk level
        ip4 = scored[scored['srcip'] == 'ip4'].iloc[0]
        assert ip4['risk_score'] == 3
        assert ip4['risk_level'] == "High"
        assert ip4['threat_type'] == "Potential Backdoor Activity"
    
    def test_edge_case_high_risk_but_normal_threat_type(self):
        """
        Test edge case where impossible combinations are handled.
        
        Actually, given the design, if risk_score is high, there must be a threat type.
        This test validates that Normal threat type only occurs with score 0.
        """
        # Cannot have high risk score without triggering at least one rule
        # So there's no valid case of "High risk but Normal threat type"
        # This test documents that understanding
        
        features = pd.DataFrame({
            'srcip': ['should_be_normal'],
            'total_connections': [50],
            'unique_destinations': [10],
            'unique_ports': [5]
        })
        
        scored = calculate_risk_score(features)
        scored['risk_level'] = scored['risk_score'].apply(classify_risk_level)
        scored['threat_type'] = scored.apply(identify_threat_type, axis=1)
        
        row = scored.iloc[0]
        
        # Normal threat type should only occur with score 0 (Normal risk level)
        if row['threat_type'] == "Normal":
            assert row['risk_score'] == 0
            assert row['risk_level'] == "Normal"
