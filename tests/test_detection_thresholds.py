"""
Unit tests for detection threshold boundary cases.

Tests specific threshold boundary values to verify detection rules
work correctly at exact thresholds, just below, and just above.
"""

import pytest
import pandas as pd
from network_bouncer.detector import apply_detection_rules, calculate_risk_score


class TestDetectionThresholds:
    """Test suite for detection threshold boundary cases."""
    
    def test_ip_exactly_100_connections(self):
        """
        Test IP with exactly 100 connections (boundary case).
        
        Should NOT be marked as suspicious (rule is > 100, not >= 100).
        Validates: Requirement 3.1
        """
        features = pd.DataFrame({
            'srcip': ['192.168.1.1'],
            'total_connections': [100],
            'unique_destinations': [10],
            'unique_ports': [5]
        })
        
        suspicious = apply_detection_rules(features)
        
        # Should NOT be suspicious (100 is not > 100)
        assert len(suspicious) == 0
    
    def test_ip_exactly_50_unique_destinations(self):
        """
        Test IP with exactly 50 unique destinations (boundary case).
        
        Should NOT be marked as suspicious (rule is > 50, not >= 50).
        Validates: Requirement 3.2
        """
        features = pd.DataFrame({
            'srcip': ['192.168.1.1'],
            'total_connections': [75],
            'unique_destinations': [50],
            'unique_ports': [15]
        })
        
        suspicious = apply_detection_rules(features)
        
        # Should NOT be suspicious (50 is not > 50)
        assert len(suspicious) == 0
    
    def test_ip_exactly_30_unique_ports(self):
        """
        Test IP with exactly 30 unique ports (boundary case).
        
        Should NOT be marked as suspicious (rule is > 30, not >= 30).
        Validates: Requirement 3.3
        """
        features = pd.DataFrame({
            'srcip': ['192.168.1.1'],
            'total_connections': [75],
            'unique_destinations': [20],
            'unique_ports': [30]
        })
        
        suspicious = apply_detection_rules(features)
        
        # Should NOT be suspicious (30 is not > 30)
        assert len(suspicious) == 0
    
    def test_ip_99_connections_just_below_threshold(self):
        """
        Test IP with 99 connections (just below threshold).
        
        Should NOT be marked as suspicious.
        Validates: Requirement 3.1
        """
        features = pd.DataFrame({
            'srcip': ['192.168.1.1'],
            'total_connections': [99],
            'unique_destinations': [10],
            'unique_ports': [5]
        })
        
        suspicious = apply_detection_rules(features)
        
        # Should NOT be suspicious
        assert len(suspicious) == 0
    
    def test_ip_101_connections_just_above_threshold(self):
        """
        Test IP with 101 connections (just above threshold).
        
        Should be marked as suspicious.
        Validates: Requirement 3.1
        """
        features = pd.DataFrame({
            'srcip': ['192.168.1.1'],
            'total_connections': [101],
            'unique_destinations': [10],
            'unique_ports': [5]
        })
        
        suspicious = apply_detection_rules(features)
        
        # Should be suspicious (101 > 100)
        assert len(suspicious) == 1
        assert suspicious.iloc[0]['srcip'] == '192.168.1.1'
    
    def test_ip_49_destinations_just_below_threshold(self):
        """
        Test IP with 49 unique destinations (just below threshold).
        
        Should NOT be marked as suspicious.
        Validates: Requirement 3.2
        """
        features = pd.DataFrame({
            'srcip': ['192.168.1.1'],
            'total_connections': [75],
            'unique_destinations': [49],
            'unique_ports': [15]
        })
        
        suspicious = apply_detection_rules(features)
        
        # Should NOT be suspicious
        assert len(suspicious) == 0
    
    def test_ip_51_destinations_just_above_threshold(self):
        """
        Test IP with 51 unique destinations (just above threshold).
        
        Should be marked as suspicious.
        Validates: Requirement 3.2
        """
        features = pd.DataFrame({
            'srcip': ['192.168.1.1'],
            'total_connections': [75],
            'unique_destinations': [51],
            'unique_ports': [15]
        })
        
        suspicious = apply_detection_rules(features)
        
        # Should be suspicious (51 > 50)
        assert len(suspicious) == 1
        assert suspicious.iloc[0]['srcip'] == '192.168.1.1'
    
    def test_ip_29_ports_just_below_threshold(self):
        """
        Test IP with 29 unique ports (just below threshold).
        
        Should NOT be marked as suspicious.
        Validates: Requirement 3.3
        """
        features = pd.DataFrame({
            'srcip': ['192.168.1.1'],
            'total_connections': [75],
            'unique_destinations': [20],
            'unique_ports': [29]
        })
        
        suspicious = apply_detection_rules(features)
        
        # Should NOT be suspicious
        assert len(suspicious) == 0
    
    def test_ip_31_ports_just_above_threshold(self):
        """
        Test IP with 31 unique ports (just above threshold).
        
        Should be marked as suspicious.
        Validates: Requirement 3.3
        """
        features = pd.DataFrame({
            'srcip': ['192.168.1.1'],
            'total_connections': [75],
            'unique_destinations': [20],
            'unique_ports': [31]
        })
        
        suspicious = apply_detection_rules(features)
        
        # Should be suspicious (31 > 30)
        assert len(suspicious) == 1
        assert suspicious.iloc[0]['srcip'] == '192.168.1.1'
    
    def test_all_values_exactly_at_thresholds(self):
        """
        Test IP with all values exactly at thresholds.
        
        Should NOT be marked as suspicious (all rules use >, not >=).
        Validates: Requirements 3.1, 3.2, 3.3
        """
        features = pd.DataFrame({
            'srcip': ['192.168.1.1'],
            'total_connections': [100],
            'unique_destinations': [50],
            'unique_ports': [30]
        })
        
        suspicious = apply_detection_rules(features)
        
        # Should NOT be suspicious (none exceed thresholds)
        assert len(suspicious) == 0
    
    def test_all_values_one_above_thresholds(self):
        """
        Test IP with all values one above thresholds.
        
        Should be marked as suspicious and have risk score of 3.
        Validates: Requirements 3.1, 3.2, 3.3, 4.2, 4.3, 4.4
        """
        features = pd.DataFrame({
            'srcip': ['192.168.1.1'],
            'total_connections': [101],
            'unique_destinations': [51],
            'unique_ports': [31]
        })
        
        suspicious = apply_detection_rules(features)
        scored = calculate_risk_score(suspicious)
        
        # Should be suspicious
        assert len(suspicious) == 1
        
        # Risk score should be 3 (all rules triggered)
        assert scored.iloc[0]['risk_score'] == 3
    
    def test_multiple_ips_at_various_thresholds(self):
        """
        Test multiple IPs at various threshold positions.
        
        Validates: Requirements 3.1, 3.2, 3.3
        """
        features = pd.DataFrame({
            'srcip': ['ip1', 'ip2', 'ip3', 'ip4', 'ip5', 'ip6'],
            'total_connections': [99, 100, 101, 150, 50, 200],
            'unique_destinations': [49, 50, 51, 60, 10, 80],
            'unique_ports': [29, 30, 31, 40, 5, 50]
        })
        
        suspicious = apply_detection_rules(features)
        
        # Only ip3, ip4, and ip6 should be suspicious
        # ip1, ip2: all below or at thresholds
        # ip3: 101 > 100, 51 > 50, 31 > 30 (all rules triggered)
        # ip4: 150 > 100, 60 > 50, 40 > 30 (all rules triggered)
        # ip5: none triggered
        # ip6: 200 > 100, 80 > 50, 50 > 30 (all rules triggered)
        assert len(suspicious) == 3
        suspicious_ips = set(suspicious['srcip'].values)
        assert suspicious_ips == {'ip3', 'ip4', 'ip6'}
    
    def test_risk_score_at_boundary_values(self):
        """
        Test risk scoring with boundary values.
        
        Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5
        """
        features = pd.DataFrame({
            'srcip': ['at_threshold', 'above_threshold', 'mixed'],
            'total_connections': [100, 101, 101],
            'unique_destinations': [50, 51, 50],
            'unique_ports': [30, 31, 30]
        })
        
        scored = calculate_risk_score(features)
        
        # at_threshold: no rules triggered, score = 0
        assert scored[scored['srcip'] == 'at_threshold']['risk_score'].iloc[0] == 0
        
        # above_threshold: all rules triggered, score = 3
        assert scored[scored['srcip'] == 'above_threshold']['risk_score'].iloc[0] == 3
        
        # mixed: only connections rule triggered, score = 1
        assert scored[scored['srcip'] == 'mixed']['risk_score'].iloc[0] == 1
