"""
Integration Tests for Network Bouncer

Tests end-to-end workflows and I/O operations.
"""

import pytest
import os
import pandas as pd
from PIL import Image
import tempfile
import shutil
from io import StringIO
import sys
import logging

from network_bouncer.main import main, display_console_output


class TestEndToEndIntegration:
    """
    Task 15.1: End-to-end integration test
    
    Tests the full pipeline from CSV input to all outputs.
    Validates: All requirements (end-to-end validation)
    """
    
    def test_full_pipeline_with_suspicious_activity(self, tmp_path):
        """
        Test complete pipeline execution with dataset containing suspicious activity.
        
        Verifies:
        - Console output appears correctly
        - CSV report file is created with correct content
        - All PNG chart files are created and are valid images
        """
        # Setup: Copy fixture to temp directory and change to it
        fixture_path = os.path.join("tests", "fixtures", "suspicious_activity.csv")
        test_csv = tmp_path / "test_data.csv"
        shutil.copy(fixture_path, test_csv)
        
        # Change to temp directory so outputs are created there
        original_dir = os.getcwd()
        os.chdir(tmp_path)
        
        try:
            # Capture console output
            captured_output = StringIO()
            sys.stdout = captured_output
            
            # Execute main pipeline
            main(str(test_csv))
            
            # Restore stdout
            sys.stdout = sys.__stdout__
            console_output = captured_output.getvalue()
            
            # Verify console output contains expected elements
            assert "SUSPICIOUS NETWORK ACTIVITY DETECTED" in console_output
            assert "Source IP" in console_output
            assert "Connections" in console_output
            assert "Destinations" in console_output
            assert "Ports" in console_output
            assert "Risk Level" in console_output
            assert "Threat Type" in console_output
            assert "attacker1.com" in console_output
            assert "Total suspicious IPs:" in console_output
            
            # Verify CSV report was created
            csv_report_path = tmp_path / "suspicious_report.csv"
            assert csv_report_path.exists(), "CSV report should be created"
            
            # Verify CSV report content
            report_df = pd.read_csv(csv_report_path)
            assert len(report_df) > 0, "CSV report should contain suspicious entries"
            
            # Check CSV columns
            expected_columns = [
                "Source IP",
                "Total Connections",
                "Unique Destinations",
                "Unique Ports",
                "Score",
                "Risk Level",
                "Threat Type"
            ]
            for col in expected_columns:
                assert col in report_df.columns, f"CSV should contain '{col}' column"
            
            # Verify content makes sense
            assert "attacker1.com" in report_df["Source IP"].values
            assert report_df["Total Connections"].max() > 100, "Should detect high connection volume"
            
            # Verify PNG chart files were created
            chart_files = [
                "suspicious_ips_connections.png",
                "risk_level_distribution.png",
                "top_10_active_ips.png"
            ]
            
            for chart_file in chart_files:
                chart_path = tmp_path / chart_file
                assert chart_path.exists(), f"{chart_file} should be created"
                
                # Verify it's a valid PNG image
                try:
                    img = Image.open(chart_path)
                    assert img.format == "PNG", f"{chart_file} should be a PNG image"
                    assert img.size[0] > 0 and img.size[1] > 0, f"{chart_file} should have valid dimensions"
                    img.close()
                except Exception as e:
                    pytest.fail(f"{chart_file} is not a valid image: {e}")
            
        finally:
            # Restore original directory
            os.chdir(original_dir)
    
    def test_full_pipeline_with_no_suspicious_activity(self, tmp_path):
        """
        Test complete pipeline with dataset that produces no suspicious entries.
        
        Verifies:
        - System completes successfully
        - Empty CSV report created with headers only
        - Visualization generation handles empty data gracefully
        """
        # Setup: Create a dataset with only normal traffic
        test_csv = tmp_path / "normal_traffic.csv"
        normal_data = pd.DataFrame({
            'srcip': ['192.168.1.1', '192.168.1.2', '192.168.1.3'],
            'dstip': ['10.0.0.1', '10.0.0.2', '10.0.0.3'],
            'dsport': [80, 443, 22],
            'proto': ['tcp', 'tcp', 'tcp'],
            'state': ['CON', 'CON', 'FIN'],
            'label': [0, 0, 0]
        })
        normal_data.to_csv(test_csv, index=False)
        
        # Change to temp directory
        original_dir = os.getcwd()
        os.chdir(tmp_path)
        
        try:
            # Capture console output
            captured_output = StringIO()
            sys.stdout = captured_output
            
            # Execute main pipeline - should complete without error
            main(str(test_csv))
            
            # Restore stdout
            sys.stdout = sys.__stdout__
            console_output = captured_output.getvalue()
            
            # Verify console output indicates no suspicious activity
            assert "No suspicious activity detected" in console_output or "Total suspicious IPs: 0" in console_output
            
            # Verify CSV report was created
            csv_report_path = tmp_path / "suspicious_report.csv"
            assert csv_report_path.exists(), "CSV report should be created even with no suspicious activity"
            
            # Verify CSV has headers but no data rows (or 0 rows)
            report_df = pd.read_csv(csv_report_path)
            assert len(report_df) == 0, "CSV report should be empty"
            
            # Verify columns exist (headers only)
            expected_columns = [
                "Source IP",
                "Total Connections",
                "Unique Destinations",
                "Unique Ports",
                "Score",
                "Risk Level",
                "Threat Type"
            ]
            for col in expected_columns:
                assert col in report_df.columns, f"CSV should contain '{col}' header"
            
            # Verify PNG charts were created (even if empty)
            chart_files = [
                "suspicious_ips_connections.png",
                "risk_level_distribution.png",
                "top_10_active_ips.png"
            ]
            
            for chart_file in chart_files:
                chart_path = tmp_path / chart_file
                assert chart_path.exists(), f"{chart_file} should be created even with no suspicious activity"
                
                # Verify it's a valid PNG image
                img = Image.open(chart_path)
                assert img.format == "PNG"
                img.close()
                
        finally:
            # Restore original directory
            os.chdir(original_dir)
    
    def test_console_output_formatting(self):
        """
        Test that console output is properly formatted and readable.
        """
        # Create sample suspicious data
        suspicious_df = pd.DataFrame({
            'srcip': ['192.168.1.1', '10.0.0.5'],
            'total_connections': [150, 120],
            'unique_destinations': [60, 40],
            'unique_ports': [40, 35],
            'risk_level': ['High', 'Medium'],
            'threat_type': ['Potential Backdoor Activity', 'Port Scan']
        })
        
        # Capture console output
        captured_output = StringIO()
        sys.stdout = captured_output
        
        display_console_output(suspicious_df)
        
        # Restore stdout
        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        
        # Verify formatting elements
        assert "=" * 60 in output, "Should have header separator"
        assert "SUSPICIOUS NETWORK ACTIVITY DETECTED" in output
        assert "Source IP" in output
        assert "192.168.1.1" in output
        assert "10.0.0.5" in output
        assert "150" in output
        assert "120" in output
        assert "High" in output
        assert "Medium" in output
        assert "Potential Backdoor Activity" in output
        assert "Port Scan" in output
        assert "Total suspicious IPs: 2" in output


class TestErrorRecoveryIntegration:
    """
    Task 15.2: Integration test for error recovery
    
    Tests that the system handles corrupted data gracefully.
    Validates: Requirements 1.5, 1.6, 1.7, 10.4, 10.5, 10.6
    """
    
    def test_partial_corruption_recovery(self, tmp_path, caplog):
        """
        Test that system processes valid data despite corruption.
        
        Verifies:
        - Valid data is processed despite corrupted rows
        - Warnings are logged appropriately
        - Outputs contain valid entries only
        """
        # Setup: Use corrupted dataset fixture
        fixture_path = os.path.join("tests", "fixtures", "corrupted_data.csv")
        test_csv = tmp_path / "corrupted_test.csv"
        shutil.copy(fixture_path, test_csv)
        
        # Change to temp directory
        original_dir = os.getcwd()
        os.chdir(tmp_path)
        
        try:
            # Enable logging capture
            with caplog.at_level(logging.WARNING):
                # Capture console output
                captured_output = StringIO()
                sys.stdout = captured_output
                
                # Execute main pipeline - should complete despite corruption
                main(str(test_csv))
                
                # Restore stdout
                sys.stdout = sys.__stdout__
            
            # Verify warnings were logged about data issues
            log_text = caplog.text.lower()
            # Should have warnings about dropped rows or invalid values
            assert "warning" in log_text or "dropped" in log_text or "invalid" in log_text, \
                "Should log warnings about data quality issues"
            
            # Verify CSV report was created with valid entries only
            csv_report_path = tmp_path / "suspicious_report.csv"
            assert csv_report_path.exists(), "CSV report should be created"
            
            # Read report and verify it only contains valid data
            report_df = pd.read_csv(csv_report_path)
            
            # Check that any entries have valid IP addresses (not empty or corrupted)
            if len(report_df) > 0:
                for ip in report_df["Source IP"]:
                    assert isinstance(ip, str), "IP should be a string"
                    assert ip != "", "IP should not be empty"
                    # Should not contain obviously corrupted values
                    assert "this" not in ip.lower(), "Should not contain corrupted data"
                    assert "broken" not in ip.lower(), "Should not contain corrupted data"
            
            # Verify PNG charts were created
            chart_files = [
                "suspicious_ips_connections.png",
                "risk_level_distribution.png",
                "top_10_active_ips.png"
            ]
            
            for chart_file in chart_files:
                chart_path = tmp_path / chart_file
                assert chart_path.exists(), f"{chart_file} should be created despite data corruption"
                
        finally:
            # Restore original directory
            os.chdir(original_dir)
    
    def test_missing_values_handling(self, tmp_path, caplog):
        """
        Test that system handles missing values in dataset.
        
        Verifies:
        - Rows with missing critical values are dropped
        - System continues processing valid rows
        - Appropriate warnings are logged
        """
        # Create dataset with missing values
        test_csv = tmp_path / "missing_values.csv"
        data_with_missing = pd.DataFrame({
            'srcip': ['192.168.1.1', None, '192.168.1.3', '192.168.1.4'],
            'dstip': ['10.0.0.1', '10.0.0.2', None, '10.0.0.4'],
            'dsport': [80, 443, 22, 8080],
            'proto': ['tcp', 'tcp', 'tcp', 'tcp'],
            'state': ['CON', 'CON', 'FIN', 'CON'],
            'label': [0, 0, 0, 1]
        })
        data_with_missing.to_csv(test_csv, index=False)
        
        # Change to temp directory
        original_dir = os.getcwd()
        os.chdir(tmp_path)
        
        try:
            with caplog.at_level(logging.WARNING):
                # Capture console output
                captured_output = StringIO()
                sys.stdout = captured_output
                
                # Execute main pipeline
                main(str(test_csv))
                
                # Restore stdout
                sys.stdout = sys.__stdout__
            
            # Verify warning was logged about dropped rows
            log_text = caplog.text.lower()
            assert "dropped" in log_text or "missing" in log_text, \
                "Should log warning about missing values"
            
            # Verify outputs were created successfully
            csv_report_path = tmp_path / "suspicious_report.csv"
            assert csv_report_path.exists(), "CSV report should be created"
            
            # Verify only valid entries are in output
            report_df = pd.read_csv(csv_report_path)
            if len(report_df) > 0:
                # All entries should have valid IPs
                assert report_df["Source IP"].notna().all(), "All IPs should be valid"
                
        finally:
            # Restore original directory
            os.chdir(original_dir)
    
    def test_invalid_port_values_handling(self, tmp_path, caplog):
        """
        Test that system handles invalid port values.
        
        Verifies:
        - Invalid port values are handled gracefully
        - System continues processing
        - Warnings are logged
        """
        # Create dataset with invalid ports
        test_csv = tmp_path / "invalid_ports.csv"
        
        # Write CSV with some text values in port field
        with open(test_csv, 'w') as f:
            f.write("srcip,dstip,dsport,proto,state,label\n")
            f.write("192.168.1.1,10.0.0.1,80,tcp,CON,0\n")
            f.write("192.168.1.2,10.0.0.2,invalid,tcp,CON,0\n")
            f.write("192.168.1.3,10.0.0.3,99999,tcp,FIN,0\n")
            f.write("192.168.1.4,10.0.0.4,-1,tcp,CON,1\n")
            f.write("192.168.1.5,10.0.0.5,8080,tcp,CON,1\n")
        
        # Change to temp directory
        original_dir = os.getcwd()
        os.chdir(tmp_path)
        
        try:
            with caplog.at_level(logging.WARNING):
                # Capture console output
                captured_output = StringIO()
                sys.stdout = captured_output
                
                # Execute main pipeline - should complete without crash
                main(str(test_csv))
                
                # Restore stdout
                sys.stdout = sys.__stdout__
            
            # Verify warning was logged about invalid ports
            log_text = caplog.text.lower()
            assert "invalid" in log_text or "port" in log_text, \
                "Should log warning about invalid port values"
            
            # Verify outputs were created successfully
            csv_report_path = tmp_path / "suspicious_report.csv"
            assert csv_report_path.exists(), "CSV report should be created despite invalid ports"
            
        finally:
            # Restore original directory
            os.chdir(original_dir)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
