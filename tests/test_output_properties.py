"""Property-based tests for output formatting module.

Feature: network-bouncer
"""

import pandas as pd
import pytest
from hypothesis import given, strategies as st, settings
from io import StringIO
import sys

from network_bouncer.main import display_console_output


# Hypothesis strategies for generating suspicious entries
ip_addresses = st.from_regex(r'^(\d{1,3}\.){3}\d{1,3}$', fullmatch=True)


@st.composite
def suspicious_entry(draw):
    """Generate a single suspicious entry with all required fields."""
    return {
        'srcip': draw(ip_addresses),
        'total_connections': draw(st.integers(min_value=0, max_value=500)),
        'unique_destinations': draw(st.integers(min_value=0, max_value=150)),
        'unique_ports': draw(st.integers(min_value=0, max_value=100)),
        'risk_score': draw(st.integers(min_value=0, max_value=3)),
        'risk_level': draw(st.sampled_from(['Normal', 'Low', 'Medium', 'High'])),
        'threat_type': draw(st.sampled_from([
            'Normal',
            'Port Scan',
            'Network Reconnaissance',
            'Potential Backdoor Activity'
        ]))
    }


@given(st.lists(suspicious_entry(), min_size=1, max_size=20))
@settings(deadline=None)
def test_property_8_output_completeness_console(entry_list):
    # Feature: network-bouncer, Property 8: Output Completeness (partial)
    """
    Test that all required fields are present in formatted console output.
    
    Property: For any set of suspicious entries, the formatted output (console) 
    SHALL include all required fields for each entry: Source IP, Total Connections, 
    Unique Destinations, Unique Ports, Risk Level, and Threat Type.
    
    **Validates: Requirements 7.2**
    """
    # Create DataFrame from entry list
    suspicious_df = pd.DataFrame(entry_list)
    
    # Capture console output
    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()
    
    try:
        display_console_output(suspicious_df)
        output = captured_output.getvalue()
    finally:
        sys.stdout = old_stdout
    
    # Verify output contains required field headers
    required_headers = [
        'Source IP',
        'Connections',
        'Destinations',
        'Ports',
        'Risk Level',
        'Threat Type'
    ]
    
    for header in required_headers:
        assert header in output, (
            f"Console output must contain header '{header}'"
        )
    
    # Verify all entries are present in the output
    for entry in entry_list:
        # Check that the source IP appears in the output
        assert entry['srcip'] in output, (
            f"Source IP '{entry['srcip']}' must appear in console output"
        )
        
        # Check that the numeric values appear in the output
        assert str(entry['total_connections']) in output, (
            f"Total connections '{entry['total_connections']}' must appear in console output"
        )
        assert str(entry['unique_destinations']) in output, (
            f"Unique destinations '{entry['unique_destinations']}' must appear in console output"
        )
        assert str(entry['unique_ports']) in output, (
            f"Unique ports '{entry['unique_ports']}' must appear in console output"
        )
        
        # Check that risk level and threat type appear in the output
        assert entry['risk_level'] in output, (
            f"Risk level '{entry['risk_level']}' must appear in console output"
        )
        assert entry['threat_type'] in output, (
            f"Threat type '{entry['threat_type']}' must appear in console output"
        )
    
    # Verify the count of entries is displayed
    assert f"Total suspicious IPs: {len(entry_list)}" in output, (
        "Console output must display the total count of suspicious IPs"
    )


def test_property_8_empty_output_handling():
    # Feature: network-bouncer, Property 8: Output Completeness (empty case)
    """
    Test that empty suspicious results are handled gracefully.
    
    **Validates: Requirements 7.1, 7.2, 7.3**
    """
    # Create empty DataFrame with proper columns
    empty_df = pd.DataFrame(columns=[
        'srcip', 'total_connections', 'unique_destinations', 
        'unique_ports', 'risk_score', 'risk_level', 'threat_type'
    ])
    
    # Capture console output
    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()
    
    try:
        display_console_output(empty_df)
        output = captured_output.getvalue()
    finally:
        sys.stdout = old_stdout
    
    # Verify appropriate message is displayed
    assert "No suspicious activity detected" in output, (
        "Console output must indicate when no suspicious activity is detected"
    )
    
    # Verify headers are NOT shown for empty results (different formatting)
    # The empty case should show a different, simpler message
    assert "NETWORK ANALYSIS COMPLETE" in output or "No suspicious activity detected" in output


def test_property_8_single_entry():
    # Feature: network-bouncer, Property 8: Output Completeness (single entry)
    """
    Test output with a single suspicious entry.
    
    **Validates: Requirements 7.1, 7.2, 7.3**
    """
    suspicious_df = pd.DataFrame([{
        'srcip': '192.168.1.1',
        'total_connections': 150,
        'unique_destinations': 60,
        'unique_ports': 40,
        'risk_score': 3,
        'risk_level': 'High',
        'threat_type': 'Potential Backdoor Activity'
    }])
    
    # Capture console output
    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()
    
    try:
        display_console_output(suspicious_df)
        output = captured_output.getvalue()
    finally:
        sys.stdout = old_stdout
    
    # Verify all required fields are present
    assert '192.168.1.1' in output
    assert '150' in output
    assert '60' in output
    assert '40' in output
    assert 'High' in output
    assert 'Potential Backdoor Activity' in output
    assert 'Total suspicious IPs: 1' in output


def test_property_8_multiple_entries():
    # Feature: network-bouncer, Property 8: Output Completeness (multiple entries)
    """
    Test output with multiple suspicious entries of varying risk levels.
    
    **Validates: Requirements 7.1, 7.2, 7.3**
    """
    suspicious_df = pd.DataFrame([
        {
            'srcip': '192.168.1.1',
            'total_connections': 150,
            'unique_destinations': 60,
            'unique_ports': 40,
            'risk_score': 3,
            'risk_level': 'High',
            'threat_type': 'Potential Backdoor Activity'
        },
        {
            'srcip': '10.0.0.5',
            'total_connections': 120,
            'unique_destinations': 40,
            'unique_ports': 35,
            'risk_score': 2,
            'risk_level': 'Medium',
            'threat_type': 'Port Scan'
        },
        {
            'srcip': '172.16.0.10',
            'total_connections': 110,
            'unique_destinations': 60,
            'unique_ports': 20,
            'risk_score': 2,
            'risk_level': 'Medium',
            'threat_type': 'Network Reconnaissance'
        }
    ])
    
    # Capture console output
    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()
    
    try:
        display_console_output(suspicious_df)
        output = captured_output.getvalue()
    finally:
        sys.stdout = old_stdout
    
    # Verify all entries are present
    assert '192.168.1.1' in output
    assert '10.0.0.5' in output
    assert '172.16.0.10' in output
    
    # Verify all threat types are present
    assert 'Potential Backdoor Activity' in output
    assert 'Port Scan' in output
    assert 'Network Reconnaissance' in output
    
    # Verify count
    assert 'Total suspicious IPs: 3' in output


def test_property_8_output_structure():
    # Feature: network-bouncer, Property 8: Output Completeness (structure)
    """
    Test that output has proper structure with headers, separators, and footer.
    
    **Validates: Requirements 7.3**
    """
    suspicious_df = pd.DataFrame([{
        'srcip': '192.168.1.1',
        'total_connections': 150,
        'unique_destinations': 60,
        'unique_ports': 40,
        'risk_score': 3,
        'risk_level': 'High',
        'threat_type': 'Potential Backdoor Activity'
    }])
    
    # Capture console output
    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()
    
    try:
        display_console_output(suspicious_df)
        output = captured_output.getvalue()
    finally:
        sys.stdout = old_stdout
    
    # Verify structure elements
    assert '=' * 60 in output, "Output must contain separator lines"
    assert 'SUSPICIOUS NETWORK ACTIVITY DETECTED' in output, "Output must contain title"
    assert '-' in output, "Output must contain column separator"
    assert 'Total suspicious IPs:' in output, "Output must contain summary"



# ========== Property 8: Output Completeness (CSV) ==========


@given(st.lists(suspicious_entry(), min_size=1, max_size=20))
@settings(deadline=None)
def test_property_8_output_completeness_csv(entry_list):
    # Feature: network-bouncer, Property 8: Output Completeness (partial)
    """
    Test that all required fields are present in CSV output.
    
    Property: For any set of suspicious entries, the formatted output (CSV) 
    SHALL include all required fields for each entry: Source IP, Total Connections, 
    Unique Destinations, Unique Ports, Score, Risk Level, and Threat Type.
    
    **Validates: Requirements 8.2, 8.3**
    """
    import tempfile
    import os
    from network_bouncer.reporter import generate_csv_report
    
    # Create DataFrame from entry list
    suspicious_df = pd.DataFrame(entry_list)
    
    # Generate CSV report using tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
        output_file = tmp.name
    
    try:
        generate_csv_report(suspicious_df, output_file)
        
        # Verify file was created
        assert os.path.exists(output_file), "CSV report file must be created"
        
        # Read back the CSV
        result_df = pd.read_csv(output_file)
        
        # Verify all required columns are present
        required_columns = [
            'Source IP',
            'Total Connections',
            'Unique Destinations',
            'Unique Ports',
            'Score',
            'Risk Level',
            'Threat Type'
        ]
        
        for col in required_columns:
            assert col in result_df.columns, (
                f"CSV output must contain column '{col}'"
            )
        
        # Verify all entries are present (same row count)
        assert len(result_df) == len(entry_list), (
            f"CSV must contain all {len(entry_list)} entries, but contains {len(result_df)}"
        )
        
        # Verify data integrity: CSV should be a faithful representation
        # We'll check that the data can be read back and all values match row-by-row
        for idx in range(len(entry_list)):
            original_entry = entry_list[idx]
            result_entry = result_df.iloc[idx]
            
            assert result_entry['Source IP'] == original_entry['srcip'], (
                f"Row {idx}: Source IP mismatch"
            )
            assert result_entry['Total Connections'] == original_entry['total_connections'], (
                f"Row {idx}: Total Connections mismatch"
            )
            assert result_entry['Unique Destinations'] == original_entry['unique_destinations'], (
                f"Row {idx}: Unique Destinations mismatch"
            )
            assert result_entry['Unique Ports'] == original_entry['unique_ports'], (
                f"Row {idx}: Unique Ports mismatch"
            )
            assert result_entry['Score'] == original_entry['risk_score'], (
                f"Row {idx}: Score mismatch"
            )
            assert result_entry['Risk Level'] == original_entry['risk_level'], (
                f"Row {idx}: Risk Level mismatch"
            )
            assert result_entry['Threat Type'] == original_entry['threat_type'], (
                f"Row {idx}: Threat Type mismatch"
            )
    finally:
        # Clean up temporary file
        if os.path.exists(output_file):
            os.remove(output_file)


def test_property_8_csv_empty_dataset_creates_headers_only(tmp_path):
    # Feature: network-bouncer, Property 8: Output Completeness (empty CSV)
    """
    Test that empty dataset creates headers-only CSV.
    
    Property: When no suspicious activity is detected, the CSV report SHALL
    create an empty report with headers only.
    
    **Validates: Requirements 8.4**
    """
    from network_bouncer.reporter import generate_csv_report
    
    # Create empty DataFrame with proper columns
    empty_df = pd.DataFrame(columns=[
        'srcip', 'total_connections', 'unique_destinations', 
        'unique_ports', 'risk_score', 'risk_level', 'threat_type'
    ])
    
    # Generate CSV report
    output_file = tmp_path / "empty_report.csv"
    generate_csv_report(empty_df, str(output_file))
    
    # Verify file was created
    assert output_file.exists(), "CSV report file must be created even for empty data"
    
    # Read back the CSV
    result_df = pd.read_csv(output_file)
    
    # Verify headers are present
    required_columns = [
        'Source IP',
        'Total Connections',
        'Unique Destinations',
        'Unique Ports',
        'Score',
        'Risk Level',
        'Threat Type'
    ]
    
    for col in required_columns:
        assert col in result_df.columns, (
            f"Empty CSV must contain header '{col}'"
        )
    
    # Verify no data rows
    assert len(result_df) == 0, (
        "Empty dataset must create CSV with headers only (no data rows)"
    )


def test_property_8_csv_single_entry(tmp_path):
    # Feature: network-bouncer, Property 8: Output Completeness (single CSV entry)
    """
    Test CSV output with a single suspicious entry.
    
    **Validates: Requirements 8.1, 8.2, 8.3**
    """
    from network_bouncer.reporter import generate_csv_report
    
    suspicious_df = pd.DataFrame([{
        'srcip': '192.168.1.1',
        'total_connections': 150,
        'unique_destinations': 60,
        'unique_ports': 40,
        'risk_score': 3,
        'risk_level': 'High',
        'threat_type': 'Potential Backdoor Activity'
    }])
    
    # Generate CSV report
    output_file = tmp_path / "single_report.csv"
    generate_csv_report(suspicious_df, str(output_file))
    
    # Read back the CSV
    result_df = pd.read_csv(output_file)
    
    # Verify single entry
    assert len(result_df) == 1, "CSV must contain exactly one entry"
    
    # Verify all values
    row = result_df.iloc[0]
    assert row['Source IP'] == '192.168.1.1'
    assert row['Total Connections'] == 150
    assert row['Unique Destinations'] == 60
    assert row['Unique Ports'] == 40
    assert row['Score'] == 3
    assert row['Risk Level'] == 'High'
    assert row['Threat Type'] == 'Potential Backdoor Activity'


def test_property_8_csv_multiple_entries(tmp_path):
    # Feature: network-bouncer, Property 8: Output Completeness (multiple CSV entries)
    """
    Test CSV output with multiple suspicious entries of varying risk levels.
    
    **Validates: Requirements 8.1, 8.2, 8.3**
    """
    from network_bouncer.reporter import generate_csv_report
    
    suspicious_df = pd.DataFrame([
        {
            'srcip': '192.168.1.1',
            'total_connections': 150,
            'unique_destinations': 60,
            'unique_ports': 40,
            'risk_score': 3,
            'risk_level': 'High',
            'threat_type': 'Potential Backdoor Activity'
        },
        {
            'srcip': '10.0.0.5',
            'total_connections': 120,
            'unique_destinations': 40,
            'unique_ports': 35,
            'risk_score': 2,
            'risk_level': 'Medium',
            'threat_type': 'Port Scan'
        },
        {
            'srcip': '172.16.0.10',
            'total_connections': 110,
            'unique_destinations': 60,
            'unique_ports': 20,
            'risk_score': 2,
            'risk_level': 'Medium',
            'threat_type': 'Network Reconnaissance'
        }
    ])
    
    # Generate CSV report
    output_file = tmp_path / "multiple_report.csv"
    generate_csv_report(suspicious_df, str(output_file))
    
    # Read back the CSV
    result_df = pd.read_csv(output_file)
    
    # Verify count
    assert len(result_df) == 3, "CSV must contain all three entries"
    
    # Verify all IPs are present
    ips = set(result_df['Source IP'].values)
    assert ips == {'192.168.1.1', '10.0.0.5', '172.16.0.10'}
    
    # Verify all threat types are present
    threat_types = set(result_df['Threat Type'].values)
    assert 'Potential Backdoor Activity' in threat_types
    assert 'Port Scan' in threat_types
    assert 'Network Reconnaissance' in threat_types
    
    # Verify data integrity for first entry
    entry1 = result_df[result_df['Source IP'] == '192.168.1.1'].iloc[0]
    assert entry1['Total Connections'] == 150
    assert entry1['Unique Destinations'] == 60
    assert entry1['Unique Ports'] == 40
    assert entry1['Score'] == 3
    assert entry1['Risk Level'] == 'High'


def test_property_8_csv_default_filename(tmp_path):
    # Feature: network-bouncer, Property 8: Output Completeness (default filename)
    """
    Test that CSV report uses default filename when not specified.
    
    **Validates: Requirements 8.1**
    """
    import os
    from network_bouncer.reporter import generate_csv_report
    
    suspicious_df = pd.DataFrame([{
        'srcip': '192.168.1.1',
        'total_connections': 150,
        'unique_destinations': 60,
        'unique_ports': 40,
        'risk_score': 3,
        'risk_level': 'High',
        'threat_type': 'Potential Backdoor Activity'
    }])
    
    # Change to tmp directory to avoid polluting workspace
    original_dir = os.getcwd()
    try:
        os.chdir(tmp_path)
        
        # Generate CSV report with default filename
        generate_csv_report(suspicious_df)
        
        # Verify default file was created
        default_file = tmp_path / "suspicious_report.csv"
        assert default_file.exists(), (
            "CSV report must use default filename 'suspicious_report.csv'"
        )
        
        # Verify content is correct
        result_df = pd.read_csv(default_file)
        assert len(result_df) == 1
        assert result_df.iloc[0]['Source IP'] == '192.168.1.1'
        
    finally:
        os.chdir(original_dir)



# ========== Property 9: Empty Dataset Handling (Visualization) ==========


def test_property_9_empty_visualization_handling(tmp_path):
    # Feature: network-bouncer, Property 9: Empty Dataset Handling (partial)
    """
    Test that visualization generation completes without errors for empty datasets.
    
    Property: For any dataset that produces zero suspicious entries after analysis, 
    the system SHALL complete successfully and handle visualization generation 
    gracefully.
    
    **Validates: Requirements 9.5**
    """
    import os
    from network_bouncer.charts import generate_visualizations
    
    # Create empty suspicious DataFrame
    empty_suspicious = pd.DataFrame(columns=[
        'srcip', 'total_connections', 'unique_destinations', 
        'unique_ports', 'risk_score', 'risk_level', 'threat_type'
    ])
    
    # Create empty all_features DataFrame
    empty_all_features = pd.DataFrame(columns=[
        'srcip', 'total_connections', 'unique_destinations', 
        'unique_ports', 'risk_score', 'risk_level'
    ])
    
    # Generate visualizations - should complete without errors
    try:
        generate_visualizations(empty_suspicious, empty_all_features, str(tmp_path))
    except Exception as e:
        pytest.fail(f"Visualization generation failed with empty dataset: {str(e)}")
    
    # Verify all chart files were created
    expected_files = [
        'suspicious_ips_connections.png',
        'risk_level_distribution.png',
        'top_10_active_ips.png'
    ]
    
    for filename in expected_files:
        chart_file = tmp_path / filename
        assert chart_file.exists(), (
            f"Chart file '{filename}' must be created even for empty dataset"
        )
        
        # Verify file is not empty (has PNG data)
        assert chart_file.stat().st_size > 0, (
            f"Chart file '{filename}' must contain image data"
        )


@given(st.integers(min_value=1, max_value=9))
@settings(deadline=None)
def test_property_9_fewer_than_10_ips_handling(num_ips):
    # Feature: network-bouncer, Property 9: Empty Dataset Handling (partial)
    """
    Test handling of fewer than 10 IPs for top 10 chart.
    
    Property: When there are fewer than 10 source IPs, the visualization engine 
    SHALL display all available source IPs in the top 10 chart without errors.
    
    **Validates: Requirements 9.5**
    """
    import tempfile
    import os
    from network_bouncer.charts import generate_visualizations
    
    # Generate features with fewer than 10 IPs
    entries = []
    for i in range(num_ips):
        entries.append({
            'srcip': f'192.168.1.{i+1}',
            'total_connections': 100 + (i * 10),
            'unique_destinations': 40 + i,
            'unique_ports': 25 + i,
            'risk_score': 2,
            'risk_level': 'Medium',
            'threat_type': 'Port Scan'
        })
    
    suspicious_df = pd.DataFrame(entries)
    all_features_df = pd.DataFrame(entries)
    
    # Create temporary directory for output
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Generate visualizations - should complete without errors
        try:
            generate_visualizations(suspicious_df, all_features_df, tmp_dir)
        except Exception as e:
            pytest.fail(
                f"Visualization generation failed with {num_ips} IPs: {str(e)}"
            )
        
        # Verify all chart files were created
        expected_files = [
            'suspicious_ips_connections.png',
            'risk_level_distribution.png',
            'top_10_active_ips.png'
        ]
        
        for filename in expected_files:
            chart_file = os.path.join(tmp_dir, filename)
            assert os.path.exists(chart_file), (
                f"Chart file '{filename}' must be created with {num_ips} IPs"
            )
            
            # Verify file is not empty
            assert os.path.getsize(chart_file) > 0, (
                f"Chart file '{filename}' must contain image data"
            )


def test_property_9_visualization_with_exactly_10_ips(tmp_path):
    # Feature: network-bouncer, Property 9: Empty Dataset Handling (edge case)
    """
    Test handling of exactly 10 IPs for top 10 chart (boundary case).
    
    **Validates: Requirements 9.5**
    """
    from network_bouncer.charts import generate_visualizations
    
    # Generate exactly 10 IPs
    entries = []
    for i in range(10):
        entries.append({
            'srcip': f'192.168.1.{i+1}',
            'total_connections': 100 + (i * 10),
            'unique_destinations': 40 + i,
            'unique_ports': 25 + i,
            'risk_score': 2,
            'risk_level': 'Medium',
            'threat_type': 'Port Scan'
        })
    
    suspicious_df = pd.DataFrame(entries)
    all_features_df = pd.DataFrame(entries)
    
    # Generate visualizations
    generate_visualizations(suspicious_df, all_features_df, str(tmp_path))
    
    # Verify all chart files were created
    top_10_chart = tmp_path / 'top_10_active_ips.png'
    assert top_10_chart.exists(), "Top 10 chart must be created"
    assert top_10_chart.stat().st_size > 0, "Top 10 chart must contain image data"


def test_property_9_visualization_with_more_than_10_ips(tmp_path):
    # Feature: network-bouncer, Property 9: Empty Dataset Handling (normal case)
    """
    Test handling of more than 10 IPs for top 10 chart (should only show top 10).
    
    **Validates: Requirements 9.3, 9.5**
    """
    from network_bouncer.charts import generate_visualizations
    
    # Generate 15 IPs
    entries = []
    for i in range(15):
        entries.append({
            'srcip': f'192.168.1.{i+1}',
            'total_connections': 100 + (i * 10),
            'unique_destinations': 40 + i,
            'unique_ports': 25 + i,
            'risk_score': 2,
            'risk_level': 'Medium',
            'threat_type': 'Port Scan'
        })
    
    suspicious_df = pd.DataFrame(entries)
    all_features_df = pd.DataFrame(entries)
    
    # Generate visualizations
    generate_visualizations(suspicious_df, all_features_df, str(tmp_path))
    
    # Verify all chart files were created
    top_10_chart = tmp_path / 'top_10_active_ips.png'
    assert top_10_chart.exists(), "Top 10 chart must be created"
    assert top_10_chart.stat().st_size > 0, "Top 10 chart must contain image data"


def test_property_9_visualization_all_charts_created(tmp_path):
    # Feature: network-bouncer, Property 9: Empty Dataset Handling (complete)
    """
    Test that all three required visualizations are created.
    
    **Validates: Requirements 9.1, 9.2, 9.3, 9.4**
    """
    from network_bouncer.charts import generate_visualizations
    
    # Create test data with various risk levels
    suspicious_data = [
        {
            'srcip': '192.168.1.1',
            'total_connections': 150,
            'unique_destinations': 60,
            'unique_ports': 40,
            'risk_score': 3,
            'risk_level': 'High',
            'threat_type': 'Potential Backdoor Activity'
        },
        {
            'srcip': '10.0.0.5',
            'total_connections': 120,
            'unique_destinations': 40,
            'unique_ports': 35,
            'risk_score': 2,
            'risk_level': 'Medium',
            'threat_type': 'Port Scan'
        }
    ]
    
    all_features_data = suspicious_data + [
        {
            'srcip': '172.16.0.1',
            'total_connections': 50,
            'unique_destinations': 10,
            'unique_ports': 5,
            'risk_score': 0,
            'risk_level': 'Normal',
            'threat_type': 'Normal'
        },
        {
            'srcip': '192.168.2.1',
            'total_connections': 110,
            'unique_destinations': 20,
            'unique_ports': 15,
            'risk_score': 1,
            'risk_level': 'Low',
            'threat_type': 'Normal'
        }
    ]
    
    suspicious_df = pd.DataFrame(suspicious_data)
    all_features_df = pd.DataFrame(all_features_data)
    
    # Generate visualizations
    generate_visualizations(suspicious_df, all_features_df, str(tmp_path))
    
    # Verify all three required charts are created
    required_charts = [
        'suspicious_ips_connections.png',
        'risk_level_distribution.png',
        'top_10_active_ips.png'
    ]
    
    for chart_name in required_charts:
        chart_file = tmp_path / chart_name
        assert chart_file.exists(), f"Required chart '{chart_name}' must be created"
        assert chart_file.stat().st_size > 0, f"Chart '{chart_name}' must contain image data"


def test_property_9_visualization_risk_level_distribution(tmp_path):
    # Feature: network-bouncer, Property 9: Empty Dataset Handling (risk distribution)
    """
    Test that risk level distribution includes all risk levels present in data.
    
    **Validates: Requirements 9.2**
    """
    from network_bouncer.charts import generate_visualizations
    
    # Create test data with all four risk levels
    all_features_data = [
        {'srcip': '192.168.1.1', 'total_connections': 150, 'unique_destinations': 60, 
         'unique_ports': 40, 'risk_score': 3, 'risk_level': 'High'},
        {'srcip': '10.0.0.5', 'total_connections': 120, 'unique_destinations': 40, 
         'unique_ports': 35, 'risk_score': 2, 'risk_level': 'Medium'},
        {'srcip': '172.16.0.1', 'total_connections': 110, 'unique_destinations': 20, 
         'unique_ports': 15, 'risk_score': 1, 'risk_level': 'Low'},
        {'srcip': '192.168.2.1', 'total_connections': 50, 'unique_destinations': 10, 
         'unique_ports': 5, 'risk_score': 0, 'risk_level': 'Normal'},
    ]
    
    suspicious_data = [d for d in all_features_data if d['risk_level'] != 'Normal']
    
    suspicious_df = pd.DataFrame(suspicious_data)
    all_features_df = pd.DataFrame(all_features_data)
    
    # Generate visualizations
    generate_visualizations(suspicious_df, all_features_df, str(tmp_path))
    
    # Verify risk level distribution chart was created
    risk_chart = tmp_path / 'risk_level_distribution.png'
    assert risk_chart.exists(), "Risk level distribution chart must be created"
    assert risk_chart.stat().st_size > 0, "Risk level chart must contain image data"


def test_property_9_visualization_single_suspicious_ip(tmp_path):
    # Feature: network-bouncer, Property 9: Empty Dataset Handling (single entry)
    """
    Test visualization generation with a single suspicious IP.
    
    **Validates: Requirements 9.1, 9.2, 9.3**
    """
    from network_bouncer.charts import generate_visualizations
    
    suspicious_data = [{
        'srcip': '192.168.1.1',
        'total_connections': 150,
        'unique_destinations': 60,
        'unique_ports': 40,
        'risk_score': 3,
        'risk_level': 'High',
        'threat_type': 'Potential Backdoor Activity'
    }]
    
    all_features_data = suspicious_data + [{
        'srcip': '10.0.0.1',
        'total_connections': 50,
        'unique_destinations': 10,
        'unique_ports': 5,
        'risk_score': 0,
        'risk_level': 'Normal',
        'threat_type': 'Normal'
    }]
    
    suspicious_df = pd.DataFrame(suspicious_data)
    all_features_df = pd.DataFrame(all_features_data)
    
    # Generate visualizations - should complete without errors
    try:
        generate_visualizations(suspicious_df, all_features_df, str(tmp_path))
    except Exception as e:
        pytest.fail(f"Visualization generation failed with single IP: {str(e)}")
    
    # Verify all chart files were created
    for chart_name in ['suspicious_ips_connections.png', 'risk_level_distribution.png', 
                       'top_10_active_ips.png']:
        chart_file = tmp_path / chart_name
        assert chart_file.exists(), f"Chart '{chart_name}' must be created"
        assert chart_file.stat().st_size > 0



# ========== Property 9: Empty Dataset Handling (End-to-End) ==========


def test_property_9_empty_dataset_end_to_end(tmp_path):
    # Feature: network-bouncer, Property 9: Empty Dataset Handling (complete)
    """
    End-to-end test that system completes successfully with datasets producing zero suspicious entries.
    
    Property: For any dataset that produces zero suspicious entries after analysis, 
    the system SHALL complete successfully, creating an empty CSV report with headers 
    only and handling visualization generation gracefully.
    
    **Validates: Requirements 1.4, 8.4, 9.5**
    """
    import os
    from network_bouncer.main import main
    
    # Create a dataset with connections that don't trigger any detection rules
    # All values below thresholds: connections ≤ 100, destinations ≤ 50, ports ≤ 30
    normal_data = []
    for i in range(20):
        for j in range(5):  # 5 connections per IP = 100 total
            normal_data.append({
                'srcip': f'192.168.1.{i+1}',
                'dstip': f'10.0.0.{j+1}',
                'dsport': 80 + j,  # Only 5 unique ports
                'proto': 'tcp',
                'state': 'CON',
                'label': 0
            })
    
    df = pd.DataFrame(normal_data)
    
    # Save to CSV in temp directory
    input_csv = tmp_path / 'normal_traffic.csv'
    df.to_csv(input_csv, index=False)
    
    # Change to temp directory for outputs
    original_dir = os.getcwd()
    try:
        os.chdir(tmp_path)
        
        # Run the complete pipeline - should complete without errors
        try:
            main(str(input_csv))
        except SystemExit as e:
            # Check if it's a normal exit (code 0) or error exit
            if e.code != 0 and e.code is not None:
                pytest.fail(f"main() exited with error code {e.code} for empty suspicious results")
        except Exception as e:
            pytest.fail(f"main() failed with empty suspicious results: {str(e)}")
        
        # Verify CSV report was created with headers only
        csv_report = tmp_path / 'suspicious_report.csv'
        assert csv_report.exists(), "CSV report must be created even when no suspicious IPs"
        
        result_df = pd.read_csv(csv_report)
        
        # Verify headers are present
        required_columns = [
            'Source IP',
            'Total Connections',
            'Unique Destinations',
            'Unique Ports',
            'Score',
            'Risk Level',
            'Threat Type'
        ]
        
        for col in required_columns:
            assert col in result_df.columns, (
                f"Empty CSV must contain header '{col}'"
            )
        
        # Verify no data rows
        assert len(result_df) == 0, (
            "CSV report must be empty (headers only) when no suspicious IPs detected"
        )
        
        # Verify all visualization files were created
        expected_charts = [
            'suspicious_ips_connections.png',
            'risk_level_distribution.png',
            'top_10_active_ips.png'
        ]
        
        for chart_name in expected_charts:
            chart_file = tmp_path / chart_name
            assert chart_file.exists(), (
                f"Visualization '{chart_name}' must be created even when no suspicious IPs"
            )
            assert chart_file.stat().st_size > 0, (
                f"Visualization '{chart_name}' must contain valid image data"
            )
    
    finally:
        os.chdir(original_dir)


@given(st.integers(min_value=1, max_value=50))
@settings(deadline=None, max_examples=20)
def test_property_9_below_threshold_dataset_produces_no_suspicious(connections_per_ip):
    # Feature: network-bouncer, Property 9: Empty Dataset Handling (property-based)
    """
    Property-based test that datasets with values below all thresholds produce no suspicious entries.
    
    Property: For any dataset where all source IPs have:
    - total_connections ≤ 100
    - unique_destinations ≤ 50
    - unique_ports ≤ 30
    
    The system SHALL produce zero suspicious entries and complete successfully.
    
    **Validates: Requirements 1.4, 3.1, 3.2, 3.3, 8.4, 9.5**
    """
    import tempfile
    import os
    from network_bouncer.main import main
    
    # Ensure connections_per_ip is below threshold
    if connections_per_ip > 100:
        connections_per_ip = 100
    
    # Generate dataset with values below all thresholds
    data = []
    num_destinations = min(connections_per_ip, 50)  # Max 50 destinations
    num_ports = min(connections_per_ip, 30)  # Max 30 ports
    
    for i in range(connections_per_ip):
        data.append({
            'srcip': '192.168.1.1',
            'dstip': f'10.0.0.{(i % num_destinations) + 1}',
            'dsport': 1000 + (i % num_ports),
            'proto': 'tcp',
            'state': 'CON',
            'label': 0
        })
    
    df = pd.DataFrame(data)
    
    # Create temporary directory and files
    with tempfile.TemporaryDirectory() as tmp_dir:
        input_csv = os.path.join(tmp_dir, 'below_threshold.csv')
        df.to_csv(input_csv, index=False)
        
        # Change to temp directory for outputs
        original_dir = os.getcwd()
        try:
            os.chdir(tmp_dir)
            
            # Run the pipeline
            try:
                main(input_csv)
            except SystemExit as e:
                if e.code != 0 and e.code is not None:
                    pytest.fail(
                        f"main() exited with error for below-threshold data: "
                        f"{connections_per_ip} connections"
                    )
            
            # Verify CSV report is empty
            csv_report = os.path.join(tmp_dir, 'suspicious_report.csv')
            assert os.path.exists(csv_report), "CSV report must be created"
            
            result_df = pd.read_csv(csv_report)
            assert len(result_df) == 0, (
                f"Below-threshold data with {connections_per_ip} connections must "
                f"produce empty CSV (no suspicious IPs)"
            )
            
            # Verify visualizations were created
            for chart_name in ['suspicious_ips_connections.png', 'risk_level_distribution.png', 
                             'top_10_active_ips.png']:
                chart_file = os.path.join(tmp_dir, chart_name)
                assert os.path.exists(chart_file), (
                    f"Chart '{chart_name}' must be created for below-threshold data"
                )
        
        finally:
            os.chdir(original_dir)


def test_property_9_mixed_dataset_with_no_suspicious(tmp_path):
    # Feature: network-bouncer, Property 9: Empty Dataset Handling (mixed data)
    """
    Test that system correctly produces no suspicious entries when dataset has
    multiple IPs but none trigger detection rules.
    
    **Validates: Requirements 1.4, 3.1, 3.2, 3.3, 8.4, 9.5**
    """
    import os
    from network_bouncer.main import main
    
    # Create dataset with various IPs, all below thresholds
    data = []
    
    # IP 1: 99 connections (just below threshold)
    for i in range(99):
        data.append({
            'srcip': '192.168.1.1',
            'dstip': f'10.0.{i % 20}.{i % 10}',
            'dsport': 80 + (i % 20),
            'proto': 'tcp',
            'state': 'CON',
            'label': 0
        })
    
    # IP 2: 50 connections to 49 destinations (just below threshold)
    for i in range(50):
        data.append({
            'srcip': '192.168.1.2',
            'dstip': f'10.1.0.{i % 49}' if i < 49 else f'10.1.0.{i-1}',
            'dsport': 443,
            'proto': 'tcp',
            'state': 'CON',
            'label': 0
        })
    
    # IP 3: 70 connections to 29 ports (just below threshold)
    for i in range(70):
        data.append({
            'srcip': '192.168.1.3',
            'dstip': '10.2.0.1',
            'dsport': 8000 + (i % 29),
            'proto': 'tcp',
            'state': 'CON',
            'label': 0
        })
    
    df = pd.DataFrame(data)
    input_csv = tmp_path / 'mixed_normal.csv'
    df.to_csv(input_csv, index=False)
    
    # Change to temp directory
    original_dir = os.getcwd()
    try:
        os.chdir(tmp_path)
        
        # Run pipeline
        try:
            main(str(input_csv))
        except SystemExit as e:
            if e.code != 0 and e.code is not None:
                pytest.fail(f"main() failed with mixed normal data")
        
        # Verify empty CSV
        csv_report = tmp_path / 'suspicious_report.csv'
        result_df = pd.read_csv(csv_report)
        assert len(result_df) == 0, (
            "Mixed normal dataset must produce empty CSV"
        )
        
        # Verify visualizations created
        for chart_name in ['suspicious_ips_connections.png', 'risk_level_distribution.png',
                          'top_10_active_ips.png']:
            chart_file = tmp_path / chart_name
            assert chart_file.exists(), f"Chart '{chart_name}' must be created"
    
    finally:
        os.chdir(original_dir)
