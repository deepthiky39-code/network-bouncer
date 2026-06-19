"""
Report Generator Component

Exports suspicious entries to CSV format.
"""

import pandas as pd


def generate_csv_report(suspicious_df: pd.DataFrame, output_path: str = "suspicious_report.csv") -> None:
    """
    Generate CSV report of suspicious activity.
    
    Exports suspicious network activity entries to a CSV file with standardized
    column names. When no suspicious entries are detected, creates a CSV with
    headers only.
    
    Args:
        suspicious_df: DataFrame with suspicious entries containing columns:
            - srcip: Source IP address
            - total_connections: Total connection count
            - unique_destinations: Unique destination IP count
            - unique_ports: Unique destination port count
            - risk_score: Numerical risk score (0-3)
            - risk_level: Categorical risk level (Normal/Low/Medium/High)
            - threat_type: Identified threat pattern
        output_path: Output file path (default: "suspicious_report.csv")
        
    Example:
        >>> suspicious = pd.DataFrame([{
        ...     'srcip': '192.168.1.1',
        ...     'total_connections': 150,
        ...     'unique_destinations': 60,
        ...     'unique_ports': 40,
        ...     'risk_score': 3,
        ...     'risk_level': 'High',
        ...     'threat_type': 'Potential Backdoor Activity'
        ... }])
        >>> generate_csv_report(suspicious)
        # Creates suspicious_report.csv with the entry
    """
    # Create a copy to avoid modifying the original DataFrame
    report_df = suspicious_df.copy()
    
    # Check if severity_score exists
    has_severity = 'severity_score' in report_df.columns
    
    # Rename columns to match CSV report format
    if has_severity:
        column_mapping = {
            'srcip': 'Source IP',
            'total_connections': 'Total Connections',
            'unique_destinations': 'Unique Destinations',
            'unique_ports': 'Unique Ports',
            'risk_score': 'Score',
            'severity_score': 'Severity',
            'risk_level': 'Risk Level',
            'threat_type': 'Threat Type'
        }
        output_columns = [
            'Source IP',
            'Total Connections',
            'Unique Destinations',
            'Unique Ports',
            'Score',
            'Severity',
            'Risk Level',
            'Threat Type'
        ]
    else:
        column_mapping = {
            'srcip': 'Source IP',
            'total_connections': 'Total Connections',
            'unique_destinations': 'Unique Destinations',
            'unique_ports': 'Unique Ports',
            'risk_score': 'Score',
            'risk_level': 'Risk Level',
            'threat_type': 'Threat Type'
        }
        output_columns = [
            'Source IP',
            'Total Connections',
            'Unique Destinations',
            'Unique Ports',
            'Score',
            'Risk Level',
            'Threat Type'
        ]
    
    report_df = report_df.rename(columns=column_mapping)
    
    # Handle case where DataFrame might not have all columns
    available_columns = [col for col in output_columns if col in report_df.columns]
    report_df = report_df[available_columns]
    
    # Write to CSV using pandas to_csv()
    # index=False ensures row numbers are not included
    # When empty, this creates a file with headers only
    report_df.to_csv(output_path, index=False)
