"""
Main Orchestrator

Coordinates component interactions and handles errors for the Network Bouncer system.
"""

import sys
import logging
import pandas as pd


# Configure logging - cleaner output for demo
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'  # Cleaner format without timestamps for demo
)
logger = logging.getLogger(__name__)


def display_console_output(suspicious_df: pd.DataFrame, time_window_alerts: pd.DataFrame = None) -> None:
    """
    Display suspicious entries to console with formatted output.
    
    Formats and prints all suspicious entries with clear labels and column alignment.
    Displays: Source IP, Total Connections, Unique Destinations, Unique Ports,
    Severity Score, Risk Level, and Threat Type for each entry.
    
    Args:
        suspicious_df: DataFrame with suspicious entries containing columns:
            - srcip: Source IP address
            - total_connections: Total connection count
            - unique_destinations: Unique destination IP count
            - unique_ports: Unique destination port count
            - severity_score: Numerical severity (0-100)
            - risk_level: Risk level classification (Normal/Low/Medium/High)
            - threat_type: Identified threat type
        time_window_alerts: Optional DataFrame with time-window burst detections
            
    Requirements:
        - 7.1: Display all suspicious entries to console
        - 7.2: Display all required fields for each entry
        - 7.3: Format output for readability with clear labels and alignment
    """
    # Handle empty results
    if len(suspicious_df) == 0 and (time_window_alerts is None or len(time_window_alerts) == 0):
        print("\n" + "=" * 60)
        print("NETWORK ANALYSIS COMPLETE")
        print("=" * 60)
        print("\nNo suspicious activity detected.")
        print("=" * 60 + "\n")
        return
    
    # Print time-window alerts first (burst attacks - CRITICAL)
    if time_window_alerts is not None and len(time_window_alerts) > 0:
        print("\n" + "=" * 80)
        print("⚠️  BURST ATTACK ALERTS - TIME WINDOW ANALYSIS")
        print("=" * 80 + "\n")
        
        for _, row in time_window_alerts.head(10).iterrows():  # Show top 10 bursts
            time_str = row['time_window'].strftime('%Y-%m-%d %H:%M:%S') if pd.notna(row['time_window']) else 'Unknown'
            print(f"🚨 HIGH ALERT: {row['srcip']}")
            print(f"   Time: {time_str}")
            print(f"   Activity: {row['alert_reason']}")
            print(f"   Burst Rate: {row['connections_per_second']:.2f} connections/second")
            print()
        
        if len(time_window_alerts) > 10:
            print(f"   ... and {len(time_window_alerts) - 10} more burst alerts\n")
        
        print("=" * 80 + "\n")
    
    # Handle empty regular suspicious
    if len(suspicious_df) == 0:
        return
    
    # Print header for overall suspicious activity
    print("\n" + "=" * 80)
    print("SUSPICIOUS NETWORK ACTIVITY DETECTED - OVERALL ANALYSIS")
    print("=" * 80 + "\n")
    
    # Check if severity_score exists
    has_severity = 'severity_score' in suspicious_df.columns
    
    # Define column headers and widths
    if has_severity:
        headers = [
            "Source IP",
            "Connections",
            "Destinations", 
            "Ports",
            "Severity",
            "Risk Level",
            "Threat Type"
        ]
        col_widths = [15, 11, 12, 5, 12, 10, 35]
    else:
        headers = [
            "Source IP",
            "Connections",
            "Destinations", 
            "Ports",
            "Risk Level",
            "Threat Type"
        ]
        col_widths = [15, 11, 12, 5, 10, 35]
    
    # Print table header
    header_line = "  ".join(
        headers[i].ljust(col_widths[i]) for i in range(len(headers))
    )
    print(header_line)
    
    # Print separator line
    separator = "  ".join("-" * col_widths[i] for i in range(len(col_widths)))
    print(separator)
    
    # Print each row
    for _, row in suspicious_df.iterrows():
        if has_severity:
            severity_str = f"{int(row['severity_score'])}/100"
            values = [
                str(row['srcip']).ljust(col_widths[0]),
                str(row['total_connections']).rjust(col_widths[1]),
                str(row['unique_destinations']).rjust(col_widths[2]),
                str(row['unique_ports']).rjust(col_widths[3]),
                severity_str.rjust(col_widths[4]),
                str(row['risk_level']).ljust(col_widths[5]),
                str(row['threat_type']).ljust(col_widths[6])
            ]
        else:
            values = [
                str(row['srcip']).ljust(col_widths[0]),
                str(row['total_connections']).rjust(col_widths[1]),
                str(row['unique_destinations']).rjust(col_widths[2]),
                str(row['unique_ports']).rjust(col_widths[3]),
                str(row['risk_level']).ljust(col_widths[4]),
                str(row['threat_type']).ljust(col_widths[5])
            ]
        print("  ".join(values))
    
    # Print footer with count
    print("\nTotal suspicious IPs: " + str(len(suspicious_df)))
    print("=" * 80 + "\n")
    
    # Add problem statement format output (for faculty/evaluators)
    print("\n" + "=" * 80)
    print("DETAILED REPORTS (Problem Statement Format)")
    print("=" * 80 + "\n")
    
    for _, row in suspicious_df.iterrows():
        print("Suspicious Activity Detected:")
        print(f"  Source IP: {row['srcip']}")
        print(f"  Connections: {row['total_connections']}")
        print(f"  Unique Destinations: {row['unique_destinations']}")
        print(f"  Unique Ports: {row['unique_ports']}")
        
        # Map threat type to problem statement terminology
        threat_type = row['threat_type']
        if 'Backdoor' in threat_type:
            classification = "Backdoor/Analysis"
        elif 'Reconnaissance' in threat_type:
            classification = "Analysis"
        elif 'Port Scan' in threat_type:
            classification = "Analysis"
        else:
            classification = "Normal"
        
        print(f"  Classification: {classification}")
        print()
    
    print("=" * 80 + "\n")


def main(file_path: str) -> None:
    """
    Main orchestration function that coordinates the entire network analysis pipeline.
    
    Executes the following workflow:
    1. Load and validate dataset (call parser)
    2. Extract features (call extractor)
    3. Apply detection rules (call detector)
    4. Calculate risk scores (call detector)
    5. Classify risk levels (call detector)
    6. Identify threat types (call detector)
    7. Display console output
    8. Generate CSV report (call reporter)
    9. Generate visualizations (call charts)
    
    Implements comprehensive error handling at each stage:
    - Critical errors (file not found, missing columns, empty data): Exit with error message
    - Non-critical errors: Log warning and continue
    
    Args:
        file_path: Path to UNSW-NB15 CSV dataset
        
    Requirements:
        - 10.1: Handle file not found errors
        - 10.2: Handle missing column errors
        - 10.3: Handle empty dataset errors
        - 10.6: Continue execution after non-critical errors
        - 12.4: Main orchestration logic in network_bouncer module
        - 12.5: Clear single responsibilities per function
    """
    from network_bouncer.parser import load_dataset
    from network_bouncer.extractor import extract_features, extract_time_window_features
    from network_bouncer.detector import (
        apply_detection_rules,
        calculate_risk_score,
        calculate_severity_score,
        classify_risk_level,
        identify_threat_type,
        detect_time_window_threats
    )
    from network_bouncer.reporter import generate_csv_report
    from network_bouncer.charts import generate_visualizations
    
    try:
        # Step 1: Load and validate dataset
        print("\n📂 Loading dataset...")
        df = load_dataset(file_path)
        print(f"✅ Loaded {len(df)} records")
        
        # Step 2: Extract features
        print("🔍 Extracting features...")
        features_df = extract_features(df)
        print(f"✅ Analyzed {len(features_df)} unique source IPs")
        
        # Step 2b: Extract time-window features (if timestamp available)
        time_window_alerts = pd.DataFrame()
        if 'stime' in df.columns:
            print("⏱️  Analyzing time-window patterns...")
            time_window_features = extract_time_window_features(df, window_size='1min')
            if len(time_window_features) > 0:
                time_window_alerts = detect_time_window_threats(time_window_features)
                print(f"✅ Detected {len(time_window_alerts)} burst attack windows")
            else:
                print("⚠️  No valid time windows to analyze")
        
        # Step 3: Apply detection rules to identify suspicious IPs
        print("🚨 Running detection rules...")
        suspicious_df = apply_detection_rules(features_df)
        print(f"✅ Identified {len(suspicious_df)} suspicious IPs")
        
        # Step 4: Calculate risk scores and severity scores for ALL IPs
        print("📊 Calculating scores...")
        features_with_scores = calculate_risk_score(features_df)
        features_with_scores = calculate_severity_score(features_with_scores)
        suspicious_with_scores = calculate_risk_score(suspicious_df)
        suspicious_with_scores = calculate_severity_score(suspicious_with_scores)
        
        # Step 5: Classify risk levels for ALL IPs using severity-based classification
        print("🎯 Classifying risk levels...")
        features_with_scores['risk_level'] = features_with_scores.apply(
            lambda row: classify_risk_level(row['risk_score'], row['severity_score']), 
            axis=1
        )
        suspicious_with_scores['risk_level'] = suspicious_with_scores.apply(
            lambda row: classify_risk_level(row['risk_score'], row['severity_score']), 
            axis=1
        )
        
        # Step 6: Identify threat types for suspicious IPs
        print("🔎 Identifying threat types...")
        if len(suspicious_with_scores) > 0:
            suspicious_with_scores['threat_type'] = suspicious_with_scores.apply(identify_threat_type, axis=1)
        else:
            suspicious_with_scores['threat_type'] = pd.Series(dtype='str')
        
        # Step 7: Display console output
        display_console_output(suspicious_with_scores, time_window_alerts)
        
        # Step 8: Generate CSV report
        print("📄 Generating CSV report...")
        generate_csv_report(suspicious_with_scores)
        print("✅ Report saved: suspicious_report.csv")
        
        # Step 9: Generate visualizations
        print("📈 Generating visualizations...")
        generate_visualizations(suspicious_with_scores, features_with_scores)
        print("✅ Charts saved: suspicious_ips_connections.png, risk_level_distribution.png, top_10_active_ips.png")
        
        # Performance summary
        print(f"\n{'='*60}")
        print("⚡ PERFORMANCE SUMMARY")
        print(f"{'='*60}")
        print(f"Records processed: {len(df)}")
        print(f"Source IPs analyzed: {len(features_df)}")
        print(f"Suspicious IPs: {len(suspicious_with_scores)}")
        if len(time_window_alerts) > 0:
            print(f"Burst attacks: {len(time_window_alerts)}")
        print(f"Time Complexity: O(n) where n = {len(df)}")
        print(f"{'='*60}")
        print("\n✅ Analysis complete!\n")
        
    except FileNotFoundError as e:
        # Critical error: File does not exist
        logger.error(str(e))
        print(f"\nERROR: {e}", file=sys.stderr)
        sys.exit(1)
        
    except ValueError as e:
        # Critical error: Missing columns or empty dataset
        logger.error(str(e))
        print(f"\nERROR: {e}", file=sys.stderr)
        sys.exit(1)
        
    except Exception as e:
        # Unexpected error
        logger.error(f"Unexpected error during analysis: {str(e)}")
        print(f"\nERROR: An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py <path_to_dataset.csv>")
        sys.exit(1)
    
    dataset_path = sys.argv[1]
    main(dataset_path)
