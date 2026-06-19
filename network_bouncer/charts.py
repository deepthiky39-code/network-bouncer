"""Visualization module for Network Bouncer.

This module provides chart generation functionality to visualize network threat
detection results, including suspicious IP analysis and risk level distribution.
"""

import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for headless environments
import matplotlib.pyplot as plt
from typing import Optional


def generate_visualizations(
    suspicious_df: pd.DataFrame,
    all_features_df: pd.DataFrame,
    output_dir: str = "."
) -> None:
    """
    Generate and save visualization charts for network threat analysis.
    
    Creates three charts:
    1. Bar chart: Suspicious IPs by connection count
    2. Pie chart: Risk level distribution across all analyzed IPs
    3. Bar chart: Top 10 most active IPs by connection count
    
    Args:
        suspicious_df: DataFrame with suspicious entries containing columns:
            - srcip: Source IP address
            - total_connections: Total connection count
            - risk_level: Risk level classification
        all_features_df: DataFrame with all features (for risk level distribution)
            containing 'risk_level' column
        output_dir: Directory to save PNG files (default: current directory)
        
    Raises:
        ValueError: If required columns are missing from input DataFrames
        
    Example:
        >>> suspicious = pd.DataFrame({
        ...     'srcip': ['192.168.1.1', '10.0.0.1'],
        ...     'total_connections': [150, 120],
        ...     'risk_level': ['High', 'Medium']
        ... })
        >>> all_features = pd.DataFrame({
        ...     'risk_level': ['High', 'Medium', 'Low', 'Normal', 'Normal']
        ... })
        >>> generate_visualizations(suspicious, all_features)
    """
    # Validate required columns
    if not suspicious_df.empty:
        required_cols = ['srcip', 'total_connections']
        missing_cols = [col for col in required_cols if col not in suspicious_df.columns]
        if missing_cols:
            raise ValueError(f"Missing required columns in suspicious_df: {missing_cols}")
    
    if not all_features_df.empty and 'risk_level' not in all_features_df.columns:
        raise ValueError("Missing 'risk_level' column in all_features_df")
    
    # Generate each chart
    _generate_suspicious_ips_chart(suspicious_df, output_dir)
    _generate_risk_distribution_chart(all_features_df, output_dir)
    _generate_top_10_chart(all_features_df, output_dir)


def _generate_suspicious_ips_chart(
    suspicious_df: pd.DataFrame,
    output_dir: str
) -> None:
    """
    Generate bar chart showing suspicious IPs by connection count.
    
    Args:
        suspicious_df: DataFrame with suspicious entries
        output_dir: Directory to save PNG file
    """
    plt.figure(figsize=(12, 6))
    
    if suspicious_df.empty:
        # Handle empty dataset: create empty chart with message
        plt.text(
            0.5, 0.5,
            'No suspicious IPs detected',
            horizontalalignment='center',
            verticalalignment='center',
            transform=plt.gca().transAxes,
            fontsize=14,
            color='gray'
        )
        plt.title('Suspicious IPs by Connection Count', fontsize=14, fontweight='bold')
    else:
        # Sort by connection count for better visualization
        sorted_df = suspicious_df.sort_values('total_connections', ascending=False)
        
        # Create bar chart
        plt.bar(range(len(sorted_df)), sorted_df['total_connections'], color='#d9534f')
        plt.xlabel('Source IP Address', fontsize=11)
        plt.ylabel('Total Connections', fontsize=11)
        plt.title('Suspicious IPs by Connection Count', fontsize=14, fontweight='bold')
        
        # Set x-axis labels with IP addresses
        plt.xticks(
            range(len(sorted_df)),
            sorted_df['srcip'].values,
            rotation=45,
            ha='right',
            fontsize=9
        )
        
        plt.grid(axis='y', alpha=0.3, linestyle='--')
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/suspicious_ips_connections.png', dpi=100, bbox_inches='tight')
    plt.close()


def _generate_risk_distribution_chart(
    all_features_df: pd.DataFrame,
    output_dir: str
) -> None:
    """
    Generate pie chart showing risk level distribution.
    
    Args:
        all_features_df: DataFrame with all features including risk_level column
        output_dir: Directory to save PNG file
    """
    plt.figure(figsize=(8, 8))
    
    if all_features_df.empty or 'risk_level' not in all_features_df.columns:
        # Handle empty dataset
        plt.text(
            0.5, 0.5,
            'No data available',
            horizontalalignment='center',
            verticalalignment='center',
            transform=plt.gca().transAxes,
            fontsize=14,
            color='gray'
        )
        plt.title('Risk Level Distribution', fontsize=14, fontweight='bold')
    else:
        # Count risk levels
        risk_counts = all_features_df['risk_level'].value_counts()
        
        # Define colors for each risk level
        colors_map = {
            'High': '#d9534f',    # Red
            'Medium': '#f0ad4e',  # Orange
            'Low': '#5bc0de',     # Light blue
            'Normal': '#5cb85c'   # Green
        }
        
        # Create colors list in the order of risk_counts
        colors = [colors_map.get(level, '#777777') for level in risk_counts.index]
        
        # Create pie chart
        plt.pie(
            risk_counts.values,
            labels=risk_counts.index,
            colors=colors,
            autopct='%1.1f%%',
            startangle=90,
            textprops={'fontsize': 11}
        )
        
        plt.title('Risk Level Distribution', fontsize=14, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/risk_level_distribution.png', dpi=100, bbox_inches='tight')
    plt.close()


def _generate_top_10_chart(
    all_features_df: pd.DataFrame,
    output_dir: str
) -> None:
    """
    Generate bar chart showing top 10 most active IPs by connection count.
    
    Handles cases with fewer than 10 IPs gracefully by showing all available IPs.
    
    Args:
        all_features_df: DataFrame with all features including srcip and total_connections
        output_dir: Directory to save PNG file
    """
    plt.figure(figsize=(12, 6))
    
    if all_features_df.empty or 'total_connections' not in all_features_df.columns:
        # Handle empty dataset
        plt.text(
            0.5, 0.5,
            'No data available',
            horizontalalignment='center',
            verticalalignment='center',
            transform=plt.gca().transAxes,
            fontsize=14,
            color='gray'
        )
        plt.title('Top 10 Most Active IPs', fontsize=14, fontweight='bold')
    else:
        # Sort by connection count and take top 10 (or fewer if less than 10 IPs)
        sorted_df = all_features_df.sort_values('total_connections', ascending=False)
        top_n = min(10, len(sorted_df))
        top_df = sorted_df.head(top_n)
        
        # Create bar chart
        plt.bar(range(len(top_df)), top_df['total_connections'], color='#5bc0de')
        plt.xlabel('Source IP Address', fontsize=11)
        plt.ylabel('Total Connections', fontsize=11)
        
        # Dynamic title based on actual count
        if top_n < 10:
            plt.title(f'Top {top_n} Most Active IPs', fontsize=14, fontweight='bold')
        else:
            plt.title('Top 10 Most Active IPs', fontsize=14, fontweight='bold')
        
        # Set x-axis labels with IP addresses
        plt.xticks(
            range(len(top_df)),
            top_df['srcip'].values,
            rotation=45,
            ha='right',
            fontsize=9
        )
        
        plt.grid(axis='y', alpha=0.3, linestyle='--')
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/top_10_active_ips.png', dpi=100, bbox_inches='tight')
    plt.close()
