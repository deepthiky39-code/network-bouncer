"""
Property-based tests for the parser module using Hypothesis.

Tests correctness properties across a wide range of generated inputs.
"""

import pytest
import pandas as pd
import tempfile
import os
from hypothesis import given, settings, strategies as st
from hypothesis.extra.pandas import data_frames, column
import hypothesis.strategies as st_base
from network_bouncer.parser import load_dataset


# Strategy for generating column names
@st.composite
def column_names_strategy(draw):
    """Generate various combinations of column names for testing validation."""
    required_cols = ['srcip', 'dstip', 'dsport', 'proto', 'state', 'label']
    
    # Decide whether to include all required columns
    include_all = draw(st.booleans())
    
    if include_all:
        # Include all required columns (may add extra columns too)
        cols = required_cols.copy()
        # Optionally add extra columns
        num_extra = draw(st.integers(min_value=0, max_value=3))
        extra_cols = [f'extra_col_{i}' for i in range(num_extra)]
        cols.extend(extra_cols)
        return cols
    else:
        # Missing at least one required column
        num_to_include = draw(st.integers(min_value=0, max_value=len(required_cols) - 1))
        cols = draw(st.lists(st.sampled_from(required_cols), min_size=num_to_include, max_size=num_to_include, unique=True))
        return cols


# Strategy for generating DataFrames with various column combinations
@st.composite
def dataframe_with_columns(draw):
    """Generate DataFrames with various column combinations."""
    cols = draw(column_names_strategy())
    
    # Skip empty column lists - pandas can't write/read CSVs with no columns
    if len(cols) == 0:
        # Generate at least one column to make it a valid CSV
        cols = [draw(st.sampled_from(['extra_col_1', 'extra_col_2']))]
    
    n_rows = draw(st.integers(min_value=1, max_value=10))
    
    data = {}
    for col in cols:
        if col == 'srcip' or col == 'dstip':
            data[col] = [f'192.168.1.{i}' for i in range(n_rows)]
        elif col == 'dsport':
            data[col] = draw(st.lists(st.integers(min_value=1, max_value=65535), min_size=n_rows, max_size=n_rows))
        elif col == 'proto':
            data[col] = draw(st.lists(st.sampled_from(['tcp', 'udp', 'icmp']), min_size=n_rows, max_size=n_rows))
        elif col == 'state':
            data[col] = draw(st.lists(st.sampled_from(['FIN', 'INT', 'CON', 'REQ']), min_size=n_rows, max_size=n_rows))
        elif col == 'label':
            data[col] = draw(st.lists(st.integers(min_value=0, max_value=1), min_size=n_rows, max_size=n_rows))
        else:
            # Extra columns get dummy values
            data[col] = [f'value_{i}' for i in range(n_rows)]
    
    return pd.DataFrame(data)


# Helper function to write DataFrame to temporary CSV
def write_temp_csv(df):
    """Write DataFrame to temporary CSV file and return path."""
    f = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
    df.to_csv(f, index=False)
    f.close()
    return f.name


# Feature: network-bouncer, Property 1: Column Validation Correctness
@settings(max_examples=100, deadline=None)
@given(dataframe_with_columns())
def test_property_1_column_validation_correctness(df):
    """
    Property 1: Column Validation Correctness
    
    **Validates: Requirements 1.2, 1.3**
    
    For any CSV dataset with a given set of columns, the parser SHALL accept 
    datasets containing all required columns (srcip, dstip, dsport, proto, state, label) 
    and SHALL reject datasets missing any required column with a descriptive error 
    message listing the missing columns.
    """
    required_cols = ['srcip', 'dstip', 'dsport', 'proto', 'state', 'label']
    
    # Write DataFrame to temporary CSV
    temp_path = write_temp_csv(df)
    
    try:
        # Check if all required columns are present
        has_all_required = all(col in df.columns for col in required_cols)
        
        if has_all_required:
            # Should accept - no exception should be raised
            result_df = load_dataset(temp_path)
            assert result_df is not None
            assert len(result_df) > 0  # Should have data
        else:
            # Should reject with descriptive error
            with pytest.raises(ValueError) as exc_info:
                load_dataset(temp_path)
            
            error_message = str(exc_info.value)
            
            # Verify error message contains "Missing required columns"
            assert "Missing required columns" in error_message
            
            # Verify all missing columns are listed in the error message
            missing_cols = set(required_cols) - set(df.columns)
            for missing_col in missing_cols:
                assert missing_col in error_message
    
    finally:
        # Clean up temporary file
        if os.path.exists(temp_path):
            os.unlink(temp_path)


# Strategy for generating datasets with various data quality issues
@st.composite
def noisy_dataset_strategy(draw):
    """Generate datasets with missing values, invalid ports, and good data."""
    n_rows = draw(st.integers(min_value=5, max_value=20))
    
    srcips = []
    dstips = []
    dsports = []
    protos = []
    states = []
    labels = []
    
    for i in range(n_rows):
        # Randomly decide what kind of row this will be
        row_type = draw(st.sampled_from(['valid', 'missing_srcip', 'missing_dstip', 'invalid_port']))
        
        if row_type == 'valid':
            srcips.append(f'192.168.1.{i}')
            dstips.append(f'10.0.0.{i}')
            dsports.append(draw(st.integers(min_value=1, max_value=65535)))
            protos.append(draw(st.sampled_from(['tcp', 'udp', 'icmp'])))
            states.append(draw(st.sampled_from(['FIN', 'INT', 'CON', 'REQ'])))
            labels.append(draw(st.integers(min_value=0, max_value=1)))
        elif row_type == 'missing_srcip':
            srcips.append(None)  # Missing srcip
            dstips.append(f'10.0.0.{i}')
            dsports.append(draw(st.integers(min_value=1, max_value=65535)))
            protos.append(draw(st.sampled_from(['tcp', 'udp', 'icmp'])))
            states.append(draw(st.sampled_from(['FIN', 'INT', 'CON', 'REQ'])))
            labels.append(draw(st.integers(min_value=0, max_value=1)))
        elif row_type == 'missing_dstip':
            srcips.append(f'192.168.1.{i}')
            dstips.append(None)  # Missing dstip
            dsports.append(draw(st.integers(min_value=1, max_value=65535)))
            protos.append(draw(st.sampled_from(['tcp', 'udp', 'icmp'])))
            states.append(draw(st.sampled_from(['FIN', 'INT', 'CON', 'REQ'])))
            labels.append(draw(st.integers(min_value=0, max_value=1)))
        elif row_type == 'invalid_port':
            srcips.append(f'192.168.1.{i}')
            dstips.append(f'10.0.0.{i}')
            dsports.append(draw(st.sampled_from(['invalid', 'NaN', '', '-999'])))  # Invalid port
            protos.append(draw(st.sampled_from(['tcp', 'udp', 'icmp'])))
            states.append(draw(st.sampled_from(['FIN', 'INT', 'CON', 'REQ'])))
            labels.append(draw(st.integers(min_value=0, max_value=1)))
    
    df = pd.DataFrame({
        'srcip': srcips,
        'dstip': dstips,
        'dsport': dsports,
        'proto': protos,
        'state': states,
        'label': labels
    })
    
    return df


# Feature: network-bouncer, Property 2: Parser Robustness
@settings(max_examples=100, deadline=None)
@given(noisy_dataset_strategy())
def test_property_2_parser_robustness(df):
    """
    Property 2: Parser Robustness
    
    **Validates: Requirements 1.5, 1.6, 1.7**
    
    For any dataset containing a mix of valid data, missing values, invalid port values, 
    and corrupted rows, the parser SHALL successfully extract all valid records without 
    terminating execution, skipping invalid entries appropriately.
    """
    # Write DataFrame to temporary CSV
    temp_path = write_temp_csv(df)
    
    try:
        # Count valid rows (rows with both srcip and dstip present)
        valid_rows = df.dropna(subset=['srcip', 'dstip'])
        num_valid_rows = len(valid_rows)
        
        if num_valid_rows > 0:
            # Should successfully load and extract valid records
            result_df = load_dataset(temp_path)
            
            # Verify the function didn't crash
            assert result_df is not None
            
            # Verify we got the expected number of valid rows
            assert len(result_df) == num_valid_rows
            
            # Verify no rows with missing srcip or dstip
            assert result_df['srcip'].notna().all()
            assert result_df['dstip'].notna().all()
            
            # Verify that dsport column exists (invalid ports should be coerced to NaN)
            assert 'dsport' in result_df.columns
            
            # The dsport column should be numeric (may have NaN for invalid values)
            # All non-NaN values should be able to be converted to numeric
            non_nan_ports = result_df['dsport'].dropna()
            if len(non_nan_ports) > 0:
                # Should all be numeric
                assert pd.api.types.is_numeric_dtype(result_df['dsport'])
        else:
            # No valid rows - should raise ValueError
            with pytest.raises(ValueError) as exc_info:
                load_dataset(temp_path)
            
            # Should indicate no valid records
            assert "no valid records" in str(exc_info.value).lower()
    
    finally:
        # Clean up temporary file
        if os.path.exists(temp_path):
            os.unlink(temp_path)
