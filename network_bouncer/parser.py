"""
Data Parser Component

Handles loading and validating CSV network traffic data from the UNSW-NB15 dataset.
"""

import pandas as pd
import os
import logging

logger = logging.getLogger(__name__)


def load_dataset(file_path: str) -> pd.DataFrame:
    """
    Load and validate UNSW-NB15 dataset from CSV file.
    
    Reads CSV network traffic data, validates the presence of all required columns,
    handles missing values and invalid port numbers gracefully, and ensures the
    dataset contains at least one valid record after cleaning.
    
    Args:
        file_path: Path to CSV file containing UNSW-NB15 network traffic data.
            The file must include columns: srcip, dstip, dsport, proto, state, label.
        
    Returns:
        DataFrame with validated network traffic data containing all required columns
        and at least one valid record. Rows with missing critical values (srcip, dstip)
        are removed. Invalid port values are coerced to NaN.
        
    Raises:
        FileNotFoundError: If the specified file path does not exist. Error message
            includes the file path and suggests checking the path.
        ValueError: If required columns are missing from the dataset (error lists
            the specific missing columns) or if the dataset contains no valid records
            after cleaning.
            
    Example:
        >>> df = load_dataset('data/UNSW-NB15.csv')
        >>> print(df.columns.tolist())
        ['srcip', 'dstip', 'dsport', 'proto', 'state', 'label', ...]
        >>> len(df) > 0
        True
    """
    # Validate file existence
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}. Please check the file path and try again.")
    
    # Load CSV with bad line handling
    logger.info(f"Loading dataset from {file_path}")
    df = pd.read_csv(file_path, on_bad_lines='skip')
    
    # Validate required columns
    required_cols = ['srcip', 'dstip', 'dsport', 'proto', 'state', 'label']
    missing_cols = set(required_cols) - set(df.columns)
    
    if missing_cols:
        missing_list = sorted(list(missing_cols))
        raise ValueError(
            f"Missing required columns: {missing_list}. "
            f"Dataset must include: srcip, dstip, dsport, proto, state, label"
        )
    
    # Check for empty dataset
    if len(df) == 0:
        raise ValueError("Dataset contains no records. No data to analyze.")
    
    # Handle missing values in critical fields
    original_len = len(df)
    df = df.dropna(subset=['srcip', 'dstip'])
    dropped_missing = original_len - len(df)
    
    if dropped_missing > 0:
        logger.warning(f"Dropped {dropped_missing} rows with missing critical values (srcip, dstip)")
    
    # Check if dataset is empty after cleaning
    if len(df) == 0:
        raise ValueError("Dataset contains no valid records after removing rows with missing critical values.")
    
    # Handle invalid port values
    df['dsport'] = pd.to_numeric(df['dsport'], errors='coerce')
    invalid_ports = df['dsport'].isna().sum()
    
    if invalid_ports > 0:
        logger.warning(f"Found {invalid_ports} invalid port values, coercing to NaN")
    
    logger.info(f"Successfully loaded {len(df)} valid records")
    
    return df
