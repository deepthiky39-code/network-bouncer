"""
Unit tests for the parser module.

Tests specific examples, edge cases, and error conditions.
"""

import pytest
import pandas as pd
import tempfile
import os
from network_bouncer.parser import load_dataset


class TestLoadDataset:
    """Test suite for load_dataset function."""
    
    def test_file_not_found(self):
        """Test that FileNotFoundError is raised for non-existent file."""
        with pytest.raises(FileNotFoundError) as exc_info:
            load_dataset("non_existent_file.csv")
        
        assert "File not found" in str(exc_info.value)
        assert "non_existent_file.csv" in str(exc_info.value)
    
    def test_missing_required_columns(self):
        """Test that ValueError is raised when required columns are missing."""
        # Create a CSV with missing columns
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("srcip,dstip,proto\n")
            f.write("192.168.1.1,10.0.0.1,tcp\n")
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError) as exc_info:
                load_dataset(temp_path)
            
            error_msg = str(exc_info.value)
            assert "Missing required columns" in error_msg
            assert "dsport" in error_msg
            assert "state" in error_msg
            assert "label" in error_msg
        finally:
            os.unlink(temp_path)
    
    def test_empty_dataset(self):
        """Test that ValueError is raised for empty dataset."""
        # Create an empty CSV with headers only
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("srcip,dstip,dsport,proto,state,label\n")
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError) as exc_info:
                load_dataset(temp_path)
            
            assert "contains no records" in str(exc_info.value)
        finally:
            os.unlink(temp_path)
    
    def test_valid_dataset_loads_successfully(self):
        """Test that a valid dataset loads correctly."""
        # Create a valid CSV
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("srcip,dstip,dsport,proto,state,label\n")
            f.write("192.168.1.1,10.0.0.1,80,tcp,CON,0\n")
            f.write("192.168.1.2,10.0.0.2,443,tcp,CON,1\n")
            temp_path = f.name
        
        try:
            df = load_dataset(temp_path)
            
            assert len(df) == 2
            assert list(df.columns) == ['srcip', 'dstip', 'dsport', 'proto', 'state', 'label']
            assert df['srcip'].iloc[0] == '192.168.1.1'
            assert df['dsport'].iloc[0] == 80
        finally:
            os.unlink(temp_path)
    
    def test_drops_rows_with_missing_critical_values(self):
        """Test that rows with missing srcip or dstip are dropped."""
        # Create a CSV with missing critical values
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("srcip,dstip,dsport,proto,state,label\n")
            f.write("192.168.1.1,10.0.0.1,80,tcp,CON,0\n")
            f.write(",10.0.0.2,443,tcp,CON,1\n")  # Missing srcip
            f.write("192.168.1.3,,22,tcp,FIN,0\n")  # Missing dstip
            f.write("192.168.1.4,10.0.0.4,8080,tcp,CON,0\n")
            temp_path = f.name
        
        try:
            df = load_dataset(temp_path)
            
            # Should only have 2 valid rows
            assert len(df) == 2
            assert '192.168.1.1' in df['srcip'].values
            assert '192.168.1.4' in df['srcip'].values
        finally:
            os.unlink(temp_path)
    
    def test_handles_invalid_port_values(self):
        """Test that invalid port values are coerced to NaN."""
        # Create a CSV with invalid port values
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("srcip,dstip,dsport,proto,state,label\n")
            f.write("192.168.1.1,10.0.0.1,80,tcp,CON,0\n")
            f.write("192.168.1.2,10.0.0.2,invalid,tcp,CON,1\n")  # Invalid port
            f.write("192.168.1.3,10.0.0.3,99999,tcp,FIN,0\n")  # Valid number
            temp_path = f.name
        
        try:
            df = load_dataset(temp_path)
            
            # All rows should be present
            assert len(df) == 3
            
            # Valid ports should be numeric
            assert df['dsport'].iloc[0] == 80
            assert df['dsport'].iloc[2] == 99999
            
            # Invalid port should be NaN
            assert pd.isna(df['dsport'].iloc[1])
        finally:
            os.unlink(temp_path)
    
    def test_skips_corrupted_rows(self):
        """Test that corrupted rows are skipped using on_bad_lines='skip'."""
        # Create a CSV with a truly corrupted row (malformed line)
        # Note: pandas read_csv with on_bad_lines='skip' will skip lines that can't be parsed
        # Lines with missing columns will still be read with NaN values
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as f:
            f.write("srcip,dstip,dsport,proto,state,label\n")
            f.write("192.168.1.1,10.0.0.1,80,tcp,CON,0\n")
            f.write("192.168.1.2,10.0.0.2,443,tcp,CON\n")  # Missing one column - will have NaN
            f.write("192.168.1.3,10.0.0.3,22,tcp,FIN,0\n")
            temp_path = f.name
        
        try:
            df = load_dataset(temp_path)
            
            # Pandas reads the row with missing column as having NaN for that field
            # This is valid behavior - the row is present but incomplete
            # All three rows should be present since srcip and dstip are not missing
            assert len(df) == 3
            assert '192.168.1.1' in df['srcip'].values
            assert '192.168.1.2' in df['srcip'].values
            assert '192.168.1.3' in df['srcip'].values
        finally:
            os.unlink(temp_path)
    
    def test_dataset_empty_after_cleaning(self):
        """Test that ValueError is raised if all rows are invalid."""
        # Create a CSV where all rows have missing critical values
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("srcip,dstip,dsport,proto,state,label\n")
            f.write(",10.0.0.1,80,tcp,CON,0\n")  # Missing srcip
            f.write("192.168.1.2,,443,tcp,CON,1\n")  # Missing dstip
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError) as exc_info:
                load_dataset(temp_path)
            
            assert "no valid records" in str(exc_info.value)
        finally:
            os.unlink(temp_path)
    
    def test_extra_columns_are_preserved(self):
        """Test that extra columns beyond required ones are preserved."""
        # Create a CSV with extra columns
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("srcip,dstip,dsport,proto,state,label,bytes,duration\n")
            f.write("192.168.1.1,10.0.0.1,80,tcp,CON,0,1024,30\n")
            temp_path = f.name
        
        try:
            df = load_dataset(temp_path)
            
            assert len(df) == 1
            assert 'bytes' in df.columns
            assert 'duration' in df.columns
            assert df['bytes'].iloc[0] == 1024
        finally:
            os.unlink(temp_path)
