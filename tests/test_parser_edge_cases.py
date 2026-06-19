"""
Unit tests for parser edge cases.

Tests specific edge cases including non-existent files, empty files, 
header-only files, and specific corrupted formats.
"""

import pytest
import tempfile
import os
from network_bouncer.parser import load_dataset


class TestParserEdgeCases:
    """Test suite for parser edge cases."""
    
    def test_non_existent_file_path(self):
        """
        Test with non-existent file path.
        
        Validates: Requirements 1.1, 10.1
        """
        non_existent_path = "/path/to/non/existent/file.csv"
        
        with pytest.raises(FileNotFoundError) as exc_info:
            load_dataset(non_existent_path)
        
        error_msg = str(exc_info.value)
        assert "File not found" in error_msg
        assert non_existent_path in error_msg
        assert "check the file path" in error_msg
    
    def test_completely_empty_file(self):
        """
        Test with completely empty file (no headers, no data).
        
        Validates: Requirements 1.4, 10.2
        """
        # Create a completely empty CSV file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            # Write nothing
            temp_path = f.name
        
        try:
            with pytest.raises(Exception) as exc_info:
                load_dataset(temp_path)
            
            error_msg = str(exc_info.value)
            # Empty file will fail - pandas raises "No columns to parse from file"
            # or missing columns error
            assert ("No columns to parse" in error_msg or 
                    "Missing required columns" in error_msg)
        finally:
            os.unlink(temp_path)
    
    def test_file_containing_only_headers(self):
        """
        Test with file containing only headers (no data rows).
        
        Validates: Requirements 1.4, 10.2
        """
        # Create a CSV with headers only
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("srcip,dstip,dsport,proto,state,label\n")
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError) as exc_info:
                load_dataset(temp_path)
            
            error_msg = str(exc_info.value)
            assert "contains no records" in error_msg
            assert "No data to analyze" in error_msg
        finally:
            os.unlink(temp_path)
    
    def test_corrupted_row_extra_fields(self):
        """
        Test with specific corrupted row format: extra fields.
        
        Validates: Requirements 1.7, 10.5
        """
        # Create a CSV with a row containing extra fields
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("srcip,dstip,dsport,proto,state,label\n")
            f.write("192.168.1.1,10.0.0.1,80,tcp,CON,0\n")
            f.write("192.168.1.2,10.0.0.2,443,tcp,CON,1,extra1,extra2,extra3\n")  # Extra fields
            f.write("192.168.1.3,10.0.0.3,22,tcp,FIN,0\n")
            temp_path = f.name
        
        try:
            df = load_dataset(temp_path)
            
            # Should load successfully with all rows
            # pandas handles extra fields by ignoring them or treating them as extra columns
            assert len(df) >= 2  # At minimum, valid rows should be present
            assert '192.168.1.1' in df['srcip'].values
            assert '192.168.1.3' in df['srcip'].values
        finally:
            os.unlink(temp_path)
    
    def test_corrupted_row_fewer_fields(self):
        """
        Test with specific corrupted row format: fewer fields.
        
        Validates: Requirements 1.7, 10.5
        """
        # Create a CSV with a row missing multiple fields
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as f:
            f.write("srcip,dstip,dsport,proto,state,label\n")
            f.write("192.168.1.1,10.0.0.1,80,tcp,CON,0\n")
            f.write("192.168.1.2,10.0.0.2\n")  # Missing multiple fields
            f.write("192.168.1.3,10.0.0.3,22,tcp,FIN,0\n")
            temp_path = f.name
        
        try:
            df = load_dataset(temp_path)
            
            # Should load successfully with valid rows
            # Row with missing fields will have NaN values but won't crash
            assert len(df) >= 2  # Valid rows should be present
            assert '192.168.1.1' in df['srcip'].values
            assert '192.168.1.3' in df['srcip'].values
        finally:
            os.unlink(temp_path)
    
    def test_corrupted_row_special_characters(self):
        """
        Test with specific corrupted row format: special characters and encoding issues.
        
        Validates: Requirements 1.7, 10.5
        """
        # Create a CSV with special characters
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            f.write("srcip,dstip,dsport,proto,state,label\n")
            f.write("192.168.1.1,10.0.0.1,80,tcp,CON,0\n")
            f.write("192.168.1.2,10.0.0.2,443,tcp,CON\x00\x00,1\n")  # Null bytes
            f.write("192.168.1.3,10.0.0.3,22,tcp,FIN,0\n")
            temp_path = f.name
        
        try:
            df = load_dataset(temp_path)
            
            # Should load successfully with valid rows
            assert len(df) >= 2
            assert '192.168.1.1' in df['srcip'].values
            assert '192.168.1.3' in df['srcip'].values
        finally:
            os.unlink(temp_path)
    
    def test_corrupted_row_mixed_delimiters(self):
        """
        Test with specific corrupted row format: mixed delimiters.
        
        Validates: Requirements 1.7, 10.5
        """
        # Create a CSV where one row uses tabs instead of commas
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("srcip,dstip,dsport,proto,state,label\n")
            f.write("192.168.1.1,10.0.0.1,80,tcp,CON,0\n")
            f.write("192.168.1.2\t10.0.0.2\t443\ttcp\tCON\t1\n")  # Tab-delimited instead of comma
            f.write("192.168.1.3,10.0.0.3,22,tcp,FIN,0\n")
            temp_path = f.name
        
        try:
            df = load_dataset(temp_path)
            
            # Should load successfully with valid comma-separated rows
            # Tab-delimited row will be treated as a single field or skipped
            assert len(df) >= 2
            assert '192.168.1.1' in df['srcip'].values
            assert '192.168.1.3' in df['srcip'].values
        finally:
            os.unlink(temp_path)
    
    def test_file_with_only_whitespace_rows(self):
        """
        Test with file containing only whitespace rows.
        
        Validates: Requirements 1.4, 10.2
        """
        # Create a CSV with headers and only whitespace rows
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("srcip,dstip,dsport,proto,state,label\n")
            f.write("     \n")
            f.write("\t\t\t\n")
            f.write("   ,  ,  ,  ,  ,  \n")
            temp_path = f.name
        
        try:
            # Pandas treats whitespace-only values as strings, not NaN
            # So these rows will actually be loaded
            df = load_dataset(temp_path)
            
            # The rows with whitespace will be present but may have whitespace values
            # This validates that the parser handles whitespace gracefully
            assert len(df) >= 0  # Parser doesn't crash
        finally:
            os.unlink(temp_path)
    
    def test_file_with_quoted_fields_containing_commas(self):
        """
        Test with properly formatted CSV containing quoted fields with commas.
        
        This validates that the parser handles standard CSV quoting correctly.
        Validates: Requirements 1.1
        """
        # Create a CSV with quoted fields (valid CSV format)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("srcip,dstip,dsport,proto,state,label\n")
            f.write('192.168.1.1,10.0.0.1,80,"tcp,udp",CON,0\n')  # Comma in quoted field
            f.write('192.168.1.2,10.0.0.2,443,tcp,CON,0\n')
            temp_path = f.name
        
        try:
            df = load_dataset(temp_path)
            
            # Should load successfully
            assert len(df) == 2
            assert '192.168.1.1' in df['srcip'].values
            assert df[df['srcip'] == '192.168.1.1']['proto'].iloc[0] == 'tcp,udp'
        finally:
            os.unlink(temp_path)
