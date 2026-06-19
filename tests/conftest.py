"""
Shared test fixtures and Hypothesis strategies for Network Bouncer tests.
"""

import pytest
import pandas as pd
import hypothesis.strategies as st
from hypothesis import settings
from hypothesis.extra.pandas import data_frames, column
import numpy as np


# Configure Hypothesis for faster test execution
settings.register_profile("fast", max_examples=20)
settings.load_profile("fast")


# Strategy for IP addresses
@st.composite
def ip_addresses(draw):
    """Generate valid IPv4 addresses."""
    octets = [draw(st.integers(min_value=0, max_value=255)) for _ in range(4)]
    return '.'.join(map(str, octets))


# Strategy for valid ports
valid_ports = st.integers(min_value=1, max_value=65535)


# Strategy for connection records
@st.composite
def connection_strategy(draw):
    """Generate valid connection record DataFrames."""
    n_rows = draw(st.integers(min_value=1, max_value=100))
    
    return pd.DataFrame({
        'srcip': [draw(ip_addresses()) for _ in range(n_rows)],
        'dstip': [draw(ip_addresses()) for _ in range(n_rows)],
        'dsport': [draw(valid_ports) for _ in range(n_rows)],
        'proto': draw(st.lists(st.sampled_from(['tcp', 'udp', 'icmp']), min_size=n_rows, max_size=n_rows)),
        'state': draw(st.lists(st.sampled_from(['FIN', 'INT', 'CON', 'REQ']), min_size=n_rows, max_size=n_rows)),
        'label': draw(st.lists(st.integers(min_value=0, max_value=1), min_size=n_rows, max_size=n_rows))
    })


# Strategy for datasets with missing values
@st.composite
def noisy_connection_strategy(draw):
    """Generate connection record DataFrames with missing values."""
    df = draw(connection_strategy())
    # Add 10% missing values randomly
    mask = np.random.random(df.shape) < 0.1
    return df.mask(mask)


# Strategy for features (post-aggregation)
@st.composite
def feature_strategy(draw):
    """Generate aggregated feature records."""
    return {
        'srcip': draw(ip_addresses()),
        'total_connections': draw(st.integers(min_value=0, max_value=500)),
        'unique_destinations': draw(st.integers(min_value=0, max_value=100)),
        'unique_ports': draw(st.integers(min_value=0, max_value=100))
    }


# Fixtures for sample data
@pytest.fixture
def sample_connection_data():
    """Provide sample connection data for unit tests."""
    return pd.DataFrame({
        'srcip': ['192.168.1.1', '192.168.1.1', '192.168.1.2'],
        'dstip': ['10.0.0.1', '10.0.0.2', '10.0.0.1'],
        'dsport': [80, 443, 22],
        'proto': ['tcp', 'tcp', 'tcp'],
        'state': ['CON', 'CON', 'FIN'],
        'label': [0, 0, 1]
    })


@pytest.fixture
def sample_features():
    """Provide sample aggregated features for unit tests."""
    return pd.DataFrame({
        'srcip': ['192.168.1.1', '192.168.1.2', '192.168.1.3'],
        'total_connections': [150, 75, 200],
        'unique_destinations': [60, 25, 80],
        'unique_ports': [40, 15, 50]
    })
