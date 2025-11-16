"""Tests for fetch_server_list() public method."""
import sys
import os
import pytest
from python_blossom import BlossomClient

# Add tests directory to path so we can import conftest
sys.path.insert(0, os.path.dirname(__file__))
from conftest import NSEC, SERVERS, RELAYS


@pytest.fixture(scope='class')
def client():
    """Create a BlossomClient instance for testing."""
    return BlossomClient(nsec=NSEC, default_servers=SERVERS)


@pytest.fixture(scope='class')
def server_list(client):
    """Fetch server list once and cache result for all tests.
    
    This fixture fetches the server list once per test class and all tests
    reuse the result, avoiding duplicate network calls.
    """
    return client.fetch_server_list(relays=RELAYS, pubkey=client.pubkey_hex)


class TestFetchServerList:
    """Tests for fetch_server_list() public method."""
    
    def test_fetch_server_list_returns_list(self, server_list):
        """Test that fetch_server_list returns a list of valid servers."""
        assert isinstance(server_list, list)
        
        # Verify all items are strings (URLs)
        for server in server_list:
            assert isinstance(server, str)
            assert server.startswith('http')
    

