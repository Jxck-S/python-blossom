"""Tests for publish_server_list_event() public method."""
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
def publish_event_result(client):
    """Publish a server list event once and cache result for multiple tests.
    
    This fixture publishes the event once per test class and caches the result.
    All tests in the class reuse this result, avoiding duplicate API calls
    and reducing relay strain.
    """
    return client.publish_server_list_event(relays=RELAYS)


class TestPublishServerListEvent:
    """Tests for publish_server_list_event() public method."""
    
    def test_publish_server_list_event_returns_event_id(self, publish_event_result):
        """Test that publish_server_list_event returns an event ID."""
        assert publish_event_result is not None
        assert isinstance(publish_event_result, str)
    
    def test_publish_server_list_event_with_custom_servers(self, client):
        """Test publishing with custom server list."""
        custom_servers = ['https://custom.com']
        event_id = client.publish_server_list_event(relays=RELAYS, servers=custom_servers)
        
        assert isinstance(event_id, str)
        assert len(event_id) == 64
    
    def test_publish_server_list_event_returns_valid_hex_id(self, publish_event_result):
        """Test that method returns valid hex event ID."""
        assert len(publish_event_result) == 64  # 256-bit hex
        try:
            int(publish_event_result, 16)
        except ValueError:
            pytest.fail("Event ID is not valid hex")
