"""Tests for generate_server_list_event() public method."""
import sys
import os
import pytest
from python_blossom import BlossomClient

# Add tests directory to path so we can import conftest
sys.path.insert(0, os.path.dirname(__file__))
from conftest import NSEC, SERVERS


@pytest.fixture(scope='class')
def client():
    """Create a BlossomClient instance for testing."""
    return BlossomClient(nsec=NSEC, default_servers=SERVERS)


@pytest.fixture(scope='class')
def generated_event(client):
    """Generate server list event once and cache result for multiple tests.
    
    This fixture generates the event once per test class and caches the result.
    All tests in the class reuse this result, avoiding duplicate generation.
    """
    return client.generate_server_list_event()


class TestGenerateServerListEvent:
    """Tests for generate_server_list_event() public method."""
    
    def test_generate_server_list_event_returns_dict(self, generated_event):
        """Test that generate_server_list_event returns a dict."""
        assert isinstance(generated_event, dict)
    
    def test_generate_server_list_event_has_required_fields(self, generated_event):
        """Test that generated event has required fields."""
        required_fields = ['id', 'pubkey', 'kind', 'tags', 'content', 'sig', 'created_at']
        for field in required_fields:
            assert field in generated_event, f"Missing required field: {field}"
    
    def test_generate_server_list_event_kind_is_10063(self, generated_event):
        """Test that generated event has kind 10063 (BUD-03)."""
        assert generated_event['kind'] == 10063
    
    def test_generate_server_list_event_content_is_empty(self, generated_event):
        """Test that generated event has empty content."""
        assert generated_event['content'] == ''
    
    def test_generate_server_list_event_has_server_tags(self, generated_event):
        """Test that generated event has server tags."""
        server_tags = [tag for tag in generated_event['tags'] if len(tag) > 0 and tag[0] == 'server']
        assert len(server_tags) > 0
    
    def test_generate_server_list_event_tags_contain_servers(self, generated_event):
        """Test that server tags contain expected servers."""
        servers_in_tags = [tag[1] for tag in generated_event['tags'] if len(tag) > 1 and tag[0] == 'server']
        
        for server in SERVERS:
            assert server in servers_in_tags
    
    def test_generate_server_list_event_has_valid_signature(self, generated_event):
        """Test that generated event has valid signature."""
        assert 'sig' in generated_event
        assert isinstance(generated_event['sig'], str)
        assert len(generated_event['sig']) == 128  # 256-bit hex signature
    
    def test_generate_server_list_event_has_valid_id(self, generated_event):
        """Test that generated event has valid ID."""
        assert 'id' in generated_event
        assert isinstance(generated_event['id'], str)
        assert len(generated_event['id']) == 64  # 256-bit hex ID
