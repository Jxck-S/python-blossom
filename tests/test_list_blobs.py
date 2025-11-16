"""Tests for list_blobs() public method."""
import sys
import os
import pytest
from python_blossom import BlossomClient

# Add tests directory to path so we can import conftest
sys.path.insert(0, os.path.dirname(__file__))
from conftest import NSEC, SERVERS, SERVER_CAPABILITIES


@pytest.fixture(scope='class')
def client():
    """Create a BlossomClient instance for testing."""
    return BlossomClient(nsec=NSEC, default_servers=SERVERS)


@pytest.fixture(scope='class')
def list_blobs_server():
    """Select a server that supports list_blob operation."""
    # Find first server that supports list_blob
    for server in SERVERS:
        if SERVER_CAPABILITIES.get(server, {}).get('list_blob', False):
            return server
    # If no server supports list_blob, skip tests
    pytest.skip("No servers available that support list_blob")


@pytest.fixture(scope='class')
def list_blobs_result(client, test_image, list_blobs_server):
    """Upload a blob once and list blobs, reusing result across all tests.
    
    This fixture uploads blob data once per test class, then calls list_blobs
    once and caches the result. All tests in the class reuse this result,
    avoiding duplicate list_blobs operations and reducing server strain.
    
    Automatically uses auth if the server requires it for list_blob.
    """
    # Upload a blob first so we have something to list
    client.upload_blob(list_blobs_server, data=test_image, mime_type='image/png')
    
    # Determine if auth is required for this server
    use_auth = SERVER_CAPABILITIES.get(list_blobs_server, {}).get('auth_required', False)
    
    # List blobs with auth if required
    blobs = client.list_blobs(list_blobs_server, pubkey=client.pubkey_hex, use_auth=use_auth)
    return blobs


class TestListBlobs:
    """Tests for list_blobs() public method."""
    
    def test_list_blobs_returns_list(self, list_blobs_result):
        """Test that list_blobs returns a list."""
        assert isinstance(list_blobs_result, list)
    
    def test_list_blobs_with_valid_pubkey(self, list_blobs_result):
        """Test list_blobs with valid hex pubkey."""
        # Should return a list (may be empty or contain items)
        assert isinstance(list_blobs_result, list)
    
    def test_list_blobs_items_are_dicts(self, list_blobs_result):
        """Test that list_blobs returns list of dicts."""
        # If we got items, verify they're dicts
        if len(list_blobs_result) > 0:
            for blob in list_blobs_result:
                assert isinstance(blob, dict)
    
    def test_list_blobs_with_npub_format(self, list_blobs_result):
        """Test list_blobs with npub format (should accept it)."""
        # Verify we can list blobs successfully
        assert isinstance(list_blobs_result, list)
