"""Tests for delete_blob() public method."""
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
def delete_blob_result(client, test_image):
    """Upload a blob once and delete it, reusing result across all tests.
    
    This fixture uploads blob data once per test class, deletes it, and caches
    the deletion result. All tests in the class reuse this result, avoiding
    duplicate upload/delete operations and reducing server strain.
    """
    # Upload blob
    upload_result = client.upload_blob(SERVERS[0], data=test_image, mime_type='image/png')
    sha256 = upload_result['sha256']
    
    # Delete blob and return result
    deletion_result = client.delete_blob(SERVERS[0], sha256)
    return deletion_result


class TestDeleteBlob:
    """Tests for delete_blob() public method."""
    
    def test_delete_blob_succeeds(self, delete_blob_result):
        """Test that delete_blob() successfully deletes uploaded blob."""
        assert delete_blob_result is not None
