"""Tests for get_blob() public method."""
import sys
import os
import pytest
from python_blossom import BlossomClient, Blob

# Add tests directory to path so we can import conftest
sys.path.insert(0, os.path.dirname(__file__))
from conftest import NSEC, SERVERS


@pytest.fixture(scope='class')
def client():
    """Create a BlossomClient instance for testing."""
    return BlossomClient(nsec=NSEC, default_servers=SERVERS)


@pytest.fixture(scope='class')
def get_blob_result(client, test_image):
    """Upload a blob once and get it, reusing result across all tests.
    
    This fixture uploads blob data once per test class, retrieves it, and caches
    the blob result. All tests in the class reuse this result, avoiding
    duplicate upload/download operations and reducing server strain.
    """
    # Upload blob
    upload_result = client.upload_blob(SERVERS[0], data=test_image, mime_type='image/png')
    sha256 = upload_result['sha256']
    
    # Get blob and return result
    blob = client.get_blob(SERVERS[0], sha256, mime_type='image/png')
    return blob


class TestGetBlob:
    """Tests for get_blob() public method."""
    
    def test_get_blob_returns_blob_object(self, get_blob_result):
        """Test that get_blob returns a Blob object."""
        assert isinstance(get_blob_result, Blob)
    
    def test_get_blob_returns_correct_sha256(self, get_blob_result, test_image):
        """Test that retrieved Blob has correct sha256."""
        import hashlib
        expected_sha256 = hashlib.sha256(test_image).hexdigest()
        
        assert get_blob_result.sha256 == expected_sha256
    
    def test_get_blob_returns_correct_mime_type(self, get_blob_result):
        """Test that retrieved Blob has correct mime type."""
        assert get_blob_result.mime_type == 'image/png'
    
    def test_get_blob_has_content(self, get_blob_result):
        """Test that retrieved Blob has content."""
        assert get_blob_result.content is not None
        assert len(get_blob_result.content) > 0
    
    def test_get_blob_get_bytes_method(self, get_blob_result):
        """Test that Blob.get_bytes() method works."""
        assert isinstance(get_blob_result.get_bytes(), bytes)
        assert len(get_blob_result.get_bytes()) > 0
    
    def test_get_blob_has_save_method(self, get_blob_result):
        """Test that Blob has save method."""
        assert hasattr(get_blob_result, 'save')
        assert callable(get_blob_result.save)
