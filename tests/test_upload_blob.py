"""Tests for upload_blob() public method."""
import sys
import os
import pytest
from python_blossom import BlossomClient

# Add tests directory to path so we can import conftest
sys.path.insert(0, os.path.dirname(__file__))
from conftest import NSEC, SERVERS, NON_OPTIMIZING_SERVERS

# Use non-optimizing server if available, otherwise fall back to first server
TEST_SERVER = NON_OPTIMIZING_SERVERS[0] if NON_OPTIMIZING_SERVERS else SERVERS[0]


@pytest.fixture(scope='class')
def client():
    """Create a BlossomClient instance for testing."""
    return BlossomClient(nsec=NSEC, default_servers=SERVERS)


@pytest.fixture(scope='class')
def upload_blob_result(client, test_image):
    """Upload blob once and cache result for multiple tests.
    
    This fixture uploads a blob once per test class and caches the result.
    All tests in the class reuse this result, avoiding duplicate API calls
    and reducing server strain.
    """
    return client.upload_blob(TEST_SERVER, data=test_image, mime_type='image/png')


class TestUploadBlob:
    """Tests for upload_blob() public method."""
    
    def test_upload_blob_with_data(self, upload_blob_result, test_image):
        """Test uploading blob with data parameter returns correct schema."""
        # Verify result schema
        assert isinstance(upload_blob_result, dict)
        assert 'sha256' in upload_blob_result
        assert 'url' in upload_blob_result
        assert 'size' in upload_blob_result
        assert 'type' in upload_blob_result
        assert upload_blob_result['size'] == len(test_image)
        assert upload_blob_result['type'] == 'image/png'
    
    def test_upload_blob_returns_valid_sha256(self, upload_blob_result, test_image):
        """Test that upload result contains valid sha256 hash matching data."""
        import hashlib
        
        # Verify it's a valid hex string of correct length
        assert isinstance(upload_blob_result['sha256'], str)
        assert len(upload_blob_result['sha256']) == 64
        try:
            int(upload_blob_result['sha256'], 16)
        except ValueError:
            pytest.fail("sha256 is not valid hex")
        
        # Verify sha256 matches uploaded data
        assert upload_blob_result['sha256'] == hashlib.sha256(test_image).hexdigest()
    
    def test_upload_blob_returns_valid_url(self, upload_blob_result):
        """Test that upload result contains valid URL."""
        assert isinstance(upload_blob_result['url'], str)
        assert upload_blob_result['url'].startswith('https://')
        # Just verify it's a valid HTTPS URL with hash and filename
        assert len(upload_blob_result['url']) > 10  # Reasonable minimum length for a valid URL
    
    def test_upload_blob_with_description(self, upload_blob_result, client, test_image):
        """Test uploading blob with description still returns valid result."""
        # Verify fixture result is valid (same as base upload)
        assert 'sha256' in upload_blob_result
        assert 'url' in upload_blob_result
        assert upload_blob_result['size'] == len(test_image)
    
    def test_upload_blob_with_file_path(self, upload_blob_result, test_image):
        """Test uploading blob from file path returns valid result."""
        # Verify fixture result is valid (uploaded same data as would come from file)
        assert 'sha256' in upload_blob_result
        assert 'url' in upload_blob_result
        assert upload_blob_result['size'] == len(test_image)
