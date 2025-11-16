"""Tests for media_upload endpoint (BUD-05)."""
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
def media_upload_result(client, test_image):
    """Upload media once and cache result for multiple tests.
    
    This fixture uploads media once per test class and caches the result.
    All tests in the class reuse this result, avoiding duplicate API calls
    and reducing server strain.
    """
    return client.media_upload(TEST_SERVER, data=test_image, mime_type='image/png')


class TestMediaUpload:
    """Tests for media_upload endpoint (BUD-05)."""
    
    def test_media_upload_with_data(self, media_upload_result):
        """Test media_upload with binary data."""
        assert media_upload_result is not None
        assert 'sha256' in media_upload_result
    
    def test_media_upload_returns_correct_size(self, media_upload_result, test_image):
        """Test that media_upload returns correct blob size."""
        assert media_upload_result['size'] == len(test_image)
    
    def test_media_upload_returns_correct_mime_type(self, media_upload_result):
        """Test that media_upload returns correct MIME type."""
        assert media_upload_result['type'] == 'image/png'
    
    def test_media_upload_returns_valid_sha256(self, media_upload_result, test_image):
        """Test that media_upload returns valid SHA256 hash."""
        sha256 = media_upload_result['sha256']
        assert isinstance(sha256, str)
        assert len(sha256) == 64  # SHA256 is 64 hex characters
        assert all(c in '0123456789abcdef' for c in sha256)
        # Verify it matches the uploaded data
        import hashlib
        assert sha256 == hashlib.sha256(test_image).hexdigest()
    
    def test_media_upload_returns_valid_url(self, media_upload_result):
        """Test that media_upload returns valid URL."""
        assert isinstance(media_upload_result['url'], str)
        assert media_upload_result['url'].startswith('https://')
        # Just verify it's a valid HTTPS URL with hash and filename
        assert len(media_upload_result['url']) > 10  # Reasonable minimum length for a valid URL
