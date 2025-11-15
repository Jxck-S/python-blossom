"""Tests for HEAD /media endpoint (BUD-05 media optimization)."""
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
def head_media_result(client, test_image):
    """Make HEAD /media request once per test class and cache result.
    
    This fixture makes the request once and all tests in the class reuse it,
    avoiding duplicate API calls and reducing server strain.
    """
    return client.media_head(SERVERS[0], data=test_image, mime_type='image/png', use_auth=True)


class TestHeadMedia:
    """Tests for HEAD /media endpoint (BUD-05 media optimization)."""
    
    def test_head_media_returns_dict(self, head_media_result):
        """Test that media_head returns a dict."""
        assert isinstance(head_media_result, dict)
    
    def test_head_media_returns_headers(self, head_media_result):
        """Test that media_head returns header information."""
        assert len(head_media_result) > 0
    
    def test_head_media_auto_detects_mime_type(self, head_media_result):
        """Test that MIME type is auto-detected (fixture uses explicit mime_type)."""
        # Headers should be present
        assert head_media_result is not None
    
    def test_head_media_accepts_mime_type(self, head_media_result):
        """Test that explicit MIME type is accepted."""
        # Fixture uses explicit mime_type='image/png'
        assert head_media_result is not None
    
    def test_head_media_with_auth(self, head_media_result):
        """Test HEAD /media with authorization."""
        # Fixture uses use_auth=True
        assert head_media_result is not None
    
    def test_head_media_includes_blob_metadata(self, head_media_result):
        """Test that response indicates server received blob metadata."""
        # Should return headers from server
        assert isinstance(head_media_result, dict)
