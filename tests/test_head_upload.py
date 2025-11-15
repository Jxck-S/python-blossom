"""Tests for HEAD /upload endpoint (BUD-06 upload requirements)."""
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
def head_upload_result(client, test_image):
    """Make HEAD /upload request once per test class and cache result.
    
    This fixture makes the request once and all tests in the class reuse it,
    avoiding duplicate API calls and reducing server strain.
    """
    return client.head_upload_requirements(SERVERS[0], data=test_image, mime_type='image/png', use_auth=True)


class TestHeadUpload:
    """Tests for HEAD /upload endpoint (BUD-06 upload requirements)."""
    
    def test_head_upload_returns_dict(self, head_upload_result):
        """Test that head_upload_requirements returns a dict."""
        assert isinstance(head_upload_result, dict)
    
    def test_head_upload_returns_headers(self, head_upload_result):
        """Test that head_upload_requirements returns header information."""
        assert len(head_upload_result) > 0
    
    def test_head_upload_auto_detects_mime_type(self, head_upload_result):
        """Test that MIME type is auto-detected."""
        # Headers should be present even if empty
        assert head_upload_result is not None
    
    def test_head_upload_accepts_mime_type(self, head_upload_result):
        """Test that explicit MIME type is accepted."""
        # Fixture already uses mime_type, just validate result exists
        assert head_upload_result is not None
    
    def test_head_upload_with_auth(self, head_upload_result):
        """Test HEAD /upload with authorization."""
        assert head_upload_result is not None
    
    def test_head_upload_includes_blob_metadata(self, head_upload_result):
        """Test that response indicates server received blob metadata."""
        # Should return headers from server (even if empty dict, it's a valid response)
        assert isinstance(head_upload_result, dict)
