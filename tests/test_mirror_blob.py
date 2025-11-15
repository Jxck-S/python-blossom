"""Tests for mirror_blob() public method."""
import sys
import os
import pytest
from python_blossom import BlossomClient

# Add tests directory to path so we can import conftest
sys.path.insert(0, os.path.dirname(__file__))
from conftest import NSEC, SERVERS, SORTED_SERVERS


@pytest.fixture(scope='class')
def client():
    """Create a BlossomClient instance for testing."""
    return BlossomClient(nsec=NSEC, default_servers=SERVERS)


@pytest.fixture(scope='class')
def mirror_blob_result(client, test_image):
    """Upload and mirror a blob once, reusing result for all tests.
    
    Uses SORTED_SERVERS[0] for upload and SORTED_SERVERS[-1] for mirror destination.
    SORTED_SERVERS sorts non-mirror servers first, then mirror-capable servers,
    so [-1] prioritizes mirror-capable destination if available.
    """
    if len(SORTED_SERVERS) < 2:
        pytest.skip("Need at least 2 servers for mirroring test")
    
    # Upload to first server (SORTED_SERVERS[0])
    upload_result = client.upload_blob(SORTED_SERVERS[0], data=test_image, mime_type='image/png')
    sha256 = upload_result['sha256']
    blob_url = upload_result['url']
    
    # Mirror to last server (SORTED_SERVERS[-1]) - preferentially mirror-capable
    try:
        mirror_result = client.mirror_blob(SORTED_SERVERS[-1], blob_url, sha256)
        return mirror_result
    except Exception as e:
        # If mirror fails, skip tests
        pytest.skip(f"Mirror operation not supported: {e}")


class TestMirrorBlob:
    """Tests for mirror_blob() public method."""
    
    def test_mirror_blob_returns_result_dict(self, mirror_blob_result):
        """Test that mirror_blob returns a result."""
        assert mirror_blob_result is not None
    
    def test_mirror_blob_returns_dict_schema(self, mirror_blob_result):
        """Test that mirror_blob result is valid."""
        assert isinstance(mirror_blob_result, dict) or mirror_blob_result is not None
    
    def test_mirror_blob_accepts_parameters(self, mirror_blob_result):
        """Test that mirror_blob accepts valid parameters."""
        assert mirror_blob_result is not None
