"""Integration test for upload and download integrity validation."""
import sys
import os
import hashlib
import pytest
from python_blossom import BlossomClient
from utils.png_utils import create_minimal_png

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
def integrity_cycle_result(client, test_image):
    """Upload and download blob once to validate integrity cycle.
    
    This fixture performs one complete upload/download cycle and caches
    the results. All tests in the class reuse this result, avoiding
    duplicate API calls and reducing server strain.
    """
    # Upload
    upload_result = client.upload_blob(TEST_SERVER, data=test_image, mime_type='image/png')
    sha256_upload = upload_result['sha256']
    size_upload = upload_result['size']
    
    # Download
    blob = client.get_blob(TEST_SERVER, sha256_upload, mime_type='image/png')
    downloaded_content = blob.get_bytes()
    
    return {
        'original_data': test_image,
        'downloaded_content': downloaded_content,
        'sha256_upload': sha256_upload,
        'size_upload': size_upload,
    }


class TestUploadDownloadIntegrity:
    """Integration tests for upload/download integrity."""
    
    def test_upload_download_integrity_single_cycle(self, integrity_cycle_result):
        """Test that uploaded and downloaded content matches exactly."""
        downloaded_content = integrity_cycle_result['downloaded_content']
        original_data = integrity_cycle_result['original_data']
        
        # Verify integrity
        assert downloaded_content == original_data, "Downloaded content doesn't match uploaded"
    
    def test_upload_download_hash_integrity(self, integrity_cycle_result):
        """Test that hash of downloaded content matches upload hash."""
        sha256_upload = integrity_cycle_result['sha256_upload']
        downloaded_content = integrity_cycle_result['downloaded_content']
        
        # Compute hash of downloaded content
        sha256_download = hashlib.sha256(downloaded_content).hexdigest()
        
        # Verify hashes match
        assert sha256_upload == sha256_download, "Upload and download hashes don't match"
    
    def test_upload_download_size_integrity(self, integrity_cycle_result):
        """Test that downloaded content size matches uploaded size."""
        size_upload = integrity_cycle_result['size_upload']
        downloaded_content = integrity_cycle_result['downloaded_content']
        original_data = integrity_cycle_result['original_data']
        
        # Verify size matches
        assert size_upload == len(downloaded_content), "Upload and download sizes don't match"
        assert len(downloaded_content) == len(original_data), "Downloaded size doesn't match original"
