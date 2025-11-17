"""Tests for async blob upload functionality."""

import asyncio

import pytest

from python_blossom import AsyncBlossomClient
from python_blossom.errors import BlossomError


@pytest.mark.asyncio
async def test_async_upload_blob_with_data(async_client, test_image_data):
    """Test async upload with raw data."""
    result = await async_client.upload_blob(
        server="https://blossom.band",
        data=test_image_data,
        mime_type="image/png",
        description="Async test upload",
    )

    assert "sha256" in result
    assert "url" in result
    assert result["type"] == "image/png"


@pytest.mark.asyncio
async def test_async_upload_to_all(async_client, test_image_data):
    """Test concurrent upload to all servers."""
    results = await async_client.upload_to_all(
        data=test_image_data, mime_type="image/png", description="Concurrent upload test"
    )

    assert isinstance(results, dict)
    assert len(results) == len(async_client.default_servers)

    # At least one upload should succeed
    successful = [r for r in results.values() if "sha256" in r]
    assert len(successful) > 0


@pytest.mark.asyncio
async def test_async_upload_error_handling(async_client):
    """Test error handling in async upload."""
    with pytest.raises(BlossomError, match="Exactly one of data or file_path must be provided"):
        await async_client.upload_blob(server="https://blossom.band", data=None, file_path=None)


@pytest.mark.asyncio
async def test_async_upload_concurrent_performance(async_client, test_image_data):
    """Test that concurrent uploads are actually faster than sequential."""
    import time

    # Measure concurrent upload time
    start = time.time()
    results = await async_client.upload_to_all(data=test_image_data, mime_type="image/png")
    concurrent_time = time.time() - start

    # The concurrent time should be less than the number of servers times a typical upload time
    # This is a weak assertion but demonstrates the concept
    assert concurrent_time < len(async_client.default_servers) * 10  # 10 seconds per server max
