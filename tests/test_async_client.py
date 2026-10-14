"""Live tests for AsyncBlossomClient (require credentials, see conftest.py)."""
import sys
import os
import pytest
from python_blossom import AsyncBlossomClient

sys.path.insert(0, os.path.dirname(__file__))
from conftest import NSEC, SERVERS, NON_OPTIMIZING_SERVERS

TEST_SERVER = NON_OPTIMIZING_SERVERS[0] if NON_OPTIMIZING_SERVERS else SERVERS[0]


async def test_async_upload_get_delete_roundtrip(test_image):
    async with AsyncBlossomClient(nsec=NSEC, default_servers=SERVERS) as client:
        result = await client.upload_blob(TEST_SERVER, data=test_image, mime_type='image/png')
        assert 'sha256' in result and 'url' in result

        blob = await client.get_blob(TEST_SERVER, result['sha256'])
        assert blob.content == test_image

        await client.delete_blob(TEST_SERVER, result['sha256'])


async def test_async_upload_to_all(test_image):
    async with AsyncBlossomClient(nsec=NSEC, default_servers=SERVERS) as client:
        results = await client.upload_to_all(data=test_image, mime_type='image/png')

    assert set(results) == set(SERVERS)
    assert any('sha256' in r for r in results.values()), results
