"""Async: upload to multiple servers concurrently

Uses AsyncBlossomClient to upload one file to every default server at the same time,
then verifies each copy, also concurrently.
"""
import asyncio

from python_blossom import AsyncBlossomClient

NSEC = 'nsec....'
SERVERS = [
    'https://blossom.band',
    'https://nostr.download',
    'https://blossom.primal.net',
]


async def main():
    async with AsyncBlossomClient(nsec=NSEC, default_servers=SERVERS) as client:
        results = await client.upload_to_all(file_path='../example_image.png')

        ok = {s: r for s, r in results.items() if 'sha256' in r}
        for server, result in results.items():
            print(f"{server}: {result.get('url') or result['error']}")

        blobs = await asyncio.gather(
            *(client.get_blob(s, r['sha256']) for s, r in ok.items()), return_exceptions=True
        )
        for server, blob in zip(ok, blobs):
            status = f"{len(blob.content)} bytes" if not isinstance(blob, Exception) else blob
            print(f"Verified {server}: {status}")

        print(f"Uploaded to {len(ok)}/{len(SERVERS)} servers")


asyncio.run(main())
