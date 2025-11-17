"""Async example: Concurrent upload to multiple servers

Demonstrates the key advantage of AsyncBlossomClient - uploading to multiple
servers concurrently instead of sequentially, significantly improving performance.
"""
import asyncio
import time
from python_blossom import AsyncBlossomClient

# Configuration
NSEC = 'nsec....'  # Your Nostr private key
SERVERS = [
    'https://blossom.band',
    'https://nostr.download',
    'https://blossom.primal.net'
]


async def main():
    # Initialize async client
    client = AsyncBlossomClient(nsec=NSEC, default_servers=SERVERS)
    
    # Create test data
    test_data = b'Example blob data for concurrent upload test'
    
    print(f"=== Async Concurrent Upload to {len(SERVERS)} servers ===\n")
    
    # Upload to all servers concurrently
    start_time = time.time()
    results = await client.upload_to_all(
        data=test_data,
        mime_type='text/plain',
        description='Concurrent upload test',
        use_auth=True
    )
    elapsed = time.time() - start_time
    
    # Display results
    print(f"\n✓ Completed in {elapsed:.2f} seconds\n")
    
    successful = []
    failed = []
    
    for server, result in results.items():
        if 'error' in result:
            failed.append(server)
            print(f"✗ {server}")
            print(f"  Error: {result['error']}\n")
        else:
            successful.append(server)
            print(f"✓ {server}")
            print(f"  SHA256: {result.get('sha256', 'N/A')}")
            print(f"  URL: {result.get('url', 'N/A')}\n")
    
    # Summary
    print("=== Summary ===")
    print(f"Success rate: {len(successful)}/{len(SERVERS)}")
    print(f"Total time: {elapsed:.2f} seconds")
    
    if successful:
        # Calculate average time per server (if sequential)
        avg_time = elapsed / len(SERVERS)
        print(f"Average time per server (if sequential): ~{avg_time:.2f}s")
        print(f"Time saved by concurrent uploads: ~{(avg_time * len(SERVERS) - elapsed):.2f}s")


async def compare_with_sequential():
    """Compare concurrent vs sequential upload performance."""
    from python_blossom import BlossomClient
    
    client_sync = BlossomClient(nsec=NSEC, default_servers=SERVERS)
    client_async = AsyncBlossomClient(nsec=NSEC, default_servers=SERVERS)
    
    test_data = b'Performance comparison test data'
    
    print("\n=== Performance Comparison ===\n")
    
    # Sequential upload (sync client)
    print("1. Sequential uploads (synchronous)...")
    start = time.time()
    sync_results = client_sync.upload_to_all(
        data=test_data,
        mime_type='text/plain',
        use_auth=True
    )
    sync_time = time.time() - start
    print(f"   Completed in {sync_time:.2f} seconds")
    
    # Concurrent upload (async client)
    print("\n2. Concurrent uploads (asynchronous)...")
    start = time.time()
    async_results = await client_async.upload_to_all(
        data=test_data,
        mime_type='text/plain',
        use_auth=True
    )
    async_time = time.time() - start
    print(f"   Completed in {async_time:.2f} seconds")
    
    # Results
    speedup = sync_time / async_time if async_time > 0 else 0
    print(f"\n📊 Speedup: {speedup:.1f}x faster with async")
    print(f"   Time saved: {sync_time - async_time:.2f} seconds")


if __name__ == '__main__':
    # Run the main async example
    asyncio.run(main())
    
    # Uncomment to run performance comparison
    # asyncio.run(compare_with_sequential())
