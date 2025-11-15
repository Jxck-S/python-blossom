"""Utility: Upload to multiple servers

Demonstrates uploading a blob to multiple Blossom servers for redundancy.
"""
from python_blossom import BlossomClient

NSEC = 'nsec....'
SERVERS = [
    'https://nostr.download',
    'https://blossom.primal.net',
    # Add more servers as needed
]

client = BlossomClient(nsec=NSEC, default_servers=SERVERS)

# Create test data
print("Loading example image...")
with open('../example_image.png', 'rb') as f:
    image_data = f.read()

# Upload to all servers
print(f"\n=== Uploading to {len(SERVERS)} servers ===")
results = {}

for server in SERVERS:
    print(f"\nUploading to {server}...", end=' ')
    try:
        result = client.upload(server, data=image_data, mime_type='image/png',
                              description='Multi-server upload test')
        results[server] = {
            'status': 'success',
            'sha256': result['sha256'],
            'url': result.get('url', 'N/A')
        }
        print("✓ Success")
        print(f"  SHA256: {result['sha256']}")
    except Exception as e:
        results[server] = {
            'status': 'failed',
            'error': str(e)
        }
        print(f"✗ Failed: {e}")

# Verify upload on successful servers
print("\n=== Verification ===")
successful_servers = [s for s, r in results.items() if r['status'] == 'success']
print(f"Successfully uploaded to {len(successful_servers)}/{len(SERVERS)} servers")

for server, result in results.items():
    if result['status'] == 'success':
        print(f"\n{server}:")
        print(f"  SHA256: {result['sha256']}")
        try:
            # Verify by downloading from this server
            blob = client.download(server, result['sha256'])
            print(f"  Verified: {len(blob.content)} bytes")
        except Exception as e:
            print(f"  Verification failed: {e}")
    else:
        print(f"\n{server}: {result['error']}")

print("\n=== Summary ===")
print(f"Upload rate: {len(successful_servers)}/{len(SERVERS)}")
if successful_servers:
    sha256 = results[successful_servers[0]]['sha256']
    print(f"Blob hash: {sha256}")
    print(f"Available on: {', '.join(successful_servers)}")
