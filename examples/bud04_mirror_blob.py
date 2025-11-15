"""BUD-04: Mirror blob to another server

Demonstrates mirroring a blob from one Blossom server to another.
"""
from python_blossom import BlossomClient

NSEC = 'nsec....'
SERVERS = ['https://nostr.download']  # Primary server

client = BlossomClient(nsec=NSEC, default_servers=SERVERS)

# First, upload a blob to the primary server
print("=== Upload blob to primary server ===")
with open('../example_image.png', 'rb') as f:
    image_data = f.read()
upload_result = client.upload(SERVERS[0], data=image_data, mime_type='image/png',
                             description='Blob to mirror')
sha256 = upload_result['sha256']
source_url = upload_result.get('url', f"{SERVERS[0]}/{sha256}")
print(f"Uploaded: {source_url}")

# Mirror to another server (if available)
print("\n=== Mirror blob to another server ===")
secondary_server = 'https://blossom.band'  # Target server for mirroring

try:
    mirror_result = client.mirror_blob(secondary_server, source_url, sha256,
                                      description='Mirrored blob from primary')
    print(f"Mirror successful!")
    print(f"Mirrored URL: {mirror_result.get('url', 'N/A')}")
    print(f"SHA256 preserved: {mirror_result['sha256'] == sha256}")
except Exception as e:
    print(f"Mirror failed: {e}")
    print(f"Note: Secondary server may not be reachable or mirror endpoint not supported")
