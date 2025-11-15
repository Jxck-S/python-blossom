"""BUD-05: Media optimization endpoints (optional)

Demonstrates media-specific upload and HEAD endpoints for optimized serving.
"""
from python_blossom import BlossomClient

NSEC = 'nsec....'
SERVERS = ['https://nostr.download']

client = BlossomClient(nsec=NSEC, default_servers=SERVERS)
server = SERVERS[0]

# Check media endpoint capabilities
print("=== HEAD /media (check media endpoint) ===")
try:
    media_info = client.media_head(server)
    print("Media endpoint available")
    print(f"Headers: {media_info}")
except Exception as e:
    print(f"Media endpoint not available: {e}")

# Upload using media endpoint (if supported)
print("\n=== PUT /media (media upload) ===")
with open('../example_image.png', 'rb') as f:
    image_data = f.read()

try:
    media_result = client.media_upload(server, data=image_data, mime_type='image/png',
                                      description='Media endpoint upload')
    print("Media upload successful!")
    print(f"URL: {media_result.get('url', 'N/A')}")
    print(f"SHA256: {media_result['sha256']}")
except Exception as e:
    print(f"Media upload failed: {e}")
    print("Server may not support media optimization endpoint")
