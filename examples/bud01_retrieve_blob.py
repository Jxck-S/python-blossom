"""BUD-01: Retrieve blob (GET and HEAD)

Demonstrates fetching blob content and metadata from a Blossom server.
"""
from python_blossom import BlossomClient

# Initialize client (no private key needed for read-only operations)
client = BlossomClient(nsec=None, default_servers=['https://nostr.download'])

# Known blob hash (example)
sha256 = 'f21342bad9a29aac16185b5525942f7b603cef7bd072b4b72e50710da554be74'
server = 'https://nostr.download'

# HEAD: Get blob metadata without downloading
print("=== HEAD blob (metadata) ===")
meta = client.head_blob(server, sha256)
print(f"Content-Type: {meta.get('content_type')}")
print(f"Content-Length: {meta.get('content_length')}")
print(f"Accept-Ranges: {meta.get('accept_ranges')}")

# GET: Download blob content
print("\n=== GET blob (download) ===")
blob = client.get_blob(server, sha256, mime_type='image/png')
print(f"Downloaded {len(blob.get_bytes())} bytes")
print(f"MIME type: {blob.mime_type}")

# Get as bytes
content = blob.get_bytes()
print(f"First 8 bytes (hex): {content[:8].hex()}")

# Get as file-like object
file_obj = blob.get_file_like()
print(f"File object position: {file_obj.tell()}")
file_obj.seek(0)
print(f"Read first 4 bytes: {file_obj.read(4).hex()}")
