"""BUD-02: Upload, list, and delete blobs

Demonstrates uploading blob content, listing user's blobs, and deleting blobs.
"""
from python_blossom import BlossomClient

# Private key required for write operations (upload, delete)
NSEC = 'nsec....'
# Public key in npub format (list_blobs automatically converts to hex)
PUBKEY = 'npub1ylccvgzdlan2vyh4snx9u8kjpk8580tm2ecxmvv72mzem3xevt9qw0z7ks'
SERVERS = ['https://nostr.download']

client = BlossomClient(nsec=NSEC, default_servers=SERVERS)
server = SERVERS[0]

print("=== PUT /upload (upload blob) ===")
with open('../example_image.png', 'rb') as f:
    image_data = f.read()
result = client.upload(server, data=image_data, mime_type='image/png',
                       description='Example BUD-02 upload')
print("Upload successful!")
print(f"SHA256: {result['sha256']}")
print(f"URL: {result['url']}")

sha256 = result['sha256']

# === LIST ===
print("\n=== GET /list/<pubkey> (list user's blobs) ===")
# Can list any pubkey's blobs without being that user
# list_blobs() automatically converts npub to hex
blobs = client.list_blobs(server, pubkey_hex=PUBKEY)
print(f"User {PUBKEY[:20]}... has {len(blobs)} blobs on server")
if blobs:
    latest = blobs[0]  # Most recent
    print(f"Latest blob: {latest['sha256'][:16]}... ({latest.get('size', 'N/A')} bytes)")

# === DELETE ===
print("\n=== DELETE /<sha256> (delete blob) ===")
delete_result = client.delete(server, sha256)
print(f"Delete result: {delete_result}")
print(f"Blob {sha256[:16]}... deleted")
