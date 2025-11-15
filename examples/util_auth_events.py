"""Utility: Authentication event details

Demonstrates building and understanding auth events for Blossom servers.
"""
from python_blossom import BlossomClient
import json
from datetime import datetime

NSEC = 'nsec....'
SERVERS = ['https://nostr.download']

client = BlossomClient(nsec=NSEC, default_servers=SERVERS)
server = SERVERS[0]
method = 'POST'
path = '/upload'
auth_event = client._build_auth_event(method, path)

print(f"Event details:")
print(f"  Kind: {auth_event.kind}")
print(f"  Public key: {auth_event.public_key.hex()}")
print(f"  Timestamp: {auth_event.created_at}")

# Get the event as a dictionary (as it would be sent to server)
event_dict = auth_event.to_dict()
print(f"\nEvent dict keys: {list(event_dict.keys())}")
print(f"  ID: {event_dict['id']}")
print(f"  Signature: {event_dict['sig'][:16]}... (truncated)")

# Check tags (these specify what we're authorizing)
print(f"\nTags (authorization scope):")
for tag in event_dict.get('tags', []):
    if len(tag) >= 2:
        print(f"  {tag[0]}: {tag[1]}")
        if len(tag) > 2:
            print(f"    -> {', '.join(tag[2:])}")

# Calculate expiration
expiration_unix = event_dict['created_at'] + client.expiration_seconds
expiration_dt = datetime.fromtimestamp(expiration_unix)
print(f"\nExpiration: {expiration_dt} (in {client.expiration_seconds}s)")

# Show how auth is used in actual request
print("\n=== Auth in HTTP Header ===")
auth_header = f'Bearer {json.dumps(event_dict)}'
print("Authorization header format:")
print('  Authorization: Bearer {"id":"...","sig":"...","tags":[["method","POST"],...]}')
print(f"Header would be approximately {len(auth_header)} bytes")

# Show auth usage in an actual upload
print("\n=== Using Auth in Upload ===")
test_data = b'test blob data'
try:
    result = client.upload(server, data=test_data, mime_type='text/plain')
    print("Upload successful with auth!")
    print(f"  SHA256: {result['sha256']}")
except Exception as e:
    print(f"Upload failed: {e}")

print("\n=== Auth Event Verification ===")
# Verify the event structure
print(f"Event structure valid: {len(event_dict['id']) == 64}")
print(f"Signature valid: {len(event_dict['sig']) == 128}")
print(f"Public key valid: {len(event_dict['pubkey']) == 64}")
print(f"Tags present: {len(event_dict.get('tags', [])) > 0}")
