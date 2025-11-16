# python-blossom

<div align="center">
  <img src="https://raw.githubusercontent.com/Jxck-S/python-blossom/main/python-blossom.png" alt="python-blossom logo" width="200" />
</div>

High-level Python client for the [Blossom protocol](https://github.com/hzrd149/blossom) (blob storage via Nostr auth).

Implements core BUDs:
- [BUD-01](https://github.com/hzrd149/blossom/blob/master/buds/01.md): Blob retrieval (GET/HEAD)
- [BUD-02](https://github.com/hzrd149/blossom/blob/master/buds/02.md): Upload, List, Delete
- [BUD-03](https://github.com/hzrd149/blossom/blob/master/buds/03.md): User Server List event generation (kind 10063)
- [BUD-04](https://github.com/hzrd149/blossom/blob/master/buds/04.md): Mirror blob
- [BUD-05](https://github.com/hzrd149/blossom/blob/master/buds/05.md): Media optimization (optional endpoints)
- [BUD-06](https://github.com/hzrd149/blossom/blob/master/buds/06.md): Upload requirements (HEAD /upload)

## Installation

Install from PyPI (coming soon):
```bash
pip install python-blossom
```

Or install locally with pipenv:
```bash
pipenv install
```

For development:
```bash
pipenv install --dev
```

## Quick Start

```python
from blossom_python import BlossomClient

nsec = 'nsec....'  # Your Nostr private key (nsec)
servers = [
    'https://blossom.band',
    'https://nostr.download',
    'https://blossom.primal.net'
]

client = BlossomClient(nsec=nsec, default_servers=servers)

# Upload blob data
result = client.upload_blob(servers[0], data=b'blob data', mime_type='image/png')
sha256 = result['sha256']
print(f"Uploaded: {result['url']}")

# Get blob
blob = client.get_blob(servers[0], sha256, mime_type='image/png')
downloaded_data = blob.get_bytes()
print(f"Downloaded: {len(downloaded_data)} bytes")

# HEAD request to check blob metadata
meta = client.head_upload_requirements(servers[0], data=b'blob data', mime_type='image/png')
print(f"Server supports: {meta}")

# List user's blobs
blobs = client.list_blobs(servers[0], pubkey=client.pubkey_hex, use_auth=True)
print(f"Found {len(blobs)} blobs")

# Delete blob
client.delete_blob(servers[0], sha256, description='Cleanup')

# Mirror blob to another server
mirror_result = client.mirror_blob(servers[1], servers[0], sha256)
print(f"Mirrored to: {mirror_result['url']}")

# Generate User Server List event (kind 10063, BUD-03)
event = client.generate_server_list_event(servers=servers)
print(f"Event ID: {event['id']}")

# Publish server list event to relays
event_id = client.publish_server_list_event(relays=['wss://relay.damus.io'])
print(f"Published: {event_id}")
```

## Publishing Media to Nostr with Redundancy

Here's how to upload a photo to multiple Blossom servers and publish it to Nostr with automatic failover:

```python
from python_blossom import BlossomClient
from pynostr.event import Event
from pynostr.key import PrivateKey
import json

nsec = 'nsec....'  # Your Nostr private key
servers = [
    'https://blossom.band',
    'https://nostr.download',
    'https://blossom.primal.net'
]

client = BlossomClient(nsec=nsec, default_servers=servers)

# Step 1: Publish your server list to Nostr (do this once or when you change servers)
# This advertises all your Blossom servers to the Nostr network
# Clients use this to find backup servers if the primary one is down
relays = ['wss://relay.damus.io', 'wss://relay.snort.social']
client.publish_server_list_event(relays=relays, servers=servers)
print(f"✓ Published server list to relays")

# Step 2: Upload photo to ALL servers for redundancy
with open('photo.jpg', 'rb') as f:
    photo_data = f.read()

upload_results = client.upload_to_all(
    data=photo_data,
    mime_type='image/jpeg',
    description='My vacation photo'
)

# Get the primary URL (first successful upload)
primary_url = None
for server, result in upload_results.items():
    if 'url' in result and not 'error' in result:
        primary_url = result['url']
        sha256 = result['sha256']
        print(f"✓ Uploaded to {server}: {primary_url}")
        break

# Step 3: Create Nostr note with media tag pointing to primary URL
# If the primary server goes down, clients will use your server list event 
# (kind 10063) to find the photo on your other servers
private_key = PrivateKey.from_nsec(nsec)
event = Event(
    content="Check out this photo! 📸",
    kind=1  # Text note
)

# Add image tag with primary URL
# Format: ["image", url, "m" MIME type, "alt" description, "x" sha256]
event.add_tag("image", primary_url, "m", "image/jpeg", "alt", "My vacation photo", "x", sha256)

event.sign(private_key.hex())

# Publish to relays using pynostr
from pynostr.relay_manager import RelayManager

relay_manager = RelayManager(timeout=5)
for relay in relays:
    relay_manager.add_relay(relay)

relay_manager.publish_event(event)
relay_manager.run_sync()
relay_manager.close_all_relay_connections()


```

## API Methods

### Upload & Download

**`upload_blob(server, data=None, file_path=None, mime_type=None, description=None, use_auth=False)`**
- Upload blob data (raw bytes or file)
- Auto-detects MIME type if not specified
- Returns blob descriptor with `sha256`, `url`, `size`, `type`

**`get_blob(server, sha256, mime_type=None, use_auth=False)`**
- Download blob by SHA256 hash
- Returns `Blob` object with `content`, `sha256`, `mime_type` properties
- Call `blob.get_bytes()` or `blob.save(file_path)` to access data

**`head_upload_requirements(server, data=None, file_path=None, mime_type=None, use_auth=False)`**
- Check server upload requirements before uploading
- Returns headers: `content_type`, `content_length`, `accept_ranges`

### Media (BUD-05)

**`media_upload(server, data=None, file_path=None, mime_type=None, description=None, use_auth=False)`**
- Upload blob with media optimization
- Returns blob descriptor

**`media_head(server, data=None, file_path=None, mime_type=None, use_auth=False)`**
- Check media upload requirements
- Returns headers

### Blob Management

**`upload_blob(server, data=None, file_path=None, mime_type=None, description=None, use_auth=True)`**
- Upload blob data (raw bytes or file)
- Auto-detects MIME type if not specified
- Returns blob descriptor with `sha256`, `url`, `size`, `type`

**`upload_to_all(data=None, file_path=None, mime_type=None, description=None, use_auth=True)`**
- Upload blob to all default servers in parallel
- Uses servers configured during client initialization
- Returns dict mapping server URLs to results/errors

**`list_blobs(server, pubkey=None, cursor=None, limit=None, use_auth=False)`**
- List blobs for a public key (accepts npub or hex format)
- Returns list of blob descriptors
- Requires `use_auth=True` for private server listings

**`delete_blob(server, sha256, description=None)`**
- Delete blob from server
- Requires authorization
- Returns confirmation

**`mirror_blob(server, source_url, sha256, description=None)`**
- Mirror blob from one server to another
- Returns blob descriptor on destination server

### Head Blob

**`head_blob(server, sha256, use_auth=False)`**
- Get blob metadata without downloading content
- Returns headers: `content_type`, `content_length`, `accept_ranges`

### Server Management (BUD-03)

Server list events (Nostr kind 10063) are like "advertising" - they publicly announce which Blossom servers a user uploads media to. When you publish a server list event to the Nostr network, anyone can look up your public key and discover which servers you use. NOSTR clients use this to know where to look for published media in a NOSTR note. 


**`generate_server_list_event(servers=None)`**
- Generate a Nostr server list event (kind 10063, BUD-03)
- Contains tags with your Blossom server URLs
- Automatically signed with your private key
- Returns Nostr event dict ready for publishing

**`publish_server_list_event(relays, servers=None)`**
- Publish your server list event to Nostr relays
- Advertises your Blossom servers publicly by your public key
- `relays`: List of relay URLs (wss://) where the event will be published
- `servers`: Optional list of server URLs (defaults to configured servers on the client)
- Returns event ID of the published event

**`fetch_server_list(relays, pubkey=None, timeout=2.0)`**
- Look up which Blossom servers a user has advertised
- Query Nostr relays for a user's server list event
- `relays`: List of relay URLs to query
- `pubkey`: Optional public key in any format (npub or hex) to look up (defaults to your own)
- Returns list of server URLs that user has advertised

## Authorization

Methods with `use_auth=True` parameter automatically generate NIP-98 authorization events:
- kind 24242
- Tags: `t=<verb>`, `expiration`, `x=<hash>` (when applicable)
- Base64 encoded in `Authorization: Nostr <base64>` header
- Auto-signed with your private key

## Error Handling

Raises `BlossomError` or specific subclasses on errors:
- `InvalidAuthorizationEvent`: 401 auth failure
- `BlobNotFound`: 404 blob not found
- `TooManyRequests`: 429 rate limit
- `BlossomError`: Other HTTP errors

```python
from blossom_python.errors import BlobNotFound, TooManyRequests

try:
    blob = client.get_blob(server, sha256)
except BlobNotFound:
    print("Blob not found")
except TooManyRequests:
    print("Rate limited - try again later")
```

## TODO / Unsupported Endpoints

The following Blossom endpoints are not yet implemented:

- **BUD-09**: PUT `/report` - Report abuse/misinformation (planned for future release)

## License

Unlicense / Public Domain (matches upstream Blossom spec repository).
