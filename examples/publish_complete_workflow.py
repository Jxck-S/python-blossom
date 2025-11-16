"""BUD-03: Publish media to Nostr with Blossom redundancy

Demonstrates how to:
1. Publish your Blossom server list to Nostr (one-time setup)
2. Upload media to multiple Blossom servers for redundancy
3. Post to Nostr with automatic failover

When the primary server is down or media is missing, Nostr clients will:
- Use your server list event to find backup servers
- Fetch the same content (via SHA256) from other servers
- Ensure media stays accessible even if one server fails
"""
from python_blossom import BlossomClient
from pynostr.event import Event
from pynostr.key import PrivateKey

# Configuration
nsec = 'nsec....'  # Your Nostr private key (nsec)
servers = [
    'https://blossom.band',
    'https://nostr.download',
    'https://blossom.primal.net'
]
relays = ['wss://relay.damus.io', 'wss://relay.snort.social']

client = BlossomClient(nsec=nsec, default_servers=servers)

print("=" * 60)
print("BLOSSOM + NOSTR PUBLISHING EXAMPLE")
print("=" * 60)

# ============================================================================
# STEP 1: Publish your server list to Nostr (do this once or when you change servers)
# ============================================================================
print("\n[STEP 1] Publishing server list to Nostr...")
print("This advertises all your Blossom servers to the Nostr network.")
print("Clients use this to find backup servers if the primary one is down or media is taken down.\n")

try:
    event_id = client.publish_server_list_event(relays=relays, servers=servers)
    print(f"✓ Published server list")
    print(f"  Event ID: {event_id}")
    print(f"  Relays: {', '.join(relays)}")
    print(f"  Your servers: {', '.join(servers)}\n")
except Exception as e:
    print(f"✗ Error publishing server list: {e}\n")

# ============================================================================
# STEP 2: Upload photo to ALL servers for redundancy
# ============================================================================
print("[STEP 2] Uploading media to all Blossom servers...")
print("The same content will be stored on multiple servers.\n")

# For this example, create a simple test image
# In real use, you'd load an actual photo: open('photo.jpg', 'rb').read()
photo_data = b'fake photo data for demonstration'

try:
    upload_results = client.upload_to_all(
        data=photo_data,
        mime_type='image/jpeg',
        description='My vacation photo'
    )
    
    # Get the primary URL (first successful upload)
    primary_url = None
    sha256 = None
    successful_uploads = 0
    
    for server, result in upload_results.items():
        if 'url' in result and 'error' not in result:
            successful_uploads += 1
            if not primary_url:
                primary_url = result['url']
                sha256 = result['sha256']
            print(f"✓ Uploaded to {server}")
            print(f"  URL: {result['url']}")
            print(f"  SHA256: {result['sha256']}\n")
        else:
            error_msg = result.get('error', 'Unknown error')
            print(f"✗ Failed to upload to {server}: {error_msg}\n")
    
    if not primary_url:
        print("✗ No successful uploads!\n")
        exit(1)
        
except Exception as e:
    print(f"✗ Error during upload: {e}\n")
    exit(1)

# ============================================================================
# STEP 3: Create Nostr note with media tag pointing to primary URL
# ============================================================================
print("[STEP 3] Creating and publishing Nostr note with media...\n")

try:
    private_key = PrivateKey.from_nsec(nsec)
    event = Event(
        content="Check out this photo! 📸",
        kind=1  # Text note
    )
    
    # Add image tag with primary URL and SHA256
    # Format: ["image", url, "m" MIME type, "alt" description, "x" sha256]
    event.add_tag("image", primary_url, "m", "image/jpeg", "alt", "My vacation photo", "x", sha256)
    
    event.sign(private_key.hex())
    
    print(f"✓ Created Nostr event")
    print(f"  Event ID: {event.id}")
    print(f"  Primary URL: {primary_url}")
    print(f"  SHA256: {sha256}")
    print(f"  Servers with backup: {successful_uploads}\n")
    
    # Publish to relays using pynostr
    from pynostr.relay_manager import RelayManager
    
    print("Publishing to relays...")
    relay_manager = RelayManager(timeout=5)
    for relay in relays:
        relay_manager.add_relay(relay)
    
    relay_manager.publish_event(event)
    relay_manager.run_sync()
    relay_manager.close_all_relay_connections()
    
    print("✓ Published to relays\n")
    
except Exception as e:
    print(f"✗ Error publishing: {e}\n")
    exit(1)

# ============================================================================
# HOW THIS WORKS - CLIENT SIDE FAILOVER
# ============================================================================
# 1. User's client fetches your note with the image tag
# 2. Client tries to load image from primary_url
# 3. If primary server is down or media is missing:
#    - Client queries relays for your server list event (kind 10063)
#    - Client finds all your Blossom servers
#    - Client tries to fetch the same sha256 from backup servers
# 4. Photo loads successfully from a backup server!
# 5. If all servers are down/missing, graceful degradation (broken image)
#
# BENEFITS:
# ✓ Redundancy - Photo survives individual server downtime
# ✓ One-time setup - Publish server list once, use for all uploads
# ✓ Simple Nostr - Note contains only ONE URL (clean, not cluttered)
# ✓ Automatic failover - Clients handle discovery automatically
# ✓ Same content everywhere - SHA256 identical across all servers
# ✓ Distributed bandwidth - Traffic spread across multiple servers
