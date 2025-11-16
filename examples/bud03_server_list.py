"""BUD-03: User server list event (kind 10063)

Demonstrates generating and fetching Nostr server list events for discovering
which Blossom servers a user prefers.
"""
from python_blossom import BlossomClient

# Generate server list event (requires private key)
print("=== Generate server list event (BUD-03) ===")
NSEC = 'nsec....'
servers = [
    'https://blossom.primal.net',
    'https://blossom.band',
    'https://nostr.download'
]

client = BlossomClient(nsec=NSEC, default_servers=servers)
event = client.generate_server_list_event()

print(f"Event kind: {event['kind']} (10063)")
print(f"Event ID: {event['id']}")
print(f"Signed by: {event['pubkey'][:16]}...")
print(f"Servers in list:")
for tag in event['tags']:
    if tag[0] == 'server':
        print(f"  - {tag[1]}")

# Fetch server list from relays
print("\n=== Fetch server list from relays ===")
RELAYS = [
    'wss://relay.damus.io',
    'wss://nos.lol'
]
TARGET_PUBKEY = event['pubkey']

try:
    fetched_servers = client.fetch_server_list(relays=RELAYS, pubkey=TARGET_PUBKEY, timeout=3.0)
    if fetched_servers:
        print(f"Fetched {len(fetched_servers)} servers for {TARGET_PUBKEY[:16]}...")
        for srv in fetched_servers:
            print(f"  - {srv}")
    else:
        print("No server list found on relays (may not be published yet)")
except Exception as e:
    print(f"Relay fetch failed: {e}")
