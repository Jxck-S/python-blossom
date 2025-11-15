"""Utility: Error handling patterns

Demonstrates common error scenarios and how to handle them gracefully.
"""
from python_blossom import BlossomClient, BlossomError

NSEC = 'nsec....'
SERVERS = ['https://nostr.download', 'https://invalid.server.local']

client = BlossomClient(nsec=NSEC, default_servers=SERVERS)

print("=== Error Scenario 1: Invalid Server URL ===")
invalid_server = 'https://invalid.server.local'
try:
    result = client.head_upload_requirements(invalid_server)
except BlossomError as e:
    print(f"Blossom error: {e}")
except Exception as e:
    print(f"Connection error: {type(e).__name__}: {e}")

print("\n=== Error Scenario 2: Blob Not Found ===")
server = SERVERS[0]
fake_sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
try:
    blob = client.download(server, fake_sha256)
except BlossomError as e:
    print(f"Blossom error (blob not found): {e}")
except Exception as e:
    print(f"Other error: {type(e).__name__}: {e}")

print("\n=== Error Scenario 3: Missing Private Key ===")
anon_client = BlossomClient(default_servers=SERVERS)
try:
    # This requires authentication (private key)
    result = anon_client.upload(server, data=b'test', mime_type='text/plain')
except BlossomError as e:
    print(f"Expected error (no private key): {e}")

print("\n=== Error Scenario 4: Invalid MIME Type ===")
try:
    result = client.upload(server, data=b'test', mime_type='not/valid-mime')
    print(f"Upload may have succeeded, server accepted it")
except Exception as e:
    print(f"Error: {type(e).__name__}: {e}")

print("\n=== Error Scenario 5: Graceful Fallback to Multiple Servers ===")
data = b'test blob'
for srv in SERVERS:
    try:
        print(f"Trying {srv}...", end=' ')
        result = client.upload(srv, data=data, mime_type='text/plain')
        print(f"Success! Hash: {result['sha256']}")
        break
    except Exception as e:
        print(f"Failed ({type(e).__name__})")
else:
    print("All servers failed!")

print("\n=== Error Handling Best Practices ===")
print("1. Catch BlossomError for Blossom-specific issues")
print("2. Catch Connection errors (requests.ConnectionError, etc.) separately")
print("3. Always check for required nsec before calling auth-required endpoints")
print("4. Implement retry logic with exponential backoff for transient failures")
print("5. Use try/except/else/finally for resource cleanup")
