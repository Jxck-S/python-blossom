"""BUD-06: Upload requirements endpoint

Demonstrates querying server capabilities and upload restrictions via HEAD /upload.
"""
from python_blossom import BlossomClient

SERVERS = ['https://nostr.download']

client = BlossomClient(nsec=None, default_servers=SERVERS)
server = SERVERS[0]

# Query upload requirements from server
print("=== HEAD /upload (check upload requirements) ===")
try:
    upload_reqs = client.head_upload_requirements(server)
    print("Upload requirements retrieved!")
    for key, value in upload_reqs.items():
        print(f"  {key}: {value}")
except Exception as e:
    print(f"Failed to get upload requirements: {e}")

# Common upload requirement headers:
# X-Upload-Auth-Required: true/false - requires authentication
# X-Upload-Auth-Scope: default scope for uploads
# X-Upload-Auth-Digest-Required: true/false - requires auth digest
# X-Upload-Auth-Proof-Required: true/false - requires work proof

print("\n=== Interpreting upload requirements ===")
try:
    upload_reqs = client.head_upload_requirements(server)
    
    # Check if authentication is required
    auth_required = upload_reqs.get('X-Upload-Auth-Required', '').lower() == 'true'
    print(f"Authentication required: {auth_required}")
    
    # Check maximum upload size
    max_size = upload_reqs.get('X-Upload-Max-Size')
    if max_size:
        size_mb = int(max_size) / (1024 * 1024)
        print(f"Maximum upload size: {size_mb:.1f} MB")
    
    # Check allowed MIME types
    allowed_types = upload_reqs.get('X-Upload-Allowed-Types')
    if allowed_types:
        print(f"Allowed MIME types: {allowed_types}")
    
except Exception as e:
    print(f"Error interpreting requirements: {e}")
