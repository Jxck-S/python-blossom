import base64
import hashlib
import json
import mimetypes
import time
from dataclasses import dataclass
from io import BytesIO
from typing import List, Optional, Dict, Any, Union

import requests
from pynostr.key import PrivateKey
from .errors import BlossomError, get_error_from_status
from pynostr.event import Event

# Constants per Blossom + Nostr specs
AUTH_KIND = 24242  # Authorization events (BUD-01,02,04,06)
SERVER_LIST_KIND = 10063  # BUD-03 User Server List
DEFAULT_EXPIRATION_SECONDS = 3600

@dataclass
class Blob:
    """Represents downloaded blob data with metadata."""
    content: bytes
    sha256: str
    mime_type: str = "application/octet-stream"
    
    # MIME type to file extension mapping
    _EXT_MAP = {
        'image/png': 'png',
        'image/jpeg': 'jpg',
        'image/webp': 'webp',
        'image/gif': 'gif',
        'image/svg+xml': 'svg',
        'video/mp4': 'mp4',
        'video/webm': 'webm',
        'audio/mpeg': 'mp3',
        'audio/wav': 'wav',
        'application/pdf': 'pdf',
        'text/plain': 'txt',
    }
    
    def get_extension(self) -> str:
        """Get file extension based on MIME type."""
        return self._EXT_MAP.get(self.mime_type, 
                                self.mime_type.split('/')[-1] if '/' in self.mime_type else 'bin')
    
    def get_bytes(self) -> bytes:
        """Get raw bytes content of blob.
        
        :return: Blob content as bytes.
        """
        return self.content
    
    def get_file_like(self) -> BytesIO:
        """Get blob as file-like BytesIO object for streaming or in-memory operations.
        
        :return: BytesIO object positioned at start of blob.
        """
        return BytesIO(self.content)
    
    def save(self, file_path: Optional[str] = None) -> str:
        """Save blob to file. If no path provided, generates one from sha256 and extension.
        
        :param file_path: Optional explicit file path. If omitted, uses {sha256[:8]}.{ext}
        :return: Path where file was saved.
        """
        if not file_path:
            file_path = f"{self.sha256[:8]}.{self.get_extension()}"
        with open(file_path, 'wb') as f:
            f.write(self.content)
        return file_path

class BlossomClient:
    """High-level Blossom protocol client.

    Implements endpoints described in BUD documents:
    - BUD-01: GET /<sha256>, HEAD /<sha256>
    - BUD-02: PUT /upload, GET /list/<pubkey>, DELETE /<sha256>
    - BUD-03: User Server List event generator (kind 10063)
    - BUD-04: PUT /mirror
    - BUD-05: Media optimization (HEAD /media, PUT /media) [optional]
    - BUD-06: HEAD /upload (upload requirements)
    """

    def __init__(self, nsec: Optional[str] = None, default_servers: Optional[List[str]] = None, expiration_seconds: int = DEFAULT_EXPIRATION_SECONDS):
        """Initialize client.

        :param nsec: NIP-19 encoded private key (nsec...). If omitted, only public endpoints can be used.
        :param default_servers: Ordered list of Blossom server base URLs (no trailing slash).
        :param expiration_seconds: Expiration time for auth events.
        """
        self.expiration_seconds = expiration_seconds
        self.default_servers = default_servers or []
        self._priv: Optional[PrivateKey] = PrivateKey.from_nsec(nsec) if nsec else None
        self.pubkey_hex: Optional[str] = self._priv.public_key.hex() if self._priv else None

    # ----------------------- Internal Helpers -----------------------
    def _require_key(self):
        if not self._priv:
            raise BlossomError("Private key required for this operation. Provide nsec when instantiating BlossomClient.")

    def _sha256_bytes(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _detect_mime_type(self, data: Optional[bytes] = None, file_path: Optional[str] = None) -> str:
        """Detect MIME type from file extension or magic bytes.
        
        :param data: Optional binary data to check magic bytes
        :param file_path: Optional file path to check extension
        :return: MIME type string
        """
        # Try file extension first
        if file_path:
            guessed, _ = mimetypes.guess_type(file_path)
            if guessed:
                return guessed
        
        # Try magic bytes
        if data:
            if data.startswith(b'\x89PNG'):
                return 'image/png'
            elif data.startswith(b'\xff\xd8\xff'):
                return 'image/jpeg'
            elif data.startswith(b'GIF8'):
                return 'image/gif'
            elif data.startswith(b'RIFF') and b'WEBP' in data[:12]:
                return 'image/webp'
            elif data.startswith(b'%PDF'):
                return 'application/pdf'
            elif data.startswith(b'ID3') or data.startswith(b'\xff\xfb'):
                return 'audio/mpeg'
            elif data.startswith(b'RIFF') and b'WAVE' in data[:12]:
                return 'audio/wav'
            elif data.startswith(b'\x00\x00\x00\x18ftypmp42'):
                return 'video/mp4'
            elif data.startswith(b'\x1a\x45\xdf\xa3'):
                return 'video/webm'
        
        return 'application/octet-stream'

    def _build_auth_event(self, verb: str, x_hashes: Optional[List[str]] = None, server_url: Optional[str] = None, content: Optional[str] = None) -> str:
        """Build and sign an authorization event (kind 24242) with pynostr."""
        self._require_key()
        created_at = int(time.time())
        expiration = created_at + self.expiration_seconds
        tags: List[List[str]] = [["t", verb], ["expiration", str(expiration)]]
        if x_hashes:
            for h in x_hashes:
                tags.append(["x", h])
        if server_url and verb == "get" and not x_hashes:
            tags.append(["server", server_url.rstrip('/') + '/'])
        # pynostr Event: supply content, kind, tags (created_at auto-set internally)
        ev = Event(content=content or f"{verb.capitalize()} Blob", kind=AUTH_KIND, tags=tags)
        ev.sign(self._priv.hex())  # sign with private key hex
        ev_json = json.dumps(ev.to_dict())
        return base64.b64encode(ev_json.encode()).decode()

    def _auth_header(self, verb: str, x_hashes: Optional[List[str]] = None, server_url: Optional[str] = None, content: Optional[str] = None) -> Dict[str,str]:
        return {"Authorization": f"Nostr {self._build_auth_event(verb, x_hashes, server_url, content)}"}

    def _full_url(self, server: str, path: str) -> str:
        return server.rstrip('/') + '/' + path.lstrip('/')

    def _handle_response(self, resp: requests.Response) -> Union[Dict[str, Any], bytes]:
        if resp.status_code >= 400:
            reason = resp.headers.get('X-Reason') or resp.text
            error = get_error_from_status(resp.status_code, reason)
            raise error
        ctype = resp.headers.get('Content-Type','')
        if 'application/json' in ctype:
            try:
                return resp.json()
            except Exception:
                raise BlossomError("Invalid JSON in response")
        return resp.content

    # ----------------------- Endpoint Methods -----------------------
    # BUD-02 + BUD-01: Upload blob
    def upload_blob(self, server: Optional[str], data: Optional[bytes] = None, file_path: Optional[str] = None, mime_type: Optional[str] = None, description: Optional[str] = None, use_auth: bool = True) -> Dict[str, Any]:
        """Upload a blob (PUT /upload). Provide either data or file_path.

        :param server: Blossom server base URL. If None, uses first default server.
        :param data: Raw binary blob.
        :param file_path: Path to file to read.
        :param mime_type: Content-Type header value (auto-detected if None).
        :param description: Human readable description for auth event.
        :param use_auth: Whether to attach authorization event.
        :return: Blob Descriptor dict.
        """
        server = server or (self.default_servers[0] if self.default_servers else None)
        if not server:
            raise BlossomError("Server URL required (no default servers configured).")
        if (data is None) == (file_path is None):
            raise BlossomError("Exactly one of data or file_path must be provided")
        if file_path:
            with open(file_path, 'rb') as f:
                data = f.read()
        assert data is not None
        body_hash = self._sha256_bytes(data)
        # Auto-detect MIME type if not provided
        if mime_type is None:
            mime_type = self._detect_mime_type(data=data, file_path=file_path)
        headers = {"Content-Type": mime_type}
        if use_auth:
            headers.update(self._auth_header("upload", [body_hash], content=description or f"Upload {file_path or 'blob'}"))
        url = self._full_url(server, 'upload')
        resp = requests.put(url, headers=headers, data=data)
        return self._handle_response(resp)

    # BUD-01: GET /<sha256>
    def get_blob(self, server: str, sha256: str, extension: Optional[str] = None, use_auth: bool = False, mime_type: Optional[str] = None) -> Blob:
        """Download a blob from server.
        
        :param server: Server URL.
        :param sha256: Blob hash.
        :param extension: Optional file extension for URL.
        :param use_auth: Whether to include authorization.
        :param mime_type: Optional MIME type. If omitted, defaults to application/octet-stream.
        :return: Blob object with content and metadata.
        """
        path = sha256 + (f".{extension}" if extension else "")
        headers = {}
        if use_auth:
            headers.update(self._auth_header("get", [sha256]))
        resp = requests.get(self._full_url(server, path), headers=headers)
        content = self._handle_response(resp)
        if isinstance(content, dict):
            raise BlossomError("Expected binary blob, got JSON")
        return Blob(content=content, sha256=sha256, mime_type=mime_type or "application/octet-stream")

    # BUD-01: HEAD /<sha256>
    def head_blob(self, server: str, sha256: str, extension: Optional[str] = None, use_auth: bool = False) -> Dict[str, Any]:
        path = sha256 + (f".{extension}" if extension else "")
        headers = {}
        if use_auth:
            headers.update(self._auth_header("get", [sha256]))
        resp = requests.head(self._full_url(server, path), headers=headers)
        if resp.status_code >= 400:
            reason = resp.headers.get('X-Reason') or resp.text
            raise BlossomError(f"HTTP {resp.status_code}: {reason}")
        return {
            "content_type": resp.headers.get('Content-Type'),
            "content_length": resp.headers.get('Content-Length'),
            "accept_ranges": resp.headers.get('Accept-Ranges')
        }

    # BUD-02: GET /list/<pubkey>
    def list_blobs(self, server: str, pubkey_hex: Optional[str] = None, cursor: Optional[str] = None, limit: Optional[int] = None, use_auth: bool = False) -> List[Dict[str, Any]]:
        # Convert npub to hex if provided
        target_pub = pubkey_hex or self.pubkey_hex
        if target_pub and target_pub.startswith('npub1'):
            # Convert NIP-19 npub to hex
            from pynostr.key import PublicKey
            try:
                target_pub = PublicKey.from_npub(target_pub).hex()
            except Exception:
                # If conversion fails, assume it's already hex
                pass
        if not target_pub:
            raise BlossomError("pubkey required (no private key provided and pubkey_hex not supplied)")
        params = {}
        if cursor:
            params['cursor'] = cursor
        if limit:
            params['limit'] = str(limit)
        headers = {}
        if use_auth:
            headers.update(self._auth_header("list"))
        url = self._full_url(server, f"list/{target_pub}")
        resp = requests.get(url, headers=headers, params=params)
        data = self._handle_response(resp)
        if isinstance(data, bytes):
            raise BlossomError("Expected JSON list, got bytes")
        if not isinstance(data, list):
            raise BlossomError("Expected list of blob descriptors")
        return data  # type: ignore

    # BUD-02: DELETE /<sha256>
    def delete_blob(self, server: str, sha256: str, description: Optional[str] = None) -> Dict[str, Any]:
        headers = self._auth_header("delete", [sha256], content=description or f"Delete {sha256[:8]}")
        resp = requests.delete(self._full_url(server, sha256), headers=headers)
        data = self._handle_response(resp)
        if isinstance(data, bytes):
            # Some servers may return empty body
            return {"status": "deleted", "sha256": sha256}
        return data  # type: ignore

    # BUD-04: PUT /mirror
    def mirror_blob(self, server: str, source_url: str, sha256: str, description: Optional[str] = None) -> Dict[str, Any]:
        headers = self._auth_header("upload", [sha256], server_url=server, content=description or f"Mirror {sha256[:8]}")
        url = self._full_url(server, 'mirror')
        body = json.dumps({"url": source_url})
        resp = requests.put(url, headers=headers, data=body)
        data = self._handle_response(resp)
        if isinstance(data, bytes):
            raise BlossomError("Expected JSON blob descriptor")
        return data  # type: ignore

    # BUD-06: HEAD /upload (requirements)
    def head_upload_requirements(self, server: str, data: bytes, mime_type: Optional[str] = None,
                                 use_auth: bool = False) -> Dict[str, Any]:
        """Check upload requirements for a blob.
        
        :param server: Server URL
        :param data: Blob data as bytes
        :param mime_type: MIME type of the blob (auto-detected if None)
        :param use_auth: Whether to include authorization
        :return: Dictionary of response headers
        """
        sha256 = hashlib.sha256(data).hexdigest()
        content_length = len(data)
        
        # Auto-detect MIME type if not provided
        if mime_type is None:
            mime_type = self._detect_mime_type(data=data)
        
        headers = {
            'X-SHA-256': sha256,
            'X-Content-Type': mime_type,
            'X-Content-Length': str(content_length)
        }
        if use_auth:
            # Include the blob hash in x tags for the auth event
            headers.update(self._auth_header("upload", [sha256], content="Check upload requirements"))
        resp = requests.head(self._full_url(server, 'upload'), headers=headers)
        if resp.status_code >= 400:
            reason = resp.headers.get('X-Reason') or resp.text
            error = get_error_from_status(resp.status_code, reason)
            raise error
        return {k.lower().replace('-', '_'): v for k, v in resp.headers.items()}

    # BUD-05: Media optimization endpoints (optional). Treat similar to upload.
    def media_upload(self, server: str, data: bytes, mime_type: Optional[str] = None, description: Optional[str] = None, use_auth: bool = True) -> Dict[str, Any]:
        body_hash = self._sha256_bytes(data)
        # Auto-detect MIME type if not provided
        if mime_type is None:
            mime_type = self._detect_mime_type(data=data)
        headers = {"Content-Type": mime_type}
        if use_auth:
            headers.update(self._auth_header("media", [body_hash], content=description or "Media upload"))
        resp = requests.put(self._full_url(server, 'media'), headers=headers, data=data)
        data_resp = self._handle_response(resp)
        if isinstance(data_resp, bytes):
            raise BlossomError("Expected JSON blob descriptor")
        return data_resp  # type: ignore

    def media_head(self, server: str, data: bytes, mime_type: Optional[str] = None,
                   use_auth: bool = True) -> Dict[str, Any]:
        """Check media optimization support for a blob.
        
        :param server: Server URL
        :param data: Blob data as bytes
        :param mime_type: MIME type of the blob (auto-detected if None)
        :param use_auth: Whether to include authorization (default True, required by servers)
        :return: Dictionary of response headers
        """
        sha256 = hashlib.sha256(data).hexdigest()
        content_length = len(data)
        
        # Auto-detect MIME type if not provided
        if mime_type is None:
            mime_type = self._detect_mime_type(data=data)
        
        headers = {
            'X-SHA-256': sha256,
            'X-Content-Type': mime_type,
            'X-Content-Length': str(content_length)
        }
        if use_auth:
            # Include the blob hash in x tags for the auth event
            headers.update(self._auth_header("media", [sha256], content="Check media optimization support"))
        resp = requests.head(self._full_url(server, 'media'), headers=headers)
        if resp.status_code >= 400:
            reason = resp.headers.get('X-Reason') or resp.text
            error = get_error_from_status(resp.status_code, reason)
            raise error
        return {k.lower().replace('-', '_'): v for k, v in resp.headers.items()}

    # BUD-03: Generate User Server List event
    def generate_server_list_event(self, servers: Optional[List[str]] = None) -> Dict[str, Any]:
        self._require_key()
        servers = servers or self.default_servers
        if not servers:
            raise BlossomError("No servers provided to generate server list event")
        ev = Event(content="", kind=SERVER_LIST_KIND, tags=[["server", s] for s in servers])
        ev.sign(self._priv.hex())
        return ev.to_dict()

    # BUD-03: Publish User Server List event to relays
    def publish_server_list_event(self, relays: List[str], servers: Optional[List[str]] = None) -> str:
        """Generate and publish a server list event to relays.
        
        :param relays: List of relay URLs (wss://) to publish to
        :param servers: Optional list of server URLs; defaults to self.default_servers
        :return: Event ID of the published event
        """
        import warnings
        from pynostr.relay_manager import RelayManager
        
        self._require_key()
        servers = servers or self.default_servers
        if not servers:
            raise BlossomError("No servers provided to publish server list event")
        if not relays:
            raise BlossomError("No relays provided to publish server list event")
        
        # Generate the server list event
        server_list_event = self.generate_server_list_event(servers)
        
        # Create Event object for publishing
        ev = Event(server_list_event['content'], kind=server_list_event['kind'], 
                   tags=server_list_event['tags'])
        ev.sign(self._priv.hex())
        
        # Connect to relays and publish
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message=".*websocket_ping.*")
            rm = RelayManager(timeout=2)
            rm.websocket_ping_interval = 60
            rm.websocket_ping_timeout = 60
            for relay in relays:
                rm.add_relay(relay)
            
            rm.publish_event(ev)
            rm.run_sync()
            time.sleep(2)
            rm.close_all_relay_connections()
        
        return ev.id

    # Convenience: upload to all default servers
    def upload_to_all(self, data: Optional[bytes] = None, file_path: Optional[str] = None, mime_type: Optional[str] = None, description: Optional[str] = None, use_auth: bool = True) -> Dict[str, Dict[str, Any]]:
        results = {}
        for server in self.default_servers:
            try:
                results[server] = self.upload_blob(server, data=data, file_path=file_path, mime_type=mime_type, description=description, use_auth=use_auth)
            except Exception as e:
                results[server] = {"error": str(e)}
        return results

    # BUD-03: Fetch a user's server list (kind 10063) from relays
    def fetch_server_list(self, relays: List[str], pubkey_hex: Optional[str] = None, timeout: float = 2.0) -> List[str]:
        """Query relays (pynostr) for latest kind 10063 server list event for a user."""
        import uuid
        import warnings
        from pynostr.relay_manager import RelayManager
        from pynostr.filters import FiltersList, Filters

        target_raw = pubkey_hex or self.pubkey_hex
        target = self._normalize_pubkey(target_raw) if target_raw else None
        if not target:
            raise BlossomError("pubkey required (no private key and pubkey_hex not supplied)")

        # Initialize RelayManager with matching ping timeout/interval
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message=".*websocket_ping.*")
            rm = RelayManager(timeout=timeout)
            rm.websocket_ping_interval = 60
            rm.websocket_ping_timeout = 60
            for r in relays:
                rm.add_relay(r)

            filters = FiltersList([Filters(authors=[target], kinds=[SERVER_LIST_KIND], limit=1)])
            sub_id = uuid.uuid4().hex
            rm.add_subscription_on_all_relays(sub_id, filters)
            rm.run_sync()  # establish connections & send subscription
            # small wait window for events
            time.sleep(timeout)
            servers = self._extract_server_list(rm, target)
            rm.close_all_relay_connections()
        return servers

    def _extract_server_list(self, relay_manager, target_pubkey: str) -> List[str]:
        servers: List[str] = []
        # Iterate through available event messages in the pool
        while relay_manager.message_pool.has_events():
            event_msg = relay_manager.message_pool.get_event()
            ev = event_msg.event
            if getattr(ev, 'kind', None) == SERVER_LIST_KIND and getattr(ev, 'pubkey', None) == target_pubkey:
                candidate = [t[1] for t in getattr(ev, 'tags', []) if len(t) > 1 and t[0] == 'server']
                if candidate:
                    servers = candidate
        return servers

    # ----------------------- Utility: npub/hex normalization -----------------------
    def _normalize_pubkey(self, pubkey: str) -> str:
        """Accept either raw hex public key (64 hex chars) or npub (bech32) and return hex.

        :param pubkey: hex string or npub identifier.
        :return: 64-char hex public key.
        """
        if not pubkey:
            raise BlossomError("Empty pubkey")
        pubkey = pubkey.strip()
        if pubkey.startswith('npub1'):
            try:
                return self._decode_npub(pubkey)
            except Exception as e:
                raise BlossomError(f"Invalid npub format: {e}") from e
        # Basic validation for hex
        if len(pubkey) != 64:
            raise BlossomError("Hex pubkey must be 64 characters")
        try:
            int(pubkey, 16)
        except ValueError:
            raise BlossomError("Pubkey is not valid hex")
        return pubkey

    def _decode_npub(self, npub: str) -> str:
        """Decode a NIP-19 npub (bech32) into hex public key."""
        CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

        def bech32_polymod(values):
            GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
            chk = 1
            for v in values:
                b = (chk >> 25) & 0xff
                chk = (chk & 0x1ffffff) << 5 ^ v
                for i in range(5):
                    chk ^= GENERATORS[i] if ((b >> i) & 1) else 0
            return chk

        def bech32_hrp_expand(hrp):
            return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

        def bech32_verify_checksum(hrp, data):
            return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

        def convertbits(data, frombits, tobits, pad=True):
            acc = 0
            bits = 0
            ret = []
            maxv = (1 << tobits) - 1
            for value in data:
                if value < 0 or value >> frombits:
                    return None
                acc = (acc << frombits) | value
                bits += frombits
                while bits >= tobits:
                    bits -= tobits
                    ret.append((acc >> bits) & maxv)
            if pad:
                if bits:
                    ret.append((acc << (tobits - bits)) & maxv)
            elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
                return None
            return ret

        if npub.lower().startswith('npub1'):
            pos = npub.rfind('1')
            if pos == -1:
                raise ValueError('No separator character for bech32')
            hrp = npub[:pos]
            data_part = npub[pos+1:]
            if hrp != 'npub':
                raise ValueError('Invalid hrp for npub')
            data = []
            for c in data_part:
                if c not in CHARSET:
                    raise ValueError('Invalid character in bech32 data')
                data.append(CHARSET.index(c))
            if not bech32_verify_checksum(hrp, data):
                raise ValueError('Checksum failed')
            # Remove checksum (last 6 values)
            payload = data[:-6]
            decoded = convertbits(payload, 5, 8, False)
            if decoded is None:
                raise ValueError('convertbits failure')
            raw = bytes(decoded)
            if len(raw) != 32:
                raise ValueError('Invalid decoded length')
            return raw.hex()
        raise ValueError('Not an npub bech32 string')
