"""Async Blossom protocol client using httpx for concurrent operations."""

import asyncio
import base64
import hashlib
import json
import mimetypes
import time
from io import BytesIO
from typing import List, Optional, Dict, Any, Union

import httpx
from pynostr.key import PrivateKey
from pynostr.event import Event

from .errors import BlossomError, get_error_from_status
from .client import Blob, AUTH_KIND, SERVER_LIST_KIND, DEFAULT_EXPIRATION_SECONDS


class AsyncBlossomClient:
    """Async high-level Blossom protocol client with concurrent operation support.

    This async client provides the same functionality as BlossomClient but with
    async/await support for non-blocking I/O operations and concurrent requests.

    Key benefits:
    - Concurrent uploads to multiple servers
    - Non-blocking network operations
    - Better performance for I/O-bound operations
    - Compatible with modern async Python applications

    Implements endpoints described in BUD documents:
    - BUD-01: GET /<sha256>, HEAD /<sha256>
    - BUD-02: PUT /upload, GET /list/<pubkey>, DELETE /<sha256>
    - BUD-03: User Server List event generator (kind 10063)
    - BUD-04: PUT /mirror
    - BUD-05: Media optimization (HEAD /media, PUT /media) [optional]
    - BUD-06: HEAD /upload (upload requirements)
    """

    def __init__(
        self,
        nsec: Optional[str] = None,
        default_servers: Optional[List[str]] = None,
        expiration_seconds: int = DEFAULT_EXPIRATION_SECONDS,
    ):
        """Initialize async client.

        :param nsec: Private key in any format (nsec, hex, or other NIP-19 encodings).
        :param default_servers: Ordered list of Blossom server base URLs (no trailing slash).
        :param expiration_seconds: Expiration time for auth events.
        """
        self.expiration_seconds = expiration_seconds
        self.default_servers = default_servers or []
        self._priv: Optional[PrivateKey] = self._normalize_private_key(nsec) if nsec else None
        self.pubkey_hex: Optional[str] = self._priv.public_key.hex() if self._priv else None

    # ----------------------- Internal Helpers -----------------------
    def _require_key(self):
        if not self._priv:
            raise BlossomError(
                "Private key required for this operation. "
                "Provide a private key when instantiating AsyncBlossomClient."
            )

    def _normalize_private_key(self, private_key_input: str) -> PrivateKey:
        """Normalize private key from any supported format to PrivateKey object."""
        private_key_input = private_key_input.strip()

        if private_key_input.startswith("nsec1"):
            try:
                return PrivateKey.from_nsec(private_key_input)
            except Exception as e:
                raise BlossomError(f"Invalid nsec format: {e}") from e

        if len(private_key_input) == 64:
            try:
                int(private_key_input, 16)
                return PrivateKey(bytes.fromhex(private_key_input))
            except ValueError:
                pass

        raise BlossomError("Unsupported private key format. Expected nsec or 64-char hex string.")

    def _normalize_public_key_to_hex(self, pubkey_input: Optional[str]) -> str:
        """Normalize public key from any supported format to hex string."""
        if not pubkey_input:
            if not self.pubkey_hex:
                raise BlossomError(
                    "Public key required (no private key provided and pubkey not supplied)"
                )
            return self.pubkey_hex

        pubkey_input = pubkey_input.strip()

        if pubkey_input.startswith("npub1"):
            try:
                return self._decode_npub(pubkey_input)
            except Exception as e:
                raise BlossomError(f"Invalid npub format: {e}") from e

        if len(pubkey_input) == 64:
            try:
                int(pubkey_input, 16)
                return pubkey_input
            except ValueError:
                raise BlossomError("Public key is not valid hex")

        raise BlossomError("Unsupported public key format. Expected npub or 64-char hex string.")

    def _sha256_bytes(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _detect_mime_type(
        self, data: Optional[bytes] = None, file_path: Optional[str] = None
    ) -> str:
        """Detect MIME type from file extension or magic bytes."""
        if file_path:
            guessed, _ = mimetypes.guess_type(file_path)
            if guessed:
                return guessed

        if data:
            if data.startswith(b"\x89PNG"):
                return "image/png"
            elif data.startswith(b"\xff\xd8\xff"):
                return "image/jpeg"
            elif data.startswith(b"GIF8"):
                return "image/gif"
            elif data.startswith(b"RIFF") and b"WEBP" in data[:12]:
                return "image/webp"
            elif data.startswith(b"%PDF"):
                return "application/pdf"
            elif data.startswith(b"ID3") or data.startswith(b"\xff\xfb"):
                return "audio/mpeg"
            elif data.startswith(b"RIFF") and b"WAVE" in data[:12]:
                return "audio/wav"
            elif data.startswith(b"\x00\x00\x00\x18ftypmp42"):
                return "video/mp4"
            elif data.startswith(b"\x1a\x45\xdf\xa3"):
                return "video/webm"

        return "application/octet-stream"

    def _build_auth_event(
        self,
        verb: str,
        x_hashes: Optional[List[str]] = None,
        server_url: Optional[str] = None,
        content: Optional[str] = None,
    ) -> str:
        """Build and sign an authorization event (kind 24242)."""
        self._require_key()
        created_at = int(time.time())
        expiration = created_at + self.expiration_seconds
        tags: List[List[str]] = [["t", verb], ["expiration", str(expiration)]]
        if x_hashes:
            for h in x_hashes:
                tags.append(["x", h])
        if server_url and verb == "get" and not x_hashes:
            tags.append(["server", server_url.rstrip("/") + "/"])
        ev = Event(content=content or f"{verb.capitalize()} Blob", kind=AUTH_KIND, tags=tags)
        ev.sign(self._priv.hex())
        ev_json = json.dumps(ev.to_dict())
        return base64.b64encode(ev_json.encode()).decode()

    def _auth_header(
        self,
        verb: str,
        x_hashes: Optional[List[str]] = None,
        server_url: Optional[str] = None,
        content: Optional[str] = None,
    ) -> Dict[str, str]:
        return {
            "Authorization": f"Nostr {self._build_auth_event(verb, x_hashes, server_url, content)}"
        }

    def _full_url(self, server: str, path: str) -> str:
        return server.rstrip("/") + "/" + path.lstrip("/")

    def _handle_response(self, resp: httpx.Response) -> Union[Dict[str, Any], bytes]:
        if resp.status_code >= 400:
            reason = resp.headers.get("X-Reason") or resp.text
            error = get_error_from_status(resp.status_code, reason)
            raise error
        ctype = resp.headers.get("Content-Type", "")
        if "application/json" in ctype:
            try:
                return resp.json()
            except Exception:
                raise BlossomError("Invalid JSON in response")
        return resp.content

    # ----------------------- Async Endpoint Methods -----------------------

    async def upload_blob(
        self,
        server: Optional[str],
        data: Optional[bytes] = None,
        file_path: Optional[str] = None,
        mime_type: Optional[str] = None,
        description: Optional[str] = None,
        use_auth: bool = True,
    ) -> Dict[str, Any]:
        """Upload a blob asynchronously (PUT /upload).

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
            with open(file_path, "rb") as f:
                data = f.read()

        assert data is not None
        body_hash = self._sha256_bytes(data)

        if mime_type is None:
            mime_type = self._detect_mime_type(data=data, file_path=file_path)

        headers = {"Content-Type": mime_type}
        if use_auth:
            headers.update(
                self._auth_header(
                    "upload", [body_hash], content=description or f"Upload {file_path or 'blob'}"
                )
            )

        url = self._full_url(server, "upload")
        async with httpx.AsyncClient() as client:
            resp = await client.put(url, headers=headers, content=data)
        return self._handle_response(resp)

    async def get_blob(
        self,
        server: str,
        sha256: str,
        extension: Optional[str] = None,
        use_auth: bool = False,
        mime_type: Optional[str] = None,
    ) -> Blob:
        """Download a blob from server asynchronously.

        :param server: Server URL.
        :param sha256: Blob hash.
        :param extension: Optional file extension for URL.
        :param use_auth: Whether to include authorization.
        :param mime_type: Optional MIME type.
        :return: Blob object with content and metadata.
        """
        path = sha256 + (f".{extension}" if extension else "")
        headers = {}
        if use_auth:
            headers.update(self._auth_header("get", [sha256]))

        async with httpx.AsyncClient() as client:
            resp = await client.get(self._full_url(server, path), headers=headers)
        content = self._handle_response(resp)

        if isinstance(content, dict):
            raise BlossomError("Expected binary blob, got JSON")
        return Blob(content=content, sha256=sha256, mime_type=mime_type or "application/octet-stream")

    async def head_blob(
        self, server: str, sha256: str, extension: Optional[str] = None, use_auth: bool = False
    ) -> Dict[str, Any]:
        """Get blob metadata without downloading (HEAD /<sha256>)."""
        path = sha256 + (f".{extension}" if extension else "")
        headers = {}
        if use_auth:
            headers.update(self._auth_header("get", [sha256]))

        async with httpx.AsyncClient() as client:
            resp = await client.head(self._full_url(server, path), headers=headers)

        if resp.status_code >= 400:
            reason = resp.headers.get("X-Reason") or resp.text
            raise BlossomError(f"HTTP {resp.status_code}: {reason}")

        return {
            "content_type": resp.headers.get("Content-Type"),
            "content_length": resp.headers.get("Content-Length"),
            "accept_ranges": resp.headers.get("Accept-Ranges"),
        }

    async def list_blobs(
        self,
        server: str,
        pubkey: Optional[str] = None,
        cursor: Optional[str] = None,
        limit: Optional[int] = None,
        use_auth: bool = False,
    ) -> List[Dict[str, Any]]:
        """List blobs for a user asynchronously.

        :param server: Server URL
        :param pubkey: Public key (npub or hex). If None, uses client's public key.
        :param cursor: Pagination cursor
        :param limit: Limit number of results
        :param use_auth: Whether to include authorization
        :return: List of blob descriptors
        """
        target_pubkey = self._normalize_public_key_to_hex(pubkey)
        params = {}
        if cursor:
            params["cursor"] = cursor
        if limit:
            params["limit"] = str(limit)

        headers = {}
        if use_auth:
            headers.update(self._auth_header("list"))

        url = self._full_url(server, f"list/{target_pubkey}")
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers, params=params)

        data = self._handle_response(resp)
        if isinstance(data, bytes):
            raise BlossomError("Expected JSON list, got bytes")
        if not isinstance(data, list):
            raise BlossomError("Expected list of blob descriptors")
        return data  # type: ignore

    async def delete_blob(
        self, server: str, sha256: str, description: Optional[str] = None
    ) -> Dict[str, Any]:
        """Delete a blob asynchronously (DELETE /<sha256>)."""
        headers = self._auth_header(
            "delete", [sha256], content=description or f"Delete {sha256[:8]}"
        )

        async with httpx.AsyncClient() as client:
            resp = await client.delete(self._full_url(server, sha256), headers=headers)

        data = self._handle_response(resp)
        if isinstance(data, bytes):
            return {"status": "deleted", "sha256": sha256}
        return data  # type: ignore

    async def mirror_blob(
        self, server: str, source_url: str, sha256: str, description: Optional[str] = None
    ) -> Dict[str, Any]:
        """Mirror blob from one server to another asynchronously (PUT /mirror)."""
        headers = self._auth_header(
            "upload", [sha256], server_url=server, content=description or f"Mirror {sha256[:8]}"
        )
        url = self._full_url(server, "mirror")
        body = json.dumps({"url": source_url})

        async with httpx.AsyncClient() as client:
            resp = await client.put(url, headers=headers, content=body)

        data = self._handle_response(resp)
        if isinstance(data, bytes):
            raise BlossomError("Expected JSON blob descriptor")
        return data  # type: ignore

    async def head_upload_requirements(
        self, server: str, data: bytes, mime_type: Optional[str] = None, use_auth: bool = False
    ) -> Dict[str, Any]:
        """Check upload requirements for a blob asynchronously (HEAD /upload)."""
        sha256 = hashlib.sha256(data).hexdigest()
        content_length = len(data)

        if mime_type is None:
            mime_type = self._detect_mime_type(data=data)

        headers = {
            "X-SHA-256": sha256,
            "X-Content-Type": mime_type,
            "X-Content-Length": str(content_length),
        }
        if use_auth:
            headers.update(
                self._auth_header("upload", [sha256], content="Check upload requirements")
            )

        async with httpx.AsyncClient() as client:
            resp = await client.head(self._full_url(server, "upload"), headers=headers)

        if resp.status_code >= 400:
            reason = resp.headers.get("X-Reason") or resp.text
            error = get_error_from_status(resp.status_code, reason)
            raise error

        return {k.lower().replace("-", "_"): v for k, v in resp.headers.items()}

    async def media_upload(
        self,
        server: str,
        data: bytes,
        mime_type: Optional[str] = None,
        description: Optional[str] = None,
        use_auth: bool = True,
    ) -> Dict[str, Any]:
        """Upload with media optimization asynchronously (PUT /media)."""
        body_hash = self._sha256_bytes(data)

        if mime_type is None:
            mime_type = self._detect_mime_type(data=data)

        headers = {"Content-Type": mime_type}
        if use_auth:
            headers.update(
                self._auth_header("media", [body_hash], content=description or "Media upload")
            )

        async with httpx.AsyncClient() as client:
            resp = await client.put(self._full_url(server, "media"), headers=headers, content=data)

        data_resp = self._handle_response(resp)
        if isinstance(data_resp, bytes):
            raise BlossomError("Expected JSON blob descriptor")
        return data_resp  # type: ignore

    async def media_head(
        self, server: str, data: bytes, mime_type: Optional[str] = None, use_auth: bool = True
    ) -> Dict[str, Any]:
        """Check media optimization support asynchronously (HEAD /media)."""
        sha256 = hashlib.sha256(data).hexdigest()
        content_length = len(data)

        if mime_type is None:
            mime_type = self._detect_mime_type(data=data)

        headers = {
            "X-SHA-256": sha256,
            "X-Content-Type": mime_type,
            "X-Content-Length": str(content_length),
        }
        if use_auth:
            headers.update(
                self._auth_header(
                    "media", [sha256], content="Check media optimization support"
                )
            )

        async with httpx.AsyncClient() as client:
            resp = await client.head(self._full_url(server, "media"), headers=headers)

        if resp.status_code >= 400:
            reason = resp.headers.get("X-Reason") or resp.text
            error = get_error_from_status(resp.status_code, reason)
            raise error

        return {k.lower().replace("-", "_"): v for k, v in resp.headers.items()}

    # ----------------------- Concurrent Operations -----------------------

    async def upload_to_all(
        self,
        data: Optional[bytes] = None,
        file_path: Optional[str] = None,
        mime_type: Optional[str] = None,
        description: Optional[str] = None,
        use_auth: bool = True,
    ) -> Dict[str, Dict[str, Any]]:
        """Upload blob to all default servers concurrently.

        This is a key advantage of the async client - uploads happen in parallel
        rather than sequentially, dramatically improving performance when uploading
        to multiple servers.

        :param data: Raw binary blob
        :param file_path: Path to file to read
        :param mime_type: Content-Type (auto-detected if None)
        :param description: Description for auth event
        :param use_auth: Whether to use authorization
        :return: Dict mapping server URLs to results/errors
        """
        if not self.default_servers:
            raise BlossomError("No default servers configured")

        # Create tasks for all servers
        tasks = []
        for server in self.default_servers:
            task = self._upload_blob_with_error_handling(
                server, data=data, file_path=file_path, mime_type=mime_type,
                description=description, use_auth=use_auth
            )
            tasks.append(task)

        # Execute all uploads concurrently
        results_list = await asyncio.gather(*tasks)

        # Map results back to server URLs
        return dict(zip(self.default_servers, results_list))

    async def _upload_blob_with_error_handling(
        self, server: str, **kwargs
    ) -> Dict[str, Any]:
        """Helper to upload blob and catch errors for concurrent operations."""
        try:
            return await self.upload_blob(server, **kwargs)
        except Exception as e:
            return {"error": str(e)}

    # ----------------------- Server List Management (BUD-03) -----------------------

    def generate_server_list_event(self, servers: Optional[List[str]] = None) -> Dict[str, Any]:
        """Generate a Nostr server list event (kind 10063).

        Note: This is synchronous as it only involves local signing, no I/O.
        """
        self._require_key()
        servers = servers or self.default_servers
        if not servers:
            raise BlossomError("No servers provided to generate server list event")
        ev = Event(content="", kind=SERVER_LIST_KIND, tags=[["server", s] for s in servers])
        ev.sign(self._priv.hex())
        return ev.to_dict()

    def publish_server_list_event(
        self, relays: List[str], servers: Optional[List[str]] = None
    ) -> str:
        """Publish server list event to relays.

        Note: This uses the synchronous pynostr RelayManager as it doesn't have
        async support. For most use cases, this is fine as it's not called frequently.
        """
        from pynostr.relay_manager import RelayManager

        self._require_key()
        servers = servers or self.default_servers
        if not servers:
            raise BlossomError("No servers provided to publish server list event")
        if not relays:
            raise BlossomError("No relays provided to publish server list event")

        server_list_event = self.generate_server_list_event(servers)
        ev = Event(
            server_list_event["content"],
            kind=server_list_event["kind"],
            tags=server_list_event["tags"],
        )
        ev.sign(self._priv.hex())

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

    def fetch_server_list(
        self, relays: List[str], pubkey: Optional[str] = None, timeout: float = 2.0
    ) -> List[str]:
        """Query relays for latest kind 10063 server list event.

        Note: This uses the synchronous pynostr RelayManager as it doesn't have
        async support.
        """
        import uuid
        from pynostr.relay_manager import RelayManager
        from pynostr.filters import FiltersList, Filters

        target_pubkey = self._normalize_public_key_to_hex(pubkey)

        rm = RelayManager(timeout=timeout)
        rm.websocket_ping_interval = 60
        rm.websocket_ping_timeout = 60
        for r in relays:
            rm.add_relay(r)

        filters = FiltersList(
            [Filters(authors=[target_pubkey], kinds=[SERVER_LIST_KIND], limit=1)]
        )
        sub_id = uuid.uuid4().hex
        rm.add_subscription_on_all_relays(sub_id, filters)
        rm.run_sync()
        time.sleep(timeout)
        servers = self._extract_server_list(rm, target_pubkey)
        rm.close_all_relay_connections()
        return servers

    def _extract_server_list(self, relay_manager, target_pubkey: str) -> List[str]:
        """Extract server URLs from relay messages."""
        servers: List[str] = []
        while relay_manager.message_pool.has_events():
            event_msg = relay_manager.message_pool.get_event()
            ev = event_msg.event
            if (
                getattr(ev, "kind", None) == SERVER_LIST_KIND
                and getattr(ev, "pubkey", None) == target_pubkey
            ):
                candidate = [
                    t[1] for t in getattr(ev, "tags", []) if len(t) > 1 and t[0] == "server"
                ]
                if candidate:
                    servers = candidate
        return servers

    # ----------------------- Utility: Key format decoding -----------------------

    def _decode_npub(self, npub: str) -> str:
        """Decode a NIP-19 npub (bech32) into hex public key."""
        CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

        def bech32_polymod(values):
            GENERATORS = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
            chk = 1
            for v in values:
                b = (chk >> 25) & 0xFF
                chk = (chk & 0x1FFFFFF) << 5 ^ v
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

        if npub.lower().startswith("npub1"):
            pos = npub.rfind("1")
            if pos == -1:
                raise ValueError("No separator character for bech32")
            hrp = npub[:pos]
            data_part = npub[pos + 1 :]
            if hrp != "npub":
                raise ValueError("Invalid hrp for npub")
            data = []
            for c in data_part:
                if c not in CHARSET:
                    raise ValueError("Invalid character in bech32 data")
                data.append(CHARSET.index(c))
            if not bech32_verify_checksum(hrp, data):
                raise ValueError("Checksum failed")
            payload = data[:-6]
            decoded = convertbits(payload, 5, 8, False)
            if decoded is None:
                raise ValueError("convertbits failure")
            raw = bytes(decoded)
            if len(raw) != 32:
                raise ValueError("Invalid decoded length")
            return raw.hex()
        raise ValueError("Not an npub bech32 string")
