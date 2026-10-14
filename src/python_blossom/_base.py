"""Transport-independent core shared by BlossomClient and AsyncBlossomClient.

Everything that does not touch the network lives here: key handling, auth event
signing, MIME detection, request construction and response parsing. The sync and
async clients only differ in how they send a prepared ``_Request``.
"""

import base64
import hashlib
import json
import mimetypes
import time
import uuid
from dataclasses import dataclass
from io import BytesIO
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import httpx
from pynostr.event import Event
from pynostr.key import PrivateKey

from .errors import BlossomError, get_error_from_status

# Constants per Blossom + Nostr specs
AUTH_KIND = 24242  # Authorization events (BUD-01,02,04,06)
SERVER_LIST_KIND = 10063  # BUD-03 User Server List
DEFAULT_EXPIRATION_SECONDS = 3600
DEFAULT_TIMEOUT: float = 30.0

TimeoutTypes = Union[None, float, Tuple[float, float], httpx.Timeout]


@dataclass
class Blob:
    """Represents downloaded blob data with metadata."""

    content: bytes
    sha256: str
    mime_type: str = "application/octet-stream"

    # MIME type to file extension mapping
    _EXT_MAP = {
        "image/png": "png",
        "image/jpeg": "jpg",
        "image/webp": "webp",
        "image/gif": "gif",
        "image/svg+xml": "svg",
        "video/mp4": "mp4",
        "video/webm": "webm",
        "audio/mpeg": "mp3",
        "audio/wav": "wav",
        "application/pdf": "pdf",
        "text/plain": "txt",
    }

    def get_extension(self) -> str:
        """Get file extension based on MIME type."""
        return self._EXT_MAP.get(
            self.mime_type, self.mime_type.split("/")[-1] if "/" in self.mime_type else "bin"
        )

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
        with open(file_path, "wb") as f:
            f.write(self.content)
        return file_path


@dataclass(frozen=True)
class _Request:
    """A fully prepared HTTP request, ready to hand to an httpx client."""

    method: str
    url: str
    headers: Dict[str, str]
    content: Optional[bytes] = None
    params: Optional[Dict[str, str]] = None


Parser = Callable[[httpx.Response], Any]


def _to_httpx_timeout(timeout: TimeoutTypes) -> Union[None, float, httpx.Timeout]:
    """Accept the ``(connect, read)`` tuple form that ``requests`` used, for compatibility."""
    if isinstance(timeout, tuple):
        if len(timeout) != 2:
            raise BlossomError("timeout tuple must be (connect, read)")
        connect, read = timeout
        return httpx.Timeout(read, connect=connect)
    return timeout


def _read_file(file_path: str) -> bytes:
    with open(file_path, "rb") as f:
        return f.read()


class _BaseBlossomClient:
    """Shared state and request/response logic for the sync and async clients.

    Implements endpoints described in BUD documents:
    - BUD-01: GET /<sha256>, HEAD /<sha256>
    - BUD-02: PUT /upload, GET /list/<pubkey>, DELETE /<sha256>
    - BUD-03: User Server List event generator (kind 10063)
    - BUD-04: PUT /mirror
    - BUD-05: Media optimization (HEAD /media, PUT /media) [optional]
    - BUD-06: HEAD /upload (upload requirements)
    - BUD-09: PUT /report [TODO - not yet implemented]
    """

    def __init__(
        self,
        nsec: Optional[str] = None,
        default_servers: Optional[List[str]] = None,
        expiration_seconds: int = DEFAULT_EXPIRATION_SECONDS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
    ):
        self.expiration_seconds = expiration_seconds
        self.timeout = timeout
        self.default_servers = default_servers or []
        self._priv: Optional[PrivateKey] = self._normalize_private_key(nsec) if nsec else None
        self.pubkey_hex: Optional[str] = self._priv.public_key.hex() if self._priv else None

    # ----------------------- Internal Helpers -----------------------
    def _require_key(self):
        if not self._priv:
            raise BlossomError(
                "Private key required for this operation. "
                f"Provide a private key when instantiating {type(self).__name__}."
            )

    def _normalize_private_key(self, private_key_input: str) -> PrivateKey:
        """Normalize private key from any supported format to PrivateKey object.

        Accepts: nsec (NIP-19) or 64-char hex string.

        :param private_key_input: Private key in any supported format
        :return: PrivateKey object
        :raises BlossomError: If format is invalid or unsupported
        """
        private_key_input = private_key_input.strip()

        if private_key_input.startswith("nsec1"):
            try:
                return PrivateKey.from_nsec(private_key_input)
            except Exception as e:
                raise BlossomError(f"Invalid nsec format: {e}") from e

        if len(private_key_input) == 64:
            try:
                int(private_key_input, 16)  # Validate it's hex
                return PrivateKey(bytes.fromhex(private_key_input))
            except ValueError:
                pass

        raise BlossomError("Unsupported private key format. Expected nsec or 64-char hex string.")

    def _normalize_public_key_to_hex(self, pubkey_input: Optional[str]) -> str:
        """Normalize public key from any supported format to hex string.

        Accepts: npub (NIP-19), hex string (64 chars).

        :param pubkey_input: Public key in any supported format, or None to use self.pubkey_hex
        :return: 64-char hex public key string
        :raises BlossomError: If format is invalid or unsupported
        """
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
                int(pubkey_input, 16)  # Validate it's hex
                return pubkey_input
            except ValueError:
                raise BlossomError("Public key is not valid hex")

        raise BlossomError("Unsupported public key format. Expected npub or 64-char hex string.")

    def _sha256_bytes(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _detect_mime_type(
        self, data: Optional[bytes] = None, file_path: Optional[str] = None
    ) -> str:
        """Detect MIME type from file extension or magic bytes.

        :param data: Optional binary data to check magic bytes
        :param file_path: Optional file path to check extension
        :return: MIME type string
        """
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
        """Build and sign an authorization event (kind 24242) with pynostr."""
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

    def _resolve_server(self, server: Optional[str]) -> str:
        server = server or (self.default_servers[0] if self.default_servers else None)
        if not server:
            raise BlossomError("Server URL required (no default servers configured).")
        return server

    @staticmethod
    def _check_one_source(data: Optional[bytes], file_path: Optional[str]) -> None:
        if (data is None) == (file_path is None):
            raise BlossomError("Exactly one of data or file_path must be provided")

    # ----------------------- Response Parsing -----------------------
    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            reason = resp.headers.get("X-Reason") or resp.text
            raise get_error_from_status(resp.status_code, reason)

    def _handle_response(self, resp: httpx.Response) -> Union[Dict[str, Any], bytes]:
        self._raise_for_status(resp)
        ctype = resp.headers.get("Content-Type", "")
        if "application/json" in ctype:
            try:
                return resp.json()
            except Exception:
                raise BlossomError("Invalid JSON in response")
        return resp.content

    def _parse_descriptor(self, resp: httpx.Response) -> Dict[str, Any]:
        data = self._handle_response(resp)
        if isinstance(data, bytes):
            raise BlossomError("Expected JSON blob descriptor")
        return data  # type: ignore

    def _parse_headers(self, resp: httpx.Response) -> Dict[str, Any]:
        self._raise_for_status(resp)
        return {k.lower().replace("-", "_"): v for k, v in resp.headers.items()}

    # ----------------------- Request Preparation -----------------------
    # Each _prep_* method returns the request to send and the parser for its response.
    def _prep_upload(
        self,
        server: str,
        data: bytes,
        file_path: Optional[str],
        mime_type: Optional[str],
        description: Optional[str],
        use_auth: bool,
    ) -> Tuple[_Request, Parser]:
        if mime_type is None:
            mime_type = self._detect_mime_type(data=data, file_path=file_path)
        headers = {"Content-Type": mime_type}
        if use_auth:
            headers.update(
                self._auth_header(
                    "upload",
                    [self._sha256_bytes(data)],
                    content=description or f"Upload {file_path or 'blob'}",
                )
            )
        req = _Request("PUT", self._full_url(server, "upload"), headers, content=data)
        return req, self._handle_response

    def _prep_upload_to_all(
        self,
        data: bytes,
        file_path: Optional[str],
        mime_type: Optional[str],
        description: Optional[str],
        use_auth: bool,
    ) -> Tuple[List[Tuple[str, _Request]], Parser]:
        """Hash, detect MIME and sign once; the auth event has no server tag so it is
        valid on every server."""
        if not self.default_servers:
            raise BlossomError("No default servers configured")
        first, parse = self._prep_upload(
            self.default_servers[0], data, file_path, mime_type, description, use_auth
        )
        reqs = [
            (s, _Request("PUT", self._full_url(s, "upload"), first.headers, content=data))
            for s in self.default_servers
        ]
        return reqs, parse

    def _prep_get_blob(
        self,
        server: str,
        sha256: str,
        extension: Optional[str],
        use_auth: bool,
        mime_type: Optional[str],
    ) -> Tuple[_Request, Parser]:
        path = sha256 + (f".{extension}" if extension else "")
        headers = self._auth_header("get", [sha256]) if use_auth else {}

        def parse(resp: httpx.Response) -> Blob:
            content = self._handle_response(resp)
            if isinstance(content, dict):
                raise BlossomError("Expected binary blob, got JSON")
            return Blob(
                content=content, sha256=sha256, mime_type=mime_type or "application/octet-stream"
            )

        return _Request("GET", self._full_url(server, path), headers), parse

    def _prep_head_blob(
        self, server: str, sha256: str, extension: Optional[str], use_auth: bool
    ) -> Tuple[_Request, Parser]:
        path = sha256 + (f".{extension}" if extension else "")
        headers = self._auth_header("get", [sha256]) if use_auth else {}

        def parse(resp: httpx.Response) -> Dict[str, Any]:
            self._raise_for_status(resp)
            return {
                "content_type": resp.headers.get("Content-Type"),
                "content_length": resp.headers.get("Content-Length"),
                "accept_ranges": resp.headers.get("Accept-Ranges"),
            }

        return _Request("HEAD", self._full_url(server, path), headers), parse

    def _prep_list_blobs(
        self,
        server: str,
        pubkey: Optional[str],
        cursor: Optional[str],
        limit: Optional[int],
        use_auth: bool,
    ) -> Tuple[_Request, Parser]:
        target_pubkey = self._normalize_public_key_to_hex(pubkey)
        params = {}
        if cursor:
            params["cursor"] = cursor
        if limit:
            params["limit"] = str(limit)
        headers = self._auth_header("list") if use_auth else {}

        def parse(resp: httpx.Response) -> List[Dict[str, Any]]:
            data = self._handle_response(resp)
            if isinstance(data, bytes):
                raise BlossomError("Expected JSON list, got bytes")
            if not isinstance(data, list):
                raise BlossomError("Expected list of blob descriptors")
            return data

        url = self._full_url(server, f"list/{target_pubkey}")
        return _Request("GET", url, headers, params=params), parse

    def _prep_delete_blob(
        self, server: str, sha256: str, description: Optional[str]
    ) -> Tuple[_Request, Parser]:
        headers = self._auth_header(
            "delete", [sha256], content=description or f"Delete {sha256[:8]}"
        )

        def parse(resp: httpx.Response) -> Dict[str, Any]:
            data = self._handle_response(resp)
            if isinstance(data, bytes):
                # Some servers may return empty body
                return {"status": "deleted", "sha256": sha256}
            return data  # type: ignore

        return _Request("DELETE", self._full_url(server, sha256), headers), parse

    def _prep_mirror_blob(
        self, server: str, source_url: str, sha256: str, description: Optional[str]
    ) -> Tuple[_Request, Parser]:
        headers = self._auth_header(
            "upload", [sha256], server_url=server, content=description or f"Mirror {sha256[:8]}"
        )
        headers["Content-Type"] = "application/json"
        body = json.dumps({"url": source_url}).encode()
        req = _Request("PUT", self._full_url(server, "mirror"), headers, content=body)
        return req, self._parse_descriptor

    def _prep_requirements(
        self,
        path: str,
        verb: str,
        auth_content: str,
        server: str,
        data: bytes,
        mime_type: Optional[str],
        use_auth: bool,
    ) -> Tuple[_Request, Parser]:
        """Shared by HEAD /upload (BUD-06) and HEAD /media (BUD-05)."""
        sha256 = self._sha256_bytes(data)
        if mime_type is None:
            mime_type = self._detect_mime_type(data=data)
        headers = {
            "X-SHA-256": sha256,
            "X-Content-Type": mime_type,
            "X-Content-Length": str(len(data)),
        }
        if use_auth:
            headers.update(self._auth_header(verb, [sha256], content=auth_content))
        return _Request("HEAD", self._full_url(server, path), headers), self._parse_headers

    def _prep_head_upload_requirements(
        self, server: str, data: bytes, mime_type: Optional[str], use_auth: bool
    ) -> Tuple[_Request, Parser]:
        return self._prep_requirements(
            "upload", "upload", "Check upload requirements", server, data, mime_type, use_auth
        )

    def _prep_media_head(
        self, server: str, data: bytes, mime_type: Optional[str], use_auth: bool
    ) -> Tuple[_Request, Parser]:
        return self._prep_requirements(
            "media", "media", "Check media optimization support", server, data, mime_type, use_auth
        )

    def _prep_media_upload(
        self,
        server: str,
        data: bytes,
        mime_type: Optional[str],
        description: Optional[str],
        use_auth: bool,
    ) -> Tuple[_Request, Parser]:
        if mime_type is None:
            mime_type = self._detect_mime_type(data=data)
        headers = {"Content-Type": mime_type}
        if use_auth:
            headers.update(
                self._auth_header(
                    "media", [self._sha256_bytes(data)], content=description or "Media upload"
                )
            )
        req = _Request("PUT", self._full_url(server, "media"), headers, content=data)
        return req, self._parse_descriptor

    # ----------------------- BUD-03: Server list (no HTTP) -----------------------
    def generate_server_list_event(self, servers: Optional[List[str]] = None) -> Dict[str, Any]:
        """Generate a signed Nostr server list event (kind 10063). Purely local, no I/O."""
        self._require_key()
        servers = servers or self.default_servers
        if not servers:
            raise BlossomError("No servers provided to generate server list event")
        ev = Event(content="", kind=SERVER_LIST_KIND, tags=[["server", s] for s in servers])
        ev.sign(self._priv.hex())
        return ev.to_dict()

    # pynostr's RelayManager is blocking; the async client runs these in a worker thread.
    def _publish_server_list_event_blocking(
        self, relays: List[str], servers: Optional[List[str]]
    ) -> str:
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

    def _fetch_server_list_blocking(
        self, relays: List[str], pubkey: Optional[str], timeout: float
    ) -> List[str]:
        from pynostr.filters import Filters, FiltersList
        from pynostr.relay_manager import RelayManager

        target_pubkey = self._normalize_public_key_to_hex(pubkey)

        rm = RelayManager(timeout=timeout)
        rm.websocket_ping_interval = 60
        rm.websocket_ping_timeout = 60
        for r in relays:
            rm.add_relay(r)

        filters = FiltersList([Filters(authors=[target_pubkey], kinds=[SERVER_LIST_KIND], limit=1)])
        rm.add_subscription_on_all_relays(uuid.uuid4().hex, filters)
        rm.run_sync()  # establish connections & send subscription
        time.sleep(timeout)  # small wait window for events
        servers = self._extract_server_list(rm, target_pubkey)
        rm.close_all_relay_connections()
        return servers

    def _extract_server_list(self, relay_manager, target_pubkey: str) -> List[str]:
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
            # Remove checksum (last 6 values)
            payload = data[:-6]
            decoded = convertbits(payload, 5, 8, False)
            if decoded is None:
                raise ValueError("convertbits failure")
            raw = bytes(decoded)
            if len(raw) != 32:
                raise ValueError("Invalid decoded length")
            return raw.hex()
        raise ValueError("Not an npub bech32 string")
