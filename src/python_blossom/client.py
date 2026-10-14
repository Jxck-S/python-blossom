"""Synchronous Blossom client."""

from typing import Any, Dict, List, Optional

import httpx

from ._base import (  # noqa: F401  (re-exported for backwards compatibility)
    AUTH_KIND,
    DEFAULT_EXPIRATION_SECONDS,
    DEFAULT_TIMEOUT,
    SERVER_LIST_KIND,
    Blob,
    TimeoutTypes,
    _BaseBlossomClient,
    _read_file,
    _Request,
    _to_httpx_timeout,
)


class BlossomClient(_BaseBlossomClient):
    """High-level synchronous Blossom protocol client.

    Holds a pooled ``httpx.Client``; use it as a context manager or call ``close()``
    when done to release connections.

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
        http_client: Optional[httpx.Client] = None,
    ):
        """Initialize client.

        :param nsec: Private key in any format (nsec or hex). If omitted, only public endpoints can be used.
        :param default_servers: Ordered list of Blossom server base URLs (no trailing slash).
        :param expiration_seconds: Expiration time for auth events.
        :param timeout: Timeout in seconds for all HTTP requests (default 30s). Accepts a float,
            a ``(connect, read)`` tuple, an ``httpx.Timeout`` or None. Ignored if ``http_client`` is given.
        :param http_client: Optional pre-configured ``httpx.Client`` (proxies, custom transport...).
            The caller owns it and is responsible for closing it.
        """
        super().__init__(nsec, default_servers, expiration_seconds, timeout)
        self._owns_http = http_client is None
        self._http = http_client or httpx.Client(
            timeout=_to_httpx_timeout(timeout), follow_redirects=True
        )

    def close(self) -> None:
        """Close the underlying HTTP connection pool (if this client created it)."""
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> "BlossomClient":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def _send(self, req: _Request) -> httpx.Response:
        return self._http.request(
            req.method, req.url, headers=req.headers, content=req.content, params=req.params
        )

    # ----------------------- Endpoint Methods -----------------------
    # BUD-02 + BUD-01: Upload blob
    def upload_blob(
        self,
        server: Optional[str],
        data: Optional[bytes] = None,
        file_path: Optional[str] = None,
        mime_type: Optional[str] = None,
        description: Optional[str] = None,
        use_auth: bool = True,
    ) -> Dict[str, Any]:
        """Upload a blob (PUT /upload). Provide either data or file_path.

        :param server: Blossom server base URL. If None, uses first default server.
        :param data: Raw binary blob.
        :param file_path: Path to file to read.
        :param mime_type: Content-Type header value (auto-detected if None).
        :param description: Human readable description for auth event.
        :param use_auth: Whether to attach authorization event.
        :return: Blob Descriptor dict.
        """
        server = self._resolve_server(server)
        self._check_one_source(data, file_path)
        if file_path:
            data = _read_file(file_path)
        req, parse = self._prep_upload(server, data, file_path, mime_type, description, use_auth)
        return parse(self._send(req))

    # Convenience: upload to all default servers
    def upload_to_all(
        self,
        data: Optional[bytes] = None,
        file_path: Optional[str] = None,
        mime_type: Optional[str] = None,
        description: Optional[str] = None,
        use_auth: bool = True,
    ) -> Dict[str, Dict[str, Any]]:
        """Upload a blob to every default server, one after another.

        For concurrent uploads use ``AsyncBlossomClient.upload_to_all``.

        :return: Dict mapping server URL to blob descriptor, or ``{"error": str}`` on failure.
        """
        self._check_one_source(data, file_path)
        if file_path:
            data = _read_file(file_path)
        reqs, parse = self._prep_upload_to_all(data, file_path, mime_type, description, use_auth)
        results = {}
        for server, req in reqs:
            try:
                results[server] = parse(self._send(req))
            except Exception as e:
                results[server] = {"error": str(e)}
        return results

    # BUD-01: GET /<sha256>
    def get_blob(
        self,
        server: str,
        sha256: str,
        extension: Optional[str] = None,
        use_auth: bool = False,
        mime_type: Optional[str] = None,
    ) -> Blob:
        """Download a blob from server.

        :param server: Server URL.
        :param sha256: Blob hash.
        :param extension: Optional file extension for URL.
        :param use_auth: Whether to include authorization.
        :param mime_type: Optional MIME type. If omitted, defaults to application/octet-stream.
        :return: Blob object with content and metadata.
        """
        req, parse = self._prep_get_blob(server, sha256, extension, use_auth, mime_type)
        return parse(self._send(req))

    # BUD-01: HEAD /<sha256>
    def head_blob(
        self, server: str, sha256: str, extension: Optional[str] = None, use_auth: bool = False
    ) -> Dict[str, Any]:
        """Get blob metadata without downloading it (HEAD /<sha256>)."""
        req, parse = self._prep_head_blob(server, sha256, extension, use_auth)
        return parse(self._send(req))

    # BUD-02: GET /list/<pubkey>
    def list_blobs(
        self,
        server: str,
        pubkey: Optional[str] = None,
        cursor: Optional[str] = None,
        limit: Optional[int] = None,
        use_auth: bool = False,
    ) -> List[Dict[str, Any]]:
        """List blobs for a user.

        :param server: Server URL
        :param pubkey: Public key in any format (npub or hex). If None, uses client's public key.
        :param cursor: Pagination cursor
        :param limit: Limit number of results
        :param use_auth: Whether to include authorization
        :return: List of blob descriptors
        """
        req, parse = self._prep_list_blobs(server, pubkey, cursor, limit, use_auth)
        return parse(self._send(req))

    # BUD-02: DELETE /<sha256>
    def delete_blob(
        self, server: str, sha256: str, description: Optional[str] = None
    ) -> Dict[str, Any]:
        """Delete a blob (DELETE /<sha256>). Requires a private key."""
        req, parse = self._prep_delete_blob(server, sha256, description)
        return parse(self._send(req))

    # BUD-04: PUT /mirror
    def mirror_blob(
        self, server: str, source_url: str, sha256: str, description: Optional[str] = None
    ) -> Dict[str, Any]:
        """Ask ``server`` to mirror a blob from ``source_url`` (PUT /mirror)."""
        req, parse = self._prep_mirror_blob(server, source_url, sha256, description)
        return parse(self._send(req))

    # BUD-06: HEAD /upload (requirements)
    def head_upload_requirements(
        self, server: str, data: bytes, mime_type: Optional[str] = None, use_auth: bool = False
    ) -> Dict[str, Any]:
        """Check upload requirements for a blob.

        :param server: Server URL
        :param data: Blob data as bytes
        :param mime_type: MIME type of the blob (auto-detected if None)
        :param use_auth: Whether to include authorization
        :return: Dictionary of response headers
        """
        req, parse = self._prep_head_upload_requirements(server, data, mime_type, use_auth)
        return parse(self._send(req))

    # BUD-05: Media optimization endpoints (optional)
    def media_upload(
        self,
        server: str,
        data: bytes,
        mime_type: Optional[str] = None,
        description: Optional[str] = None,
        use_auth: bool = True,
    ) -> Dict[str, Any]:
        """Upload a blob for media optimization (PUT /media)."""
        req, parse = self._prep_media_upload(server, data, mime_type, description, use_auth)
        return parse(self._send(req))

    def media_head(
        self, server: str, data: bytes, mime_type: Optional[str] = None, use_auth: bool = True
    ) -> Dict[str, Any]:
        """Check media optimization support for a blob.

        :param server: Server URL
        :param data: Blob data as bytes
        :param mime_type: MIME type of the blob (auto-detected if None)
        :param use_auth: Whether to include authorization (default True, required by servers)
        :return: Dictionary of response headers
        """
        req, parse = self._prep_media_head(server, data, mime_type, use_auth)
        return parse(self._send(req))

    # BUD-03: Publish User Server List event to relays
    def publish_server_list_event(
        self, relays: List[str], servers: Optional[List[str]] = None
    ) -> str:
        """Generate and publish a server list event to relays.

        :param relays: List of relay URLs (wss://) to publish to
        :param servers: Optional list of server URLs; defaults to self.default_servers
        :return: Event ID of the published event
        """
        return self._publish_server_list_event_blocking(relays, servers)

    # BUD-03: Fetch a user's server list (kind 10063) from relays
    def fetch_server_list(
        self, relays: List[str], pubkey: Optional[str] = None, timeout: float = 2.0
    ) -> List[str]:
        """Query relays for latest kind 10063 server list event for a user.

        :param relays: List of relay URLs to query (wss://)
        :param pubkey: Public key in any format (npub or hex). If None, uses client's public key.
        :param timeout: Timeout in seconds for relay queries
        :return: List of server URLs from the user's server list event
        """
        return self._fetch_server_list_blocking(relays, pubkey, timeout)

    # TODO: BUD-09 - PUT /report endpoint (report abuse/misinformation)
