"""Asynchronous Blossom client."""

import asyncio
from typing import Any, Dict, List, Optional

import httpx

from ._base import (
    DEFAULT_EXPIRATION_SECONDS,
    DEFAULT_TIMEOUT,
    Blob,
    TimeoutTypes,
    _BaseBlossomClient,
    _read_file,
    _Request,
    _to_httpx_timeout,
)


class AsyncBlossomClient(_BaseBlossomClient):
    """High-level asyncio Blossom protocol client.

    Same methods and return values as ``BlossomClient``, but awaitable. Holds a pooled
    ``httpx.AsyncClient``; use ``async with`` or call ``await client.aclose()`` when done.

    ``upload_to_all`` uploads to every default server concurrently.
    """

    def __init__(
        self,
        nsec: Optional[str] = None,
        default_servers: Optional[List[str]] = None,
        expiration_seconds: int = DEFAULT_EXPIRATION_SECONDS,
        timeout: TimeoutTypes = DEFAULT_TIMEOUT,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        """Initialize async client.

        :param nsec: Private key in any format (nsec or hex). If omitted, only public endpoints can be used.
        :param default_servers: Ordered list of Blossom server base URLs (no trailing slash).
        :param expiration_seconds: Expiration time for auth events.
        :param timeout: Timeout in seconds for all HTTP requests (default 30s). Accepts a float,
            a ``(connect, read)`` tuple, an ``httpx.Timeout`` or None. Ignored if ``http_client`` is given.
        :param http_client: Optional pre-configured ``httpx.AsyncClient``.
            The caller owns it and is responsible for closing it.
        """
        super().__init__(nsec, default_servers, expiration_seconds, timeout)
        self._owns_http = http_client is None
        self._http = http_client or httpx.AsyncClient(
            timeout=_to_httpx_timeout(timeout), follow_redirects=True
        )

    async def aclose(self) -> None:
        """Close the underlying HTTP connection pool (if this client created it)."""
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> "AsyncBlossomClient":
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()

    async def _send(self, req: _Request) -> httpx.Response:
        return await self._http.request(
            req.method, req.url, headers=req.headers, content=req.content, params=req.params
        )

    # ----------------------- Endpoint Methods -----------------------
    async def upload_blob(
        self,
        server: Optional[str],
        data: Optional[bytes] = None,
        file_path: Optional[str] = None,
        mime_type: Optional[str] = None,
        description: Optional[str] = None,
        use_auth: bool = True,
    ) -> Dict[str, Any]:
        """Upload a blob (PUT /upload). Provide either data or file_path.

        See ``BlossomClient.upload_blob``.
        """
        server = self._resolve_server(server)
        self._check_one_source(data, file_path)
        if file_path:
            data = await asyncio.to_thread(_read_file, file_path)
        req, parse = self._prep_upload(server, data, file_path, mime_type, description, use_auth)
        return parse(await self._send(req))

    async def upload_to_all(
        self,
        data: Optional[bytes] = None,
        file_path: Optional[str] = None,
        mime_type: Optional[str] = None,
        description: Optional[str] = None,
        use_auth: bool = True,
        max_concurrency: Optional[int] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """Upload a blob to every default server concurrently.

        The file is read, hashed and signed once, then sent to all servers in parallel.

        :param max_concurrency: Optional cap on simultaneous uploads (default: all at once).
        :return: Dict mapping server URL to blob descriptor, or ``{"error": str}`` on failure.
        """
        self._check_one_source(data, file_path)
        if file_path:
            data = await asyncio.to_thread(_read_file, file_path)
        reqs, parse = self._prep_upload_to_all(data, file_path, mime_type, description, use_auth)
        sem = asyncio.Semaphore(max_concurrency or len(reqs))

        async def one(req: _Request) -> Dict[str, Any]:
            async with sem:
                try:
                    return parse(await self._send(req))
                except Exception as e:
                    return {"error": str(e)}

        results = await asyncio.gather(*(one(req) for _, req in reqs))
        return {server: result for (server, _), result in zip(reqs, results)}

    async def get_blob(
        self,
        server: str,
        sha256: str,
        extension: Optional[str] = None,
        use_auth: bool = False,
        mime_type: Optional[str] = None,
    ) -> Blob:
        """Download a blob (GET /<sha256>). See ``BlossomClient.get_blob``."""
        req, parse = self._prep_get_blob(server, sha256, extension, use_auth, mime_type)
        return parse(await self._send(req))

    async def head_blob(
        self, server: str, sha256: str, extension: Optional[str] = None, use_auth: bool = False
    ) -> Dict[str, Any]:
        """Get blob metadata without downloading it (HEAD /<sha256>)."""
        req, parse = self._prep_head_blob(server, sha256, extension, use_auth)
        return parse(await self._send(req))

    async def list_blobs(
        self,
        server: str,
        pubkey: Optional[str] = None,
        cursor: Optional[str] = None,
        limit: Optional[int] = None,
        use_auth: bool = False,
    ) -> List[Dict[str, Any]]:
        """List blobs for a user (GET /list/<pubkey>). See ``BlossomClient.list_blobs``."""
        req, parse = self._prep_list_blobs(server, pubkey, cursor, limit, use_auth)
        return parse(await self._send(req))

    async def delete_blob(
        self, server: str, sha256: str, description: Optional[str] = None
    ) -> Dict[str, Any]:
        """Delete a blob (DELETE /<sha256>). Requires a private key."""
        req, parse = self._prep_delete_blob(server, sha256, description)
        return parse(await self._send(req))

    async def mirror_blob(
        self, server: str, source_url: str, sha256: str, description: Optional[str] = None
    ) -> Dict[str, Any]:
        """Ask ``server`` to mirror a blob from ``source_url`` (PUT /mirror)."""
        req, parse = self._prep_mirror_blob(server, source_url, sha256, description)
        return parse(await self._send(req))

    async def head_upload_requirements(
        self, server: str, data: bytes, mime_type: Optional[str] = None, use_auth: bool = False
    ) -> Dict[str, Any]:
        """Check upload requirements for a blob (HEAD /upload)."""
        req, parse = self._prep_head_upload_requirements(server, data, mime_type, use_auth)
        return parse(await self._send(req))

    async def media_upload(
        self,
        server: str,
        data: bytes,
        mime_type: Optional[str] = None,
        description: Optional[str] = None,
        use_auth: bool = True,
    ) -> Dict[str, Any]:
        """Upload a blob for media optimization (PUT /media)."""
        req, parse = self._prep_media_upload(server, data, mime_type, description, use_auth)
        return parse(await self._send(req))

    async def media_head(
        self, server: str, data: bytes, mime_type: Optional[str] = None, use_auth: bool = True
    ) -> Dict[str, Any]:
        """Check media optimization support for a blob (HEAD /media)."""
        req, parse = self._prep_media_head(server, data, mime_type, use_auth)
        return parse(await self._send(req))

    # pynostr's RelayManager is blocking, so run it off the event loop.
    async def publish_server_list_event(
        self, relays: List[str], servers: Optional[List[str]] = None
    ) -> str:
        """Generate and publish a server list event (kind 10063) to relays."""
        return await asyncio.to_thread(self._publish_server_list_event_blocking, relays, servers)

    async def fetch_server_list(
        self, relays: List[str], pubkey: Optional[str] = None, timeout: float = 2.0
    ) -> List[str]:
        """Query relays for a user's latest kind 10063 server list."""
        return await asyncio.to_thread(self._fetch_server_list_blocking, relays, pubkey, timeout)
