"""Offline tests for BlossomClient and AsyncBlossomClient.

Every test runs against both clients through httpx.MockTransport, so no network or
credentials are needed. They check that both clients build the same requests and
parse responses the same way.
"""
import asyncio
import base64
import hashlib
import inspect
import json
import threading
import time

import httpx
import pytest

from python_blossom import AsyncBlossomClient, BlossomClient, DEFAULT_TIMEOUT
from python_blossom.errors import BlobNotFound, BlossomError, InternalServerError

KEY_HEX = "01" * 32
SERVERS = ["https://a.example", "https://b.example", "https://c.example"]
DATA = b"\x89PNG fake image bytes"
SHA = hashlib.sha256(DATA).hexdigest()


def descriptor(server):
    return {"sha256": SHA, "url": f"{server}/{SHA}", "size": len(DATA), "type": "image/png"}


def decode_auth(request):
    scheme, b64 = request.headers["Authorization"].split(" ", 1)
    assert scheme == "Nostr"
    return json.loads(base64.b64decode(b64))


def tag_values(event, name):
    return [t[1] for t in event["tags"] if t[0] == name]


def make_client(kind, handler, **kwargs):
    """Build a sync or async client whose HTTP calls go to ``handler``."""
    kwargs.setdefault("nsec", KEY_HEX)
    kwargs.setdefault("default_servers", SERVERS)
    transport = httpx.MockTransport(handler)
    if kind == "sync":
        http = httpx.Client(transport=transport, follow_redirects=True)
        return BlossomClient(http_client=http, **kwargs)
    http = httpx.AsyncClient(transport=transport, follow_redirects=True)
    return AsyncBlossomClient(http_client=http, **kwargs)


async def call(client, method, *args, **kwargs):
    result = getattr(client, method)(*args, **kwargs)
    return await result if inspect.isawaitable(result) else result


@pytest.fixture(params=["sync", "async"])
def kind(request):
    return request.param


class Recorder:
    """MockTransport handler that records requests and returns canned responses."""

    def __init__(self, respond):
        self.requests = []
        self.respond = respond

    def __call__(self, request):
        self.requests.append(request)
        return self.respond(request)


# ----------------------- Endpoints -----------------------
async def test_upload_blob_builds_signed_put(kind):
    rec = Recorder(lambda r: httpx.Response(200, json=descriptor(SERVERS[0])))
    client = make_client(kind, rec)

    result = await call(client, "upload_blob", SERVERS[0], data=DATA)

    assert result == descriptor(SERVERS[0])
    (req,) = rec.requests
    assert req.method == "PUT"
    assert str(req.url) == f"{SERVERS[0]}/upload"
    assert req.headers["Content-Type"] == "image/png"  # detected from magic bytes
    assert req.content == DATA
    event = decode_auth(req)
    assert event["kind"] == 24242
    assert tag_values(event, "t") == ["upload"]
    assert tag_values(event, "x") == [SHA]


async def test_upload_blob_from_file(kind, tmp_path):
    path = tmp_path / "photo.jpg"
    path.write_bytes(DATA)
    rec = Recorder(lambda r: httpx.Response(200, json=descriptor(SERVERS[0])))
    client = make_client(kind, rec)

    await call(client, "upload_blob", None, file_path=str(path))

    (req,) = rec.requests
    assert str(req.url) == f"{SERVERS[0]}/upload"  # falls back to first default server
    assert req.headers["Content-Type"] == "image/jpeg"  # extension wins over magic bytes
    assert req.content == DATA


async def test_upload_blob_requires_exactly_one_source(kind):
    client = make_client(kind, Recorder(lambda r: httpx.Response(200)))
    with pytest.raises(BlossomError, match="Exactly one"):
        await call(client, "upload_blob", SERVERS[0])
    with pytest.raises(BlossomError, match="Exactly one"):
        await call(client, "upload_blob", SERVERS[0], data=DATA, file_path="x")


async def test_upload_requires_key(kind):
    client = make_client(kind, Recorder(lambda r: httpx.Response(200)), nsec=None)
    with pytest.raises(BlossomError, match="Private key required"):
        await call(client, "upload_blob", SERVERS[0], data=DATA)


async def test_get_blob_follows_redirect(kind):
    def respond(request):
        if request.url.host == "a.example":
            return httpx.Response(302, headers={"Location": f"https://cdn.example/{SHA}"})
        return httpx.Response(200, content=DATA, headers={"Content-Type": "image/png"})

    rec = Recorder(respond)
    client = make_client(kind, rec)

    blob = await call(client, "get_blob", SERVERS[0], SHA, mime_type="image/png")

    assert blob.content == DATA and blob.sha256 == SHA and blob.get_extension() == "png"
    assert [r.url.host for r in rec.requests] == ["a.example", "cdn.example"]
    assert "Authorization" not in rec.requests[0].headers


async def test_get_blob_rejects_json(kind):
    client = make_client(kind, Recorder(lambda r: httpx.Response(200, json={"oops": 1})))
    with pytest.raises(BlossomError, match="Expected binary blob"):
        await call(client, "get_blob", SERVERS[0], SHA)


async def test_http_errors_map_to_blossom_errors(kind):
    client = make_client(
        kind, Recorder(lambda r: httpx.Response(404, headers={"X-Reason": "blob missing"}))
    )
    with pytest.raises(BlobNotFound, match="HTTP 404: blob missing"):
        await call(client, "get_blob", SERVERS[0], SHA)
    with pytest.raises(BlobNotFound):
        await call(client, "head_blob", SERVERS[0], SHA)


async def test_head_blob(kind):
    headers = {"Content-Type": "image/png", "Content-Length": "22", "Accept-Ranges": "bytes"}
    rec = Recorder(lambda r: httpx.Response(200, headers=headers))
    client = make_client(kind, rec)

    meta = await call(client, "head_blob", SERVERS[0], SHA, extension="png")

    assert meta == {"content_type": "image/png", "content_length": "22", "accept_ranges": "bytes"}
    assert rec.requests[0].method == "HEAD"
    assert str(rec.requests[0].url) == f"{SERVERS[0]}/{SHA}.png"


async def test_list_blobs(kind):
    client_key = BlossomClient(nsec=KEY_HEX).pubkey_hex
    rec = Recorder(lambda r: httpx.Response(200, json=[descriptor(SERVERS[0])]))
    client = make_client(kind, rec)

    blobs = await call(client, "list_blobs", SERVERS[0], cursor="abc", limit=5, use_auth=True)

    assert blobs == [descriptor(SERVERS[0])]
    req = rec.requests[0]
    assert req.url.path == f"/list/{client_key}"
    assert dict(req.url.params) == {"cursor": "abc", "limit": "5"}
    assert tag_values(decode_auth(req), "t") == ["list"]


async def test_list_blobs_rejects_non_list(kind):
    client = make_client(kind, Recorder(lambda r: httpx.Response(200, json={"not": "a list"})))
    with pytest.raises(BlossomError, match="Expected list"):
        await call(client, "list_blobs", SERVERS[0])


async def test_delete_blob_empty_body(kind):
    rec = Recorder(lambda r: httpx.Response(200))
    client = make_client(kind, rec)

    result = await call(client, "delete_blob", SERVERS[0], SHA)

    assert result == {"status": "deleted", "sha256": SHA}
    assert rec.requests[0].method == "DELETE"
    assert tag_values(decode_auth(rec.requests[0]), "t") == ["delete"]


async def test_mirror_blob_sends_json(kind):
    rec = Recorder(lambda r: httpx.Response(200, json=descriptor(SERVERS[1])))
    client = make_client(kind, rec)
    source = f"{SERVERS[0]}/{SHA}"

    await call(client, "mirror_blob", SERVERS[1], source, SHA)

    req = rec.requests[0]
    assert str(req.url) == f"{SERVERS[1]}/mirror"
    assert req.headers["Content-Type"] == "application/json"
    assert json.loads(req.content) == {"url": source}
    assert tag_values(decode_auth(req), "x") == [SHA]


@pytest.mark.parametrize(
    "method,path,verb", [("head_upload_requirements", "upload", None), ("media_head", "media", "media")]
)
async def test_requirement_heads(kind, method, path, verb):
    rec = Recorder(lambda r: httpx.Response(200, headers={"X-Reason": "ok"}))
    client = make_client(kind, rec)

    result = await call(client, method, SERVERS[0], DATA)

    req = rec.requests[0]
    assert req.method == "HEAD" and req.url.path == f"/{path}"
    assert req.headers["X-SHA-256"] == SHA
    assert req.headers["X-Content-Length"] == str(len(DATA))
    assert req.headers["X-Content-Type"] == "image/png"
    assert result["x_reason"] == "ok"
    # head_upload_requirements defaults to no auth, media_head to auth
    if verb:
        assert tag_values(decode_auth(req), "t") == [verb]
    else:
        assert "Authorization" not in req.headers


async def test_media_upload(kind):
    rec = Recorder(lambda r: httpx.Response(200, json=descriptor(SERVERS[0])))
    client = make_client(kind, rec)

    await call(client, "media_upload", SERVERS[0], DATA)

    req = rec.requests[0]
    assert req.method == "PUT" and req.url.path == "/media"
    assert tag_values(decode_auth(req), "t") == ["media"]


# ----------------------- upload_to_all -----------------------
async def test_upload_to_all_partial_failure_and_single_signature(kind):
    def respond(request):
        if request.url.host == "b.example":
            return httpx.Response(500, headers={"X-Reason": "disk full"})
        return httpx.Response(200, json=descriptor(f"https://{request.url.host}"))

    rec = Recorder(respond)
    client = make_client(kind, rec)

    results = await call(client, "upload_to_all", data=DATA)

    assert list(results) == SERVERS
    assert results[SERVERS[0]] == descriptor(SERVERS[0])
    assert results[SERVERS[1]] == {"error": "HTTP 500: disk full"}
    assert results[SERVERS[2]] == descriptor(SERVERS[2])
    # Hashed and signed once, reused for every server
    assert len({r.headers["Authorization"] for r in rec.requests}) == 1


async def test_upload_to_all_needs_servers(kind):
    client = make_client(kind, Recorder(lambda r: httpx.Response(200)), default_servers=[])
    with pytest.raises(BlossomError, match="No default servers"):
        await call(client, "upload_to_all", data=DATA)


async def test_async_upload_to_all_is_concurrent():
    in_flight = 0
    peak = 0

    async def respond(request):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.2)
        in_flight -= 1
        return httpx.Response(200, json=descriptor(SERVERS[0]))

    client = make_client("async", respond)
    start = time.perf_counter()
    await client.upload_to_all(data=DATA)
    elapsed = time.perf_counter() - start

    assert peak == len(SERVERS)
    assert elapsed < 0.2 * len(SERVERS)


async def test_async_upload_to_all_respects_max_concurrency():
    in_flight = 0
    peak = 0

    async def respond(request):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.05)
        in_flight -= 1
        return httpx.Response(200, json=descriptor(SERVERS[0]))

    client = make_client("async", respond)
    await client.upload_to_all(data=DATA, max_concurrency=1)
    assert peak == 1


# ----------------------- Relays run off the event loop -----------------------
async def test_async_relay_methods_run_in_worker_thread(monkeypatch):
    loop_thread = threading.get_ident()
    seen = {}

    def fake_publish(self, relays, servers):
        seen["publish"] = threading.get_ident()
        return "event-id"

    def fake_fetch(self, relays, pubkey, timeout):
        seen["fetch"] = threading.get_ident()
        return SERVERS

    monkeypatch.setattr(AsyncBlossomClient, "_publish_server_list_event_blocking", fake_publish)
    monkeypatch.setattr(AsyncBlossomClient, "_fetch_server_list_blocking", fake_fetch)
    client = AsyncBlossomClient(nsec=KEY_HEX, default_servers=SERVERS)

    assert await client.publish_server_list_event(["wss://relay.example"]) == "event-id"
    assert await client.fetch_server_list(["wss://relay.example"]) == SERVERS
    assert seen["publish"] != loop_thread and seen["fetch"] != loop_thread
    await client.aclose()


# ----------------------- Configuration & lifecycle -----------------------
def test_timeout_defaults_and_tuple_compat():
    client = BlossomClient()
    assert client.timeout == DEFAULT_TIMEOUT
    assert client._http.timeout.read == DEFAULT_TIMEOUT

    client = BlossomClient(timeout=(5, 60))
    assert client._http.timeout.connect == 5
    assert client._http.timeout.read == 60

    client = AsyncBlossomClient(timeout=None)
    assert client._http.timeout.read is None


def test_sync_context_manager_closes_owned_client_only():
    with BlossomClient() as client:
        pass
    assert client._http.is_closed

    http = httpx.Client()
    with BlossomClient(http_client=http):
        pass
    assert not http.is_closed
    http.close()


async def test_async_context_manager_closes_owned_client_only():
    async with AsyncBlossomClient() as client:
        pass
    assert client._http.is_closed

    http = httpx.AsyncClient()
    async with AsyncBlossomClient(http_client=http):
        pass
    assert not http.is_closed
    await http.aclose()


def test_api_parity():
    def public(cls):
        return {n for n in dir(cls) if not n.startswith("_") and callable(getattr(cls, n))}

    sync_only = {"close"}
    async_only = {"aclose"}
    assert public(BlossomClient) - sync_only == public(AsyncBlossomClient) - async_only


def test_generate_server_list_event_shared():
    event = AsyncBlossomClient(nsec=KEY_HEX, default_servers=SERVERS).generate_server_list_event()
    assert event["kind"] == 10063
    assert tag_values(event, "server") == SERVERS
