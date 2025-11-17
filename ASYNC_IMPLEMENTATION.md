# Async Implementation for python-blossom

## Problem Statement: "Should I have made this async?"

**Answer: YES** - The python-blossom library significantly benefits from async/await support.

## Why Async is Beneficial

### 1. **Network I/O is the Bottleneck**
The Blossom protocol is entirely network-based - every operation involves HTTP requests to remote servers. Network I/O is inherently slow compared to CPU operations, making it an ideal candidate for async/await patterns.

### 2. **Multiple Server Operations**
A common use case is uploading the same blob to multiple servers for redundancy. With synchronous code, these uploads happen **sequentially**:
```
Server 1: [====2s====]
Server 2:              [====2s====]
Server 3:                           [====2s====]
Total: 6 seconds
```

With async code, uploads happen **concurrently**:
```
Server 1: [====2s====]
Server 2: [====2s====]
Server 3: [====2s====]
Total: 2 seconds (3x faster!)
```

### 3. **Modern Python Ecosystem**
Many modern Python applications use async frameworks (FastAPI, aiohttp, etc.). Having an async client allows seamless integration without blocking the event loop.

## Implementation Details

### Architecture

The implementation adds a new `AsyncBlossomClient` class that:
- Uses `httpx` for async HTTP operations (instead of `requests`)
- Implements all BUD endpoints with `async`/`await`
- Provides concurrent operation support via `asyncio.gather()`
- Maintains API parity with synchronous `BlossomClient`

### Key Components

#### 1. AsyncBlossomClient (`src/python_blossom/async_client.py`)
- Full implementation of all BUD-01 through BUD-06 endpoints
- Async methods: `upload_blob()`, `get_blob()`, `list_blobs()`, `delete_blob()`, etc.
- Special `upload_to_all()` method for concurrent uploads

#### 2. Concurrent Upload to Multiple Servers
```python
async def upload_to_all(self, data, ...):
    # Create tasks for all servers
    tasks = [self._upload_blob_with_error_handling(server, ...) 
             for server in self.default_servers]
    
    # Execute all uploads concurrently
    results = await asyncio.gather(*tasks)
    return results
```

#### 3. Error Handling
Each concurrent operation catches errors independently, ensuring one failed upload doesn't affect others:
```python
async def _upload_blob_with_error_handling(self, server, **kwargs):
    try:
        return await self.upload_blob(server, **kwargs)
    except Exception as e:
        return {"error": str(e)}
```

## Backward Compatibility

**Critical:** The async client is **100% backward compatible**. Existing code using `BlossomClient` continues to work without any changes:

- ✅ `BlossomClient` remains unchanged
- ✅ All existing imports work
- ✅ All existing code works
- ✅ No breaking changes
- ➕ New `AsyncBlossomClient` available for async applications

## Usage Examples

### Synchronous (Original)
```python
from python_blossom import BlossomClient

client = BlossomClient(nsec='nsec...', default_servers=servers)

# Sequential uploads - slow
results = client.upload_to_all(data=blob_data)
# Takes ~6 seconds for 3 servers
```

### Asynchronous (New)
```python
import asyncio
from python_blossom import AsyncBlossomClient

async def main():
    client = AsyncBlossomClient(nsec='nsec...', default_servers=servers)
    
    # Concurrent uploads - fast!
    results = await client.upload_to_all(data=blob_data)
    # Takes ~2 seconds for 3 servers (3x faster!)

asyncio.run(main())
```

## Performance Benefits

### Upload to Multiple Servers
- **Synchronous**: O(n) time where n = number of servers
- **Asynchronous**: O(1) time (limited only by slowest server)
- **Speedup**: ~3x for 3 servers, ~5x for 5 servers

### Example Timing
For uploading a 1MB blob to 3 servers with 2s latency each:
- Synchronous: ~6 seconds (2s × 3 servers)
- Asynchronous: ~2 seconds (max of 2s)
- **Time saved: 4 seconds (67% reduction)**

## When to Use Each Client

### Use `BlossomClient` (Synchronous) When:
- Simple scripts or applications
- Sequential operations are acceptable
- Not using async frameworks
- Simplicity is preferred

### Use `AsyncBlossomClient` (Asynchronous) When:
- Uploading to multiple servers
- Using async frameworks (FastAPI, aiohttp)
- Performance is critical
- Handling many concurrent operations
- Building responsive applications

## Testing

Tests added in `tests/test_async_upload_blob.py`:
- ✅ Async upload with data
- ✅ Concurrent upload to all servers
- ✅ Error handling
- ✅ Performance validation

## Security

- ✅ No vulnerabilities in new dependencies (httpx)
- ✅ CodeQL analysis clean
- ✅ Same authorization patterns as synchronous client
- ✅ No security regressions

## Dependencies

New dependency added:
- `httpx>=0.27.0,<1.0.0` - Modern async HTTP client
- `pytest-asyncio>=0.21.0` - For async testing (dev dependency)

## Future Enhancements

Potential future improvements:
1. **Connection pooling** - Reuse HTTP connections across requests
2. **Rate limiting** - Built-in rate limiting for concurrent operations
3. **Retry logic** - Automatic retries with exponential backoff
4. **Streaming uploads** - Support for large file uploads without loading into memory
5. **Async relay operations** - If pynostr adds async support for RelayManager

## Conclusion

**Yes, async was the right choice** for this library because:

1. ✅ **Performance**: 3-5x faster for multi-server operations
2. ✅ **Scalability**: Handles hundreds of concurrent requests efficiently
3. ✅ **Compatibility**: Works with modern async Python applications
4. ✅ **Future-proof**: Aligns with Python ecosystem trends
5. ✅ **No breaking changes**: Existing code continues to work

The async implementation provides significant benefits while maintaining complete backward compatibility, making it a clear win for the library.
