"""Test configuration and shared fixtures."""
import pytest
import sys
import os
from python_blossom.utils.png_utils import create_minimal_png
from python_blossom.errors import TooManyRequests

# Test credentials - load from environment variables (GitHub Secrets or local .env)
NSEC = os.getenv('BLOSSOM_TEST_NSEC')
PUBKEY_NPUB = os.getenv('BLOSSOM_TEST_PUBKEY_NPUB')

# Validate credentials are set
if not NSEC or not PUBKEY_NPUB:
    raise ValueError(
        "Test credentials not configured. Set BLOSSOM_TEST_NSEC and BLOSSOM_TEST_PUBKEY_NPUB "
        "environment variables (from .env file or GitHub Secrets)."
    )

# Test servers with capabilities
SERVER_CAPABILITIES = {
    'https://blossom.band': {'mirror': True, 'list_blob': True, 'auth_required': True},
    'https://nostr.download': {'mirror': False, 'list_blob': False, 'auth_required': False},
    'https://blossom.primal.net/': {'mirror': True, 'list_blob': True, 'auth_required': True}
}

# Extract server URLs - can be overridden with environment variable BLOSSOM_TEST_SERVERS
_default_servers = list(SERVER_CAPABILITIES.keys())

SERVERS = os.getenv('BLOSSOM_TEST_SERVERS', ','.join(_default_servers)).split(',')
SERVERS = [s.strip() for s in SERVERS if s.strip()]  # Clean up whitespace


def get_sorted_servers():
    """Sort servers by capability - non-mirror first, then mirror-capable.
    
    This allows tests to use SORTED_SERVERS[0] for upload and SORTED_SERVERS[-1] for mirror,
    ensuring mirror destination supports mirroring if available.
    
    Returns at least 2 servers if available, sorted by: non-mirror first, then mirror-capable.
    """
    if len(SERVERS) < 2:
        return SERVERS
    
    non_mirror = [s for s in SERVERS if not SERVER_CAPABILITIES.get(s, {}).get('mirror', False)]
    mirror = [s for s in SERVERS if SERVER_CAPABILITIES.get(s, {}).get('mirror', False)]
    
    # Return non-mirror servers first, then mirror-capable servers
    return non_mirror + mirror


SORTED_SERVERS = get_sorted_servers()

# Test relays
RELAYS = ['wss://relay.damus.io', 'wss://nos.lol']


@pytest.fixture(scope='class')
def test_image():
    """Generate a test PNG image."""
    return create_minimal_png(256, 256, 1)


def pytest_configure(config):
    """Register custom markers and initialize error tracking."""
    config.addinivalue_line(
        "markers", "rate_limited: mark test as rate limited to stop suite"
    )
    # Initialize error tracking dict on config object
    config.rate_limit_detected = False


def pytest_runtest_makereport(item, call):
    """Hook to capture test execution results and check for rate limit/Cloudflare errors."""
    config = item.config
    
    # Check if test failed
    if call.excinfo is not None:
        exc_value = call.excinfo.value
        exc_str = str(exc_value)
        
        # Check if the exception is a rate limit error (429)
        if isinstance(exc_value, TooManyRequests) or '429' in exc_str:
            config.rate_limit_detected = True
            print(f"\n⚠️  HTTP 429 Rate Limit Detected: {exc_value}")
            print("⚠️  Stopping test suite to prevent further server strain...\n")
        
        # Check if response is from Cloudflare blocking
        if 'cloudflare' in exc_str.lower() or '403 Forbidden' in exc_str:
            config.rate_limit_detected = True
            print(f"\n⚠️  Cloudflare/Block Detected: {exc_value}")
            print("⚠️  Stopping test suite - server is blocking requests...\n")


@pytest.fixture(autouse=True)
def check_rate_limit_before_test(request):
    """Auto-use fixture that stops all tests if 429 or Cloudflare error was detected."""
    config = request.config
    if getattr(config, 'rate_limit_detected', False):
        pytest.exit("Test suite stopped: Rate limit (429) or server block detected. "
                    "Stopping to prevent further server strain.", returncode=1)
