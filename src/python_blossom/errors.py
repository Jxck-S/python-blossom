"""Blossom HTTP error classes and status code handling."""

from typing import Optional


class BlossomError(Exception):
    """Base exception for Blossom errors."""
    def __init__(self, message: str, status_code: Optional[int] = None, reason: Optional[str] = None):
        self.status_code = status_code
        self.reason = reason
        super().__init__(message)


# 400 - Bad Request errors
class BadRequest(BlossomError):
    """400 Bad Request - The request was malformed or missing required parameters."""
    pass


class InvalidHash(BadRequest):
    """400 - Provided sha256 hash is invalid or doesn't match the blob."""
    pass


class InvalidMimeType(BadRequest):
    """400 - The Content-Type header is invalid or not supported."""
    pass


class InvalidUrl(BadRequest):
    """400 - The provided URL is invalid or malformed."""
    pass


# 401 - Unauthorized errors
class Unauthorized(BlossomError):
    """401 Unauthorized - Authorization header is missing or invalid."""
    pass


class InvalidAuthorizationEvent(Unauthorized):
    """401 - Authorization event is invalid, expired, or doesn't match the request."""
    pass


class InvalidSignature(Unauthorized):
    """401 - The authorization event signature is invalid."""
    pass


class ExpiredAuthorization(Unauthorized):
    """401 - The authorization event has expired."""
    pass


class UnauthorizedVerb(Unauthorized):
    """401 - The authorization event's verb doesn't match the endpoint (e.g., 'upload' instead of 'delete')."""
    pass


# 402 - Payment Required
class PaymentRequired(BlossomError):
    """402 Payment Required - The server requires payment for this operation."""
    pass


# 403 - Forbidden
class Forbidden(BlossomError):
    """403 Forbidden - The server refuses to perform the request (e.g., server is full)."""
    pass


# 404 - Not Found
class NotFound(BlossomError):
    """404 Not Found - The blob or endpoint does not exist."""
    pass


class BlobNotFound(NotFound):
    """404 - The blob with the specified sha256 hash was not found."""
    pass


class EndpointNotSupported(NotFound):
    """404 - The requested endpoint is not supported by this server."""
    pass


# 413 - Payload Too Large
class PayloadTooLarge(BlossomError):
    """413 Payload Too Large - The blob exceeds the server's maximum size limit."""
    pass


# 414 - URI Too Long
class UriTooLong(BlossomError):
    """414 URI Too Long - The request URI is too long."""
    pass


# 415 - Unsupported Media Type
class UnsupportedMediaType(BlossomError):
    """415 Unsupported Media Type - The Content-Type is not supported by the server."""
    pass


# 429 - Too Many Requests
class TooManyRequests(BlossomError):
    """429 Too Many Requests - Rate limit exceeded. The client should back off."""
    pass


# 500 - Internal Server Error
class InternalServerError(BlossomError):
    """500 Internal Server Error - The server encountered an error."""
    pass


# 502 - Bad Gateway
class BadGateway(BlossomError):
    """502 Bad Gateway - The server received an invalid response from upstream."""
    pass


# 503 - Service Unavailable
class ServiceUnavailable(BlossomError):
    """503 Service Unavailable - The server is temporarily unavailable."""
    pass


# Mirror-specific errors
class MirrorError(BlossomError):
    """Error during mirror operation."""
    pass


class RemoteBlobNotFound(MirrorError):
    """The blob at the source URL could not be accessed or downloaded."""
    pass


class MirrorHashMismatch(MirrorError):
    """The sha256 hash of the downloaded blob doesn't match the expected hash."""
    pass


class MirrorUnauthorized(MirrorError):
    """401 - Authorization event doesn't have matching x tag for the blob being mirrored."""
    pass


def get_error_from_status(status_code: int, reason: str) -> BlossomError:
    """Get the appropriate error class based on HTTP status code.
    
    :param status_code: HTTP status code
    :param reason: Error reason from X-Reason header or response body
    :return: Appropriate BlossomError subclass instance
    """
    # Format the error message with status code and reason
    error_message = f"HTTP {status_code}: {reason}"
    
    if status_code == 400:
        if 'sha256' in reason.lower() or 'hash' in reason.lower():
            return InvalidHash(error_message, status_code, reason)
        elif 'mime' in reason.lower() or 'type' in reason.lower():
            return InvalidMimeType(error_message, status_code, reason)
        elif 'url' in reason.lower():
            return InvalidUrl(error_message, status_code, reason)
        else:
            return BadRequest(error_message, status_code, reason)
    
    elif status_code == 401:
        if 'signature' in reason.lower():
            return InvalidSignature(error_message, status_code, reason)
        elif 'expir' in reason.lower():
            return ExpiredAuthorization(error_message, status_code, reason)
        elif 'verb' in reason.lower() or 'tag' in reason.lower():
            return UnauthorizedVerb(error_message, status_code, reason)
        elif 'x tag' in reason.lower():
            return MirrorUnauthorized(error_message, status_code, reason)
        else:
            return InvalidAuthorizationEvent(error_message, status_code, reason)
    
    elif status_code == 402:
        return PaymentRequired(error_message, status_code, reason)
    
    elif status_code == 403:
        return Forbidden(error_message, status_code, reason)
    
    elif status_code == 404:
        if 'mirror' in reason.lower() or 'endpoint' in reason.lower():
            return EndpointNotSupported(error_message, status_code, reason)
        else:
            return BlobNotFound(error_message, status_code, reason)
    
    elif status_code == 413:
        return PayloadTooLarge(error_message, status_code, reason)
    
    elif status_code == 414:
        return UriTooLong(error_message, status_code, reason)
    
    elif status_code == 415:
        return UnsupportedMediaType(error_message, status_code, reason)
    
    elif status_code == 429:
        return TooManyRequests(error_message, status_code, reason)
    
    elif status_code == 500:
        return InternalServerError(error_message, status_code, reason)
    
    elif status_code == 502:
        return BadGateway(error_message, status_code, reason)
    
    elif status_code == 503:
        return ServiceUnavailable(error_message, status_code, reason)
    
    else:
        return BlossomError(error_message, status_code, reason)
