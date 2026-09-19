"""
Base64 utilities for the encryptorx library.
"""
import base64


def b64_encode(text: str) -> str:
    """
    Encode a UTF-8 string to a standard Base64 string.

    Args:
        text: The plain text to encode.

    Returns:
        A Base64-encoded string.

    Example:
        >>> import encryptorx
        >>> encryptorx.b64_encode("Hello")
        'SGVsbG8='
    """
    if not text:
        return ""
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")


def b64_decode(b64_text: str) -> str:
    """
    Decode a Base64 string back to a UTF-8 string.

    Args:
        b64_text: A Base64-encoded string.

    Returns:
        The decoded plain text string.

    Raises:
        ValueError: If the input is not valid Base64 or not valid UTF-8.

    Example:
        >>> import encryptorx
        >>> encryptorx.b64_decode("SGVsbG8=")
        'Hello'
    """
    if not b64_text:
        return ""
    try:
        return base64.b64decode(b64_text).decode("utf-8")
    except Exception as e:
        raise ValueError(f"Invalid Base64 string: {e}") from e


def b64_encode_bytes(data: bytes) -> str:
    """
    Encode raw bytes to a Base64 string.

    Args:
        data: The bytes to encode.

    Returns:
        A Base64-encoded string.
    """
    if not data:
        return ""
    return base64.b64encode(data).decode("utf-8")


def b64_decode_bytes(b64_text: str) -> bytes:
    """
    Decode a Base64 string to raw bytes.

    Args:
        b64_text: A Base64-encoded string.

    Returns:
        The decoded bytes.

    Raises:
        ValueError: If the input is not valid Base64.
    """
    if not b64_text:
        return b""
    try:
        return base64.b64decode(b64_text)
    except Exception as e:
        raise ValueError(f"Invalid Base64 string: {e}") from e


def is_valid_base64(text: str) -> bool:
    """
    Check whether a string is valid Base64.

    Args:
        text: The string to check.

    Returns:
        True if the string is valid Base64, False otherwise.

    Example:
        >>> import encryptorx
        >>> encryptorx.is_valid_base64("SGVsbG8=")
        True
        >>> encryptorx.is_valid_base64("not-base64!!!")
        False
    """
    try:
        base64.b64decode(text, validate=True)
        return True
    except Exception:
        return False
