"""Core validation logic for netmask_py.

This module validates that an IP address and prefix length form a legal
network and, if so, identifies any host bits that are set in the address.

Design decision: we parse the IP address by hand using bytes.fromhex
rather than using ipaddress.IPv4Address. The reason is that
ipaddress.IPv4Address happily accepts forms like "1", "167837696", and
"0x01020304" (decimal and hex integers). For a *netmask* validator that
is a footgun: those forms are almost never what a user editing a config
file means, and they hide typos. By accepting only dotted-decimal we
fail loudly on the ambiguous forms.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkResult:
    """Outcome of validating a network address and prefix.

    Attributes:
        is_valid: True when the address parses and is legal for the prefix.
        network_address: The masked address as a dotted-quad string, or None
            when invalid. Masking is applied unconditionally so callers get a
            normalised value regardless of whether host bits were set.
        prefix: The prefix length as an int, or None when invalid.
        host_bits: A list of (octet_index, bit_index) tuples marking host
            bits that were set in the original address. Bit indices are 0..7
            within the octet, 0 being the most-significant bit. Empty list
            when invalid (no address to inspect) or when no host bits are set.
    """

    is_valid: bool
    network_address: str | None
    prefix: int | None
    host_bits: list[tuple[int, int]]


def _parse_octet(token: str) -> int | None:
    """Parse a single dotted-quad octet.

    Returns the integer value, or None if the token is not a valid octet.
    A valid octet is 1 to 3 ASCII digits forming a number in 0..255 with no
    leading zero (e.g. "01" is rejected) and no sign or whitespace.

    Leading zeros are rejected because they are a common source of
    copy-paste errors (e.g. "192.168.001.001") and because some platforms
    interpret leading-zero strings as octal — a source of silent misconfig.
    """
    if not token or not token.isascii() or not token.isdigit():
        return None
    if len(token) > 1 and token[0] == "0":
        return None
    if len(token) > 3:
        return None
    value = int(token)
    if value > 255:
        return None
    return value


def _parse_ipv4(address: str) -> tuple[int, int, int, int] | None:
    """Parse a dotted-decimal IPv4 address.

    Returns a 4-tuple of octet integers, or None if the string is not a
    valid dotted-quad address in canonical dotted-decimal form.
    """
    if not isinstance(address, str):
        return None
    if not address.isascii():
        return None
    parts = address.split(".")
    if len(parts) != 4:
        return None
    if any(part == "" for part in parts):
        return None
    octets = [_parse_octet(p) for p in parts]
    if any(o is None for o in octets):
        return None
    return (octets[0], octets[1], octets[2], octets[3])  # type: ignore[return-value]


def _parse_prefix(prefix: int | str) -> int | None:
    """Parse a prefix length.

    Accepts an int in 0..32 or a decimal string of such an int (no leading
    zeros, no sign). Returns the int, or None if invalid.
    """
    if isinstance(prefix, bool):
        return None
    if isinstance(prefix, int):
        if 0 <= prefix <= 32:
            return prefix
        return None
    if isinstance(prefix, str):
        if not prefix or not prefix.isascii() or not prefix.isdigit():
            return None
        if len(prefix) > 1 and prefix[0] == "0":
            return None
        value = int(prefix)
        if 0 <= value <= 32:
            return value
        return None
    return None


def validate_network(address: str, prefix: int | str) -> NetworkResult:
    """Validate an IPv4 address and prefix length as a network.

    Args:
        address: A dotted-decimal IPv4 address (e.g. "192.168.1.0").
        prefix: The prefix length, as an int (0..32) or a decimal string.

    Returns:
        A NetworkResult. When invalid, all fields are None/empty except
        is_valid which is False. When valid, network_address is the masked
        address (host bits zeroed) and host_bits lists the (octet, bit)
        positions of host bits that were set in the input address.

    Edge cases:
        - Prefix 0 means the entire address is host bits; a non-zero
          address is still *valid* (it just has host bits set).
        - Prefix 32 has no host bits, so host_bits is always empty.
        - The IPv4 unspecified address "0.0.0.0" is accepted like any
          other address; this library does not classify addresses as
          public, private, or reserved.
    """
    octets = _parse_ipv4(address)
    pfx = _parse_prefix(prefix)

    if octets is None or pfx is None:
        return NetworkResult(
            is_valid=False,
            network_address=None,
            prefix=None,
            host_bits=[],
        )

    masked = [0, 0, 0, 0]
    host_bits: list[tuple[int, int]] = []

    for i, octet in enumerate(octets):
        for bit in range(8):
            bit_index_in_address = i * 8 + bit
            is_network_bit = bit_index_in_address < pfx
            if is_network_bit:
                # Bit falls within the network prefix → keep it in the mask.
                if octet & (0x80 >> bit):
                    masked[i] |= 0x80 >> bit
            else:
                # Bit is a host bit. If it is set in the input, record it.
                if octet & (0x80 >> bit):
                    host_bits.append((i, bit))

    network_address = ".".join(str(m) for m in masked)

    return NetworkResult(
        is_valid=True,
        network_address=network_address,
        prefix=pfx,
        host_bits=host_bits,
    )
