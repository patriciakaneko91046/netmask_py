# netmask_py

A small, dependency-free library that validates whether an IPv4 address and prefix length form a legal network, and reports any host bits set in the address.

## Usage

```python
from netmask_py import validate_network, NetworkResult

result: NetworkResult = validate_network("192.168.1.5", 24)
print(result.is_valid)          # True
print(result.network_address)   # "192.168.1.0"
print(result.prefix)            # 24
print(result.host_bits)         # [(3, 5), (3, 7)]
```

## Why this exists

When a user writes `192.168.1.5/24` in a config file, the `5` is a host bit and the value is not a network address. Most IP libraries silently mask it for you, which hides the mistake. This library validates the pair and tells you exactly which host bits were set, as `(octet_index, bit_index)` pairs (bit 0 = most-significant bit within the octet).

The trade-off: we parse the address by hand instead of using `ipaddress.IPv4Address`. The standard library parser accepts integer and hex forms (`"167837696"`, `"0x01020304"`) that are almost never intended in a config-file context and that hide typos. This library accepts only canonical dotted-decimal — four groups of 1–3 digits, no leading zeros, each in 0–255.

## Edge cases you will hit

- Leading zeros are rejected (`"192.168.01.1"` is invalid). Some platforms interpret these as octal; rejecting avoids the ambiguity.
- `bool` is explicitly rejected as a prefix, even though it is a subclass of `int` in Python.
- Prefix `0` is legal; the entire address is host bits, and a non-zero address is still valid — it just has host bits set.
- Prefix `32` has no host bits; `host_bits` is always empty.
- The unspecified address `0.0.0.0` is accepted like any other address; this library does not classify addresses as public, private, or reserved.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

