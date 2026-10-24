import unittest

from netmask_py import NetworkResult, validate_network


class TestParseOctet(unittest.TestCase):
    """Exercise _parse_ipv4 via validate_network's rejection of bad octets."""

    def test_three_digit_octet_allowed(self):
        r = validate_network("255.255.255.255", 24)
        self.assertTrue(r.is_valid)
        self.assertEqual(r.network_address, "255.255.255.0")

    def test_octet_too_large(self):
        r = validate_network("256.1.1.1", 24)
        self.assertFalse(r.is_valid)

    def test_octet_leading_zero_rejected(self):
        r = validate_network("192.168.01.1", 24)
        self.assertFalse(r.is_valid)

    def test_octet_empty_rejected(self):
        r = validate_network("192.168..1", 24)
        self.assertFalse(r.is_valid)

    def test_non_digit_rejected(self):
        r = validate_network("192.168.a.1", 24)
        self.assertFalse(r.is_valid)

    def test_too_few_octets(self):
        r = validate_network("192.168.1", 24)
        self.assertFalse(r.is_valid)

    def test_too_many_octets(self):
        r = validate_network("192.168.1.1.1", 24)
        self.assertFalse(r.is_valid)


class TestPrefixParsing(unittest.TestCase):
    def test_prefix_as_int(self):
        r = validate_network("10.0.0.0", 8)
        self.assertTrue(r.is_valid)
        self.assertEqual(r.prefix, 8)

    def test_prefix_as_string(self):
        r = validate_network("10.0.0.0", "8")
        self.assertTrue(r.is_valid)
        self.assertEqual(r.prefix, 8)

    def test_prefix_leading_zero_rejected(self):
        r = validate_network("10.0.0.0", "08")
        self.assertFalse(r.is_valid)

    def test_prefix_too_large(self):
        r = validate_network("10.0.0.0", 33)
        self.assertFalse(r.is_valid)

    def test_prefix_negative(self):
        r = validate_network("10.0.0.0", -1)
        self.assertFalse(r.is_valid)

    def test_prefix_non_numeric_string(self):
        r = validate_network("10.0.0.0", "abc")
        self.assertFalse(r.is_valid)

    def test_prefix_bool_rejected(self):
        # bool is a subclass of int; we explicitly reject it to avoid
        # silently accepting True as prefix 1.
        r = validate_network("10.0.0.0", True)
        self.assertFalse(r.is_valid)


class TestHostBitDetection(unittest.TestCase):
    def test_no_host_bits(self):
        r = validate_network("192.168.1.0", 24)
        self.assertTrue(r.is_valid)
        self.assertEqual(r.network_address, "192.168.1.0")
        self.assertEqual(r.host_bits, [])

    def test_host_bits_in_last_octet(self):
        r = validate_network("192.168.1.5", 24)
        self.assertTrue(r.is_valid)
        self.assertEqual(r.network_address, "192.168.1.0")
        # 5 = 0b00000101 → bits 5 and 7 (0-indexed from MSB within octet 3)
        self.assertEqual(r.host_bits, [(3, 5), (3, 7)])

    def test_host_bits_spanning_octets(self):
        # Prefix 22 → first 22 bits are network.
        # Octet 2 (index 2) has its last 2 bits as host bits.
        # Address 192.168.3.0: octet 2 = 3 = 0b00000011.
        # Bit 6 and bit 7 of octet 2 are host bits and both are set.
        r = validate_network("192.168.3.0", 22)
        self.assertTrue(r.is_valid)
        self.assertEqual(r.network_address, "192.168.0.0")
        self.assertEqual(r.host_bits, [(2, 6), (2, 7)])

    def test_prefix_zero_all_host_bits(self):
        # Prefix 0 → entire address is host bits.
        # 1.2.3.4: octet 0=1=0b00000001 → bit 7 set;
        # octet 1=2=0b00000010 → bit 6 set;
        # octet 2=3=0b00000011 → bits 6,7 set;
        # octet 3=4=0b00000100 → bit 5 set.
        r = validate_network("1.2.3.4", 0)
        self.assertTrue(r.is_valid)
        self.assertEqual(r.network_address, "0.0.0.0")
        self.assertEqual(
            r.host_bits,
            [(0, 7), (1, 6), (2, 6), (2, 7), (3, 5)],
        )

    def test_prefix_zero_address_zero(self):
        r = validate_network("0.0.0.0", 0)
        self.assertTrue(r.is_valid)
        self.assertEqual(r.network_address, "0.0.0.0")
        self.assertEqual(r.host_bits, [])

    def test_prefix_32_no_host_bits(self):
        r = validate_network("192.168.1.1", 32)
        self.assertTrue(r.is_valid)
        self.assertEqual(r.network_address, "192.168.1.1")
        self.assertEqual(r.host_bits, [])

    def test_all_host_bits_set(self):
        # 255 = 0b11111111, prefix 24 → all 8 host bits set in octet 3.
        r = validate_network("10.0.0.255", 24)
        self.assertTrue(r.is_valid)
        self.assertEqual(r.network_address, "10.0.0.0")
        self.assertEqual(
            r.host_bits,
            [(3, 0), (3, 1), (3, 2), (3, 3), (3, 4), (3, 5), (3, 6), (3, 7)],
        )


class TestResultShape(unittest.TestCase):
    def test_invalid_result_fields(self):
        r = validate_network("bad", 24)
        self.assertFalse(r.is_valid)
        self.assertIsNone(r.network_address)
        self.assertIsNone(r.prefix)
        self.assertEqual(r.host_bits, [])

    def test_network_address_is_string(self):
        r = validate_network("192.168.1.0", 24)
        self.assertIsInstance(r.network_address, str)

    def test_prefix_is_int(self):
        r = validate_network("192.168.1.0", 24)
        self.assertIsInstance(r.prefix, int)

    def test_result_is_network_result(self):
        r = validate_network("192.168.1.0", 24)
        self.assertIsInstance(r, NetworkResult)


if __name__ == "__main__":
    unittest.main()
