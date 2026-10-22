import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("mcbe_compat", Path(__file__).parents[1] / "scripts/mcbe_compat.py")
mc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mc)


def pe_fixture(payload=b"\x90\x48\x89\x5c\x24\x08\x90"):
    # Minimal PE32+ x64 image with one executable .text section.
    peoff = 0x80
    opt_size = 0xF0
    rawoff = 0x200
    data = bytearray(rawoff + 0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, peoff)
    data[peoff:peoff+4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, peoff+4, 0x8664, 1, 0, 0, 0, opt_size, 0)
    opt = peoff + 24
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<Q", data, opt+24, 0x140000000)
    struct.pack_into("<I", data, opt+56, 0x2000)
    struct.pack_into("<I", data, opt+60, rawoff)
    sec = opt + opt_size
    data[sec:sec+8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, sec+8, 0x200, 0x1000, 0x200, rawoff)
    struct.pack_into("<I", data, sec+36, 0x60000020)
    data[rawoff:rawoff+len(payload)] = payload
    return bytes(data)


class CompatTests(unittest.TestCase):
    def test_pe_identity_and_section_bounds(self):
        info = mc.parse_pe(pe_fixture())
        self.assertEqual(info["architecture"], "x64")
        self.assertEqual(info["sections"][0]["rva"], 0x1000)

    def test_invalid_pe_rejected(self):
        with self.assertRaises(mc.InputError):
            mc.parse_pe(b"not a PE")

    def test_pattern_match_is_unique_in_fixture(self):
        pe = pe_fixture()
        info = mc.parse_pe(pe)
        pat = mc.parse_pattern("48 89 ?? 24 08")
        found = mc.scan(pe, pat, info["sections"][0])
        self.assertEqual(found, [0x1001])

    def test_empty_or_all_wildcard_pattern_rejected(self):
        for text in ("", "?? ??"):
            with self.assertRaises(mc.InputError):
                mc.parse_pattern(text)

    def test_targets_catalogue_bootstrap_is_explicit(self):
        self.assertEqual(json.loads((Path(__file__).parents[1] / "compat/targets.json").read_text())["status"], "bootstrap_required")


if __name__ == "__main__":
    unittest.main()
