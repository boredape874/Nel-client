import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('analysis', ROOT / 'tools/bedrock_analysis.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def pe(code=b'\x48\x89\x01\x90\xc3'):
    data = bytearray(1024)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', data, 0x84, 0x8664, 1)
    struct.pack_into('<H', data, 0x94, 240)
    struct.pack_into('<H', data, 0x98, 0x20b)
    struct.pack_into('<Q', data, 0xb0, 0x140000000)
    struct.pack_into('<8sIIII', data, 0x188, b'.text', 128, 0x1000, 128, 512)
    struct.pack_into('<I', data, 0x188 + 36, 0x60000020)
    data[512:512+len(code)] = code
    return bytes(data)


def elf():
    data = bytearray(1024)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<H', data, 18, 62)
    struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<HH', data, 54, 56, 1)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 512, 0x401000, 0, 128, 128, 4096)
    return bytes(data)


class Tests(unittest.TestCase):
    def test_pe_addresses(self):
        kind, regions = a.executable_regions(pe())
        self.assertEqual(kind, 'PE-x64')
        self.assertEqual(regions[0]['rva'], 0x1000)
        self.assertEqual(regions[0]['offset'], 512)
        self.assertEqual(regions[0]['va'], 0x140001000)

    def test_elf_addresses(self):
        kind, regions = a.executable_regions(elf())
        self.assertEqual(kind, 'ELF-x64')
        self.assertEqual(regions[0]['va'], 0x401000)
        self.assertNotIn('rva', regions[0])

    def test_malformed_headers(self):
        for data in (b'MZ', b'not a binary', b'\x7fELF\x02\x01', bytes(512)):
            with self.subTest(data=data[:8]), self.assertRaises(a.Blocked):
                a.executable_regions(data)

    def test_out_of_bounds(self):
        data = bytearray(pe())
        struct.pack_into('<I', data, 0x188 + 20, 1000000)
        with self.assertRaises(a.Blocked):
            a.executable_regions(data)

    def test_wrong_architecture(self):
        data = bytearray(pe())
        struct.pack_into('<H', data, 0x84, 0x14c)
        with self.assertRaises(a.Blocked):
            a.executable_regions(data)

    def scan(self, code, pattern):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.exe'
            path.write_bytes(pe(code))
            return a.scan(path, [{'id': 'fixture', 'pattern': pattern}])['signatures'][0]

    def test_unique_signature(self):
        result = self.scan(b'\x48\x89\x01\x90\xc3', '48 89 ?? 90')
        self.assertEqual(result['status'], 'UNIQUE_CANDIDATE')
        self.assertEqual(result['matches'][0]['rva'], 0x1000)

    def test_missing_signature(self):
        self.assertEqual(self.scan(b'\xc3', '48 89 ?? 90')['status'], 'MISSING')

    def test_overlapping_signature(self):
        result = self.scan(b'\xaa' * 5, 'AA AA AA AA')
        self.assertEqual(len(result['matches']), 2)
        self.assertEqual(result['status'], 'AMBIGUOUS')

    def test_saturated_signature(self):
        result = self.scan(b'\xaa' * 100, 'AA AA AA AA')
        self.assertTrue(result['count_is_lower_bound'])
        self.assertEqual(len(result['matches']), 16)

    def test_invalid_patterns(self):
        for pattern in ('?? ?? ?? ??', 'GG 00 11 22', '90', 'A? 00 11 22'):
            with self.subTest(pattern=pattern), self.assertRaises(a.Blocked):
                self.scan(b'\xc3', pattern)

    def test_zip_exact_member_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            z = root / 'input.zip'
            with zipfile.ZipFile(z, 'w') as out:
                out.writestr('Minecraft.Windows.exe', pe())
                out.writestr('../escape.exe', b'ignored')
            a.extract_member(z, 'Minecraft.Windows.exe', root / 'target.exe')
            self.assertEqual((root / 'target.exe').read_bytes(), pe())
            self.assertFalse((root.parent / 'escape.exe').exists())

    def test_zip_missing_member(self):
        with tempfile.TemporaryDirectory() as directory:
            z = Path(directory) / 'input.zip'
            with zipfile.ZipFile(z, 'w') as out:
                out.writestr('wrong.exe', pe())
            with self.assertRaises(a.Blocked):
                a.extract_member(z, 'Minecraft.Windows.exe', Path(directory) / 'out.exe')

    def test_url_policy(self):
        a.check_url('https://example.com/file?a=secret', {'example.com'}, resolve=False)
        for url in ('http://example.com/a', 'https://example.com.evil/a', 'https://x:y@example.com/a', 'https://example.com:22/a'):
            with self.subTest(url=url), self.assertRaises(a.Blocked):
                a.check_url(url, {'example.com'}, resolve=False)

    def test_private_ip_blocked(self):
        with patch.object(a.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('127.0.0.1', 443))]):
            with self.assertRaises(a.Blocked):
                a.check_url('https://example.com/a', {'example.com'})

    def test_sha256(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(b'abc')
            self.assertEqual(a.sha256(path), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    def test_client_requires_approved_hosts(self):
        with patch.dict(a.os.environ, {}, clear=True), self.assertRaises(a.Blocked):
            a.client_entries()

    def test_toolchain_is_pinned(self):
        settings = json.loads((ROOT / 'analysis/settings.json').read_text())
        self.assertRegex(settings['ghidriff_image'], r'@sha256:[0-9a-f]{64}$')
        self.assertLess(settings['deep_timeout_seconds'], 7200)


if __name__ == '__main__':
    unittest.main()
