#!/usr/bin/env python3
"""Extract public JA3/JA4 fields from a captured, plaintext TLS ClientHello record.

Input must be this engine's actual capture, not a reconstructed OpenSSL profile.
The hashes are identifiers, not authentication or an upstream risk-score claim.
JA4 source: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
"""
import argparse
import hashlib
import json
from pathlib import Path


class Reader:
    def __init__(self, data):
        self.data = data

    def take(self, count):
        if count < 0 or len(self.data) < count:
            raise ValueError('truncated ClientHello')
        result, self.data = self.data[:count], self.data[count:]
        return result

    def number(self, size):
        return int.from_bytes(self.take(size), 'big')

    def vector(self, size):
        return self.take(self.number(size))

    def end(self):
        if self.data:
            raise ValueError('trailing ClientHello bytes')


def u16s(data):
    if len(data) % 2:
        raise ValueError('odd TLS vector')
    return [int.from_bytes(data[i:i+2], 'big') for i in range(0, len(data), 2)]


def grease(value):
    return value & 0x0f0f == 0x0a0a and value >> 8 == value & 255


def fingerprint(record):
    outer = Reader(record)
    if outer.take(1) != b'\x16':
        raise ValueError('not a handshake record')
    outer.take(2)
    payload = outer.vector(2)
    outer.end()
    handshake = Reader(payload)
    if handshake.take(1) != b'\x01':
        raise ValueError('not ClientHello')
    reader = Reader(handshake.vector(3))
    handshake.end()
    version = reader.number(2)
    reader.take(32)
    reader.vector(1)
    ciphers = [v for v in u16s(reader.vector(2)) if not grease(v)]
    reader.vector(1)
    ext_reader = Reader(reader.vector(2))
    reader.end()
    extensions = {}
    while ext_reader.data:
        kind = ext_reader.number(2)
        if kind in extensions:
            raise ValueError('duplicate TLS extension')
        extensions[kind] = ext_reader.vector(2)
    ordered = [v for v in extensions if not grease(v)]
    def vector(kind, size):
        if kind not in extensions:
            return b''
        r = Reader(extensions[kind])
        result = r.vector(size)
        r.end()
        return result
    groups = [v for v in u16s(vector(10, 2)) if not grease(v)]
    points = list(vector(11, 1))
    signatures = [v for v in u16s(vector(13, 2)) if not grease(v)]
    versions = [v for v in u16s(vector(43, 1)) if not grease(v)]
    alpn_reader = Reader(vector(16, 2))
    alpns = []
    while alpn_reader.data:
        alpns.append(alpn_reader.vector(1))
    alpn = alpns[0] if alpns else b''
    if alpn:
        encoded = alpn.decode('ascii', errors='replace')
        alpn_code = encoded[0]+encoded[-1] if encoded.isascii() and encoded.isalnum() else alpn.hex()[0]+alpn.hex()[-1]
        if alpn == b'http/1.1':
            alpn_code = 'h1'
    else:
        alpn_code = '00'
    selected = max(versions or [version])
    tls_code = {0x0304: '13', 0x0303: '12'}.get(selected, '00')
    a = f't{tls_code}{"d" if 0 in extensions else "i"}{min(len(ciphers),99):02d}{min(len(ordered),99):02d}{alpn_code}'
    b_raw = ','.join(f'{v:04x}' for v in sorted(ciphers))
    c_raw = ','.join(f'{v:04x}' for v in sorted(ordered) if v not in (0, 16))
    if signatures:
        c_raw += '_'+','.join(f'{v:04x}' for v in signatures)
    digest = lambda value: hashlib.sha256(value.encode()).hexdigest()[:12]
    ja3 = ','.join([str(version), '-'.join(map(str,ciphers)), '-'.join(map(str,ordered)), '-'.join(map(str,groups)), '-'.join(map(str,points))])
    return {'ja3_raw': ja3, 'ja3': hashlib.md5(ja3.encode(), usedforsecurity=False).hexdigest(),
            'ja4': f'{a}_{digest(b_raw)}_{digest(c_raw)}', 'ja4_b_raw': b_raw, 'ja4_c_raw': c_raw,
            'ciphers': ciphers, 'extensions': ordered, 'groups': groups, 'signature_algorithms': signatures,
            'alpn': [v.decode('ascii', errors='replace') for v in alpns],
            'basis': 'captured plaintext ClientHello; no API credential or TLS traffic secret'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    args = parser.parse_args()
    if args.capture.stat().st_size > 65540:
        parser.error('ClientHello record exceeds bound')
    print(json.dumps(fingerprint(args.capture.read_bytes()), indent=2))
