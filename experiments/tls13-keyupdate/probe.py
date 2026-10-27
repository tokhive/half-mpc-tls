#!/usr/bin/env python3
"""Local wire-compatibility experiment, NOT an MPC implementation.

A normal TLS 1.3 handshake supplies fixture traffic secrets. A simulated Hub
receives only the next client epoch's secret for bulk encryption. The native
OpenSSL server must accept a KeyUpdate in the middle of an HTTP request.
Only disposable fixture credentials are used; no secrets are printed.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def expand_label(secret, label, length, digest):
    label = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(label)]) + label + b"\0"
    output, block = b"", b""
    for counter in range(1, (length + digest().digest_size - 1) // digest().digest_size + 1):
        block = hmac.new(secret, block + info + bytes([counter]), digest).digest()
        output += block
    return output[:length]


def keys(secret, digest, key_length):
    return (expand_label(secret, b"key", key_length, digest),
            expand_label(secret, b"iv", 12, digest))


def nonce(iv, sequence):
    return bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, "big")))


def seal(material, sequence, content, content_type=23):
    key, iv = material
    inner = content + bytes([content_type])
    header = b"\x17\x03\x03" + (len(inner) + 16).to_bytes(2, "big")
    return header + AESGCM(key).encrypt(nonce(iv, sequence), inner, header)


def open_record(material, sequence, record):
    key, iv = material
    assert len(record) == 5 + int.from_bytes(record[3:5], "big")
    inner = AESGCM(key).decrypt(nonce(iv, sequence), record[5:], record[:5])
    end = len(inner) - 1
    while end >= 0 and inner[end] == 0:
        end -= 1
    assert end >= 0
    return inner[:end], inner[end]


def must_reject(material, sequence, record):
    try:
        open_record(material, sequence, record)
    except InvalidTag:
        return
    raise AssertionError("unexpected authentication success")


def handshake(cert, key, secret_file):
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = server_context.maximum_version = ssl.TLSVersion.TLSv1_3
    server_context.load_cert_chain(cert, key)
    server_context.num_tickets = 0
    client_context = ssl.create_default_context(cafile=cert)
    client_context.minimum_version = client_context.maximum_version = ssl.TLSVersion.TLSv1_3
    client_context.keylog_filename = str(secret_file)
    ci, co, si, so = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(ci, co, server_hostname="localhost")
    server = server_context.wrap_bio(si, so, server_side=True)
    completed = [False, False]
    for _ in range(32):
        for index, endpoint in enumerate((client, server)):
            if not completed[index]:
                try:
                    endpoint.do_handshake()
                    completed[index] = True
                except ssl.SSLWantReadError:
                    pass
        if co.pending:
            si.write(co.read())
        if so.pending:
            ci.write(so.read())
        if all(completed):
            break
    assert all(completed)
    assert client.version() == "TLSv1.3"
    cipher = client.cipher()[0]
    if cipher == "TLS_AES_256_GCM_SHA384":
        digest, key_length = hashlib.sha384, 32
    elif cipher == "TLS_AES_128_GCM_SHA256":
        digest, key_length = hashlib.sha256, 16
    else:
        raise RuntimeError(f"experiment requires AES-GCM, negotiated {cipher}")
    secrets = {}
    for line in secret_file.read_text().splitlines():
        if line and not line.startswith("#"):
            label, _, value = line.split()
            secrets[label] = bytes.fromhex(value)
    secret_file.unlink()
    return client, server, ci, co, si, so, secrets, digest, key_length, cipher


def run_probe(cert, key, secret_file, body_bytes):
    client, server, ci, co, si, so, secrets, digest, key_length, cipher = handshake(cert, key, secret_file)
    old_secret = secrets["CLIENT_TRAFFIC_SECRET_0"]
    new_secret = expand_label(old_secret, b"traffic upd", digest().digest_size, digest)
    old_material, new_material = keys(old_secret, digest, key_length), keys(new_secret, digest, key_length)
    body = b'{"model":"fixture","input":"' + b"x" * body_bytes + b'"}'
    prefix = b"POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer fixture-not-a-real-credential\r\n"
    suffix = b"Content-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    assert client.write(prefix) == len(prefix)
    credential_record = co.read()
    assert open_record(old_material, 0, credential_record) == (prefix, 23)
    must_reject(new_material, 0, credential_record)
    si.write(credential_record)
    received = bytearray(server.read(16384))
    assert received == prefix
    # KeyUpdate(update_not_requested) is authenticated in the old epoch.
    update = seal(old_material, 1, b"\x18\x00\x00\x01\x00", 22)
    si.write(update)
    try:
        server.read(16384)
        raise AssertionError("KeyUpdate became HTTP application bytes")
    except ssl.SSLWantReadError:
        pass
    # No server acknowledgement is needed for update_not_requested.
    assert not so.pending
    start = time.perf_counter_ns()
    records = [seal(new_material, sequence, suffix[offset:offset+16384])
               for sequence, offset in enumerate(range(0, len(suffix), 16384))]
    encrypt_ns = time.perf_counter_ns() - start
    must_reject(old_material, 0, records[0])
    corrupted = bytearray(records[0])
    corrupted[-1] ^= 1
    must_reject(new_material, 0, bytes(corrupted))
    for record in records:
        si.write(record)
        while True:
            try:
                received.extend(server.read(16384))
            except ssl.SSLWantReadError:
                break
    assert received == prefix + suffix
    headers, received_body = bytes(received).split(b"\r\n\r\n", 1)
    assert b"Authorization: Bearer fixture-not-a-real-credential" in headers
    assert len(received_body) == len(body)
    assert json.loads(received_body)["input"] == "x" * body_bytes
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    server.write(response)
    ci.write(so.read())
    assert client.read(16384) == response
    return {"body_bytes": len(body), "cipher": cipher, "bulk_records": len(records),
            "bulk_encrypt_ms": round(encrypt_ns / 1e6, 3), "http_round_trip": "passed",
            "new_key_cannot_decrypt_credential_record": True, "tamper_rejected": True,
            "mpc_tested": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bytes", type=int, nargs="+", default=[4096, 65536, 1048576, 5242880])
    args = parser.parse_args()
    if any(size < 1 or size > 16 << 20 for size in args.bytes):
        parser.error("sizes must be between 1 and 16 MiB")
    with tempfile.TemporaryDirectory(prefix="tokenhive-keyupdate-") as directory:
        directory = Path(directory)
        cert, key = directory / "cert.pem", directory / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)
        for size in args.bytes:
            print(json.dumps(run_probe(cert, key, directory / "fixture-secrets.log", size)), flush=True)


if __name__ == "__main__":
    main()
