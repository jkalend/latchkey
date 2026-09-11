#!/usr/bin/env python3
"""Independent RPv1 vault reader — the second implementation for the
test-vector cross-check (DEVELOPMENT.md).

Parses and decrypts a vault file using Python's `cryptography` and
`argon2-cffi` — no rpass code involved. Used to prove the Rust
implementation reads and writes the format that VAULT_FORMAT.md
specifies, not merely the format it itself produces.

Layout (VAULT_FORMAT §3-§7):
  [0    .. 117       ]  header
  [117  ..           ]  index frame: 12B nonce || 4B ct_len || ct+tag
  [..                ]  u32 slot_count || per-slot frames (same framing)
  [last 8            ]  u32 slot_count || u32 crc32c

Header fields (offsets):
  0..3    magic "RPv"          3     version 0x01
  4       kdf_id (0x01)        5     wrap_alg_id   6     item_alg_id
  7..10   reserved              10..14 argon2_m_mib (u32 BE)
  14..18  argon2_t (u32 BE)    18    argon2_p (u8)
  19..35  kdf_salt (16B)       35..39 enc_counter (u32 BE)
  39..51  wrap_nonce (12B)     51..83 wrapped_dek (32B)
  83..99  wrap_tag (16B)       99..117 future_pad (18B)

AAD domains (CRYPTO_SPEC §5): header = bytes[4..51]; index = [version, 0x49];
item = [version, 0x53, item_id_be].
"""

import struct
import sys

import argon2.low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

HEADER_LEN = 117
ALGS = {0x01: ("aes-256-gcm", AESGCM), 0x02: ("chacha20-poly1305", ChaCha20Poly1305)}


class VaultError(Exception):
    pass


def u32be(b, off):
    return struct.unpack_from(">I", b, off)[0]


def parse_header(data):
    if len(data) < HEADER_LEN:
        raise VaultError("file too short for header")
    if data[0:3] != b"RPv":
        raise VaultError("bad magic")
    if data[3] != 0x01:
        raise VaultError(f"unsupported version 0x{data[3]:02x}")
    return {
        "kdf_id": data[4],
        "wrap_alg_id": data[5],
        "item_alg_id": data[6],
        "m_mib": u32be(data, 10),
        "t": u32be(data, 14),
        "p": data[18],
        "salt": data[19:35],
        "enc_counter": u32be(data, 35),
        "wrap_nonce": data[39:51],
        "wrapped_dek": data[51:83],
        "wrap_tag": data[83:99],
    }


def derive_kek(password, m_mib, t, p, salt):
    return argon2.low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=t,
        memory_cost=m_mib * 1024,  # Rust side takes MiB, argon2-cffi KiB
        parallelism=p,
        hash_len=32,
        type=argon2.low_level.Type.ID,
    )


def unwrap_dek(header, password):
    name, cls = ALGS[header["wrap_alg_id"]]
    kek = derive_kek(
        password, header["m_mib"], header["t"], header["p"], header["salt"]
    )
    ct = header["wrapped_dek"] + header["wrap_tag"]
    aad = header_bytes_for_aad(header)
    return cls(kek).decrypt(header["wrap_nonce"], ct, aad)


def header_bytes_for_aad(h):
    # offsets 4..51 of the on-disk header — rebuilt from the parsed fields.
    return (
        bytes([h["kdf_id"], h["wrap_alg_id"], h["item_alg_id"]])
        + b"\x00\x00\x00"
        + struct.pack(">I", h["m_mib"])
        + struct.pack(">I", h["t"])
        + bytes([h["p"]])
        + h["salt"]
        + struct.pack(">I", h["enc_counter"])
        + h["wrap_nonce"]
    )


def read_frames(data, off):
    """One AEAD frame: 12B nonce || u32 ct_len || ct+tag. Returns (nonce, ct)."""
    nonce = data[off : off + 12]
    ct_len = u32be(data, off + 12)
    ct = data[off + 16 : off + 16 + ct_len]
    return nonce, ct, off + 16 + ct_len


def decrypt_vault(path, password):
    """Full read: header → KEK → DEK → index → items. Returns (entries, items).

    entries: list of dicts (item_id, slot, state, title, username)
    items:   {item_id: record dict} — password/url/notes/totp/created/modified
    """
    data = open(path, "rb").read()
    header = parse_header(data)
    dek = unwrap_dek(header, password)
    _, item_cls = ALGS[header["item_alg_id"]]
    item_aead = item_cls(dek)

    # Trailer: u32 slot_count || u32 crc32c over the whole file before the
    # trailer (header + index + items region — the slot_count itself is
    # outside the CRC's coverage, per the Rust writer's behavior).
    trailer_count = u32be(data, len(data) - 8)
    import crc32c

    if crc32c.crc32c(data[:-8]) != u32be(data, len(data) - 4):
        raise VaultError("crc32c mismatch")

    # Index frame.
    off = HEADER_LEN
    nonce, ct, off = read_frames(data, off)
    index_pt = item_aead.decrypt(nonce, ct, bytes([0x01, 0x49]))

    entries = []
    n = struct.unpack_from(">I", index_pt, 0)[0]
    cur = 4
    for _ in range(n):
        item_id, slot = struct.unpack_from(">II", index_pt, cur)
        state = index_pt[cur + 8]
        cur += 9
        tlen = struct.unpack_from(">H", index_pt, cur)[0]
        cur += 2
        title = index_pt[cur : cur + tlen].decode()
        cur += tlen
        ulen = struct.unpack_from(">H", index_pt, cur)[0]
        cur += 2
        username = index_pt[cur : cur + ulen].decode()
        cur += ulen
        entries.append(
            {
                "item_id": item_id,
                "slot": slot,
                "state": state,
                "title": title,
                "username": username,
            }
        )

    # Items region: u32 slot_count || frames (frame position == slot).
    items_count = u32be(data, off)
    off += 4
    if items_count != trailer_count:
        raise VaultError("slot count mismatch between items region and trailer")
    items = {}
    for slot in range(items_count):
        nonce, ct, off = read_frames(data, off)
        # The index tells us which item_id lives at this slot.
        entry = next(e for e in entries if e["slot"] == slot)
        aad = bytes([0x01, 0x53]) + struct.pack(">I", entry["item_id"])
        pt = item_aead.decrypt(nonce, ct, aad)
        items[entry["item_id"]] = parse_item(pt)

    return entries, items


def parse_item(pt):
    """ItemRecord: password? || url || notes? || totp? || created || modified || item_id."""
    cur = 0

    def opt_bytes():
        nonlocal cur
        if pt[cur] == 0:
            cur += 1
            return None
        cur += 1
        ln = struct.unpack_from(">I", pt, cur)[0]
        cur += 4
        b = pt[cur : cur + ln]
        cur += ln
        return b

    password = opt_bytes()
    ulen = struct.unpack_from(">H", pt, cur)[0]
    cur += 2
    url = pt[cur : cur + ulen].decode()
    cur += ulen
    notes = opt_bytes()
    if pt[cur] == 0:
        cur += 1
        totp = None
    else:
        cur += 1
        slen = struct.unpack_from(">I", pt, cur)[0]
        cur += 4
        secret = pt[cur : cur + slen]
        cur += slen
        period, digits = struct.unpack_from(">II", pt, cur)
        cur += 8
        alg = {0x01: "SHA1", 0x02: "SHA256", 0x03: "SHA512"}[pt[cur]]
        cur += 1
        totp = {
            "secret": secret,
            "period": period,
            "digits": digits,
            "algorithm": alg,
        }
    created, modified, item_id = struct.unpack_from(">QQI", pt, cur)
    return {
        "password": password,
        "url": url,
        "notes": notes,
        "totp": totp,
        "created_unix": created,
        "modified_unix": modified,
        "item_id": item_id,
    }


def main():
    if len(sys.argv) != 3:
        print("usage: cross_check.py <vault-file> <password>", file=sys.stderr)
        return 2
    entries, items = decrypt_vault(sys.argv[1], sys.argv[2].encode())
    for e in entries:
        rec = items[e["item_id"]]
        pw = rec["password"].decode() if rec["password"] else None
        totp = rec["totp"]["algorithm"] if rec["totp"] else None
        print(
            f"{e['item_id']:>3} {e['title']:<24} {e['username']:<12} "
            f"pw={pw!r} url={rec['url']!r} totp={totp} "
            f"notes={rec['notes']!r} created={rec['created_unix']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
