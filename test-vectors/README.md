# Test vectors

A golden vault + an independent second implementation of the LKv1 format,
cross-checked (DEVELOPMENT.md's verification bar).

## Files

| File | What it is |
|---|---|
| `vault-golden.bin` | Golden vault: 3 items (TOTP + notes + a password-less entry, duplicate "github.com" titles), fast test KDF (8 MiB, t=1), password `test-vector-master-password` |
| `expected.txt` | The exact content listing both readers must produce |
| `cross_check.py` | The second implementation — pure Python (`argon2-cffi`, `cryptography`, `crc32c`), zero latchkey code |

## Why

A reader/writer can always round-trip with itself; that proves nothing
about the *format*. `cross_check.py` parses VAULT_FORMAT.md and
CRYPTO_SPEC.md directly: header layout, Argon2id parameter passing
(MiB on the Rust side, KiB on the Python side), the three AAD domains,
AEAD framing, the index/item serialization, and the CRC coverage. If both
implementations agree on `vault-golden.bin`, the bytes on disk match the
spec, not just the Rust implementation's own conventions.

## Regenerating and verifying

```sh
cargo run --release --example make_test_vectors
python test-vectors/cross_check.py test-vectors/vault-golden.bin "test-vector-master-password" \
  | diff test-vectors/expected.txt -
```

`make_test_vectors` writes both the vault (fresh salts/nonces each run —
that's fine, the expected output is content, not bytes) and
`expected.txt`. The Rust-side golden tests (`tests/golden_vectors.rs`)
read the vault through the public API and additionally bit-flip a spread
of offsets (header, index, items, trailer) asserting every flip is
rejected — which is how the future-pad and trailer slot-count
authentication gaps below were found.

## Notable cross-check findings (fixed)

- The CRC covers everything **before the trailer** — the trailer's own
  slot_count is outside it (initially misread in the Python reader).
- `future_pad` (header offsets 99–117) is covered by neither the header
  AAD nor the CRC → v1 now rejects non-zero future_pad.
- The trailer slot_count is unauthenticated → now cross-checked against
  the authenticated index's live-entry count at open.
- `Vault::open` never verified the CRC at all → it now does, with the
  spec's "incomplete or still syncing" wording (torn-write detection
  before crypto errors, THREAT_MODEL §5.5).
