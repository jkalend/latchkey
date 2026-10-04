# Vault File Format

**Status:** Public-preview implementation (`latchkey` 0.4.1)
**Covers:** Format version 2 (`LKv` magic + binary version byte `0x02`)
**Companion specs:** [CRYPTO_SPEC.md](CRYPTO_SPEC.md), [THREAT_MODEL.md](THREAT_MODEL.md)

> This is a byte-level specification. The success criterion: an
> implementer with no access to this codebase can read this document and
> produce a compatible reader/writer. All multi-byte integers are
> **big-endian**. Offsets are from the start of the file unless stated.

---

## 1. Design constraints driving the layout

1. **Per-item encryption** — each item is an independent AEAD ciphertext.
   Rationale: item-level nonces (CRYPTO_SPEC §5), partial decryption for
   `list`/TUI without touching secrets, and crash-safe single-item rewrites.
2. **Sensitive metadata is encrypted** — titles and usernames live in the
   encrypted index (THREAT_MODEL §5.4). Slot count and ciphertext lengths
   remain visible as framing metadata.
3. **Safe as an opaque file under naive sync** — a partially-synced file
   must fail authentication cleanly, never yield garbage.
4. **Upgradable parameters** — KDF params and algorithm IDs live in the
   header, readable without a key, so upgrades don't require decryption.

## 2. File layout (overview)

```
┌───────────────────────────┐  offset 0
│  Magic + version ("LKv")  │  3-byte magic + binary version 0x02
├───────────────────────────┤
│  Fixed header             │  crypto parameters + wrapped DEK, 117 total
├───────────────────────────┤
│  Index (encrypted)        │  one AEAD ciphertext; maps ids → slots
├───────────────────────────┤
│  Items (encrypted)        │  N independent AEAD ciphertexts
├───────────────────────────┤
│  Trailer                  │  u32 slot count + u32 CRC32C + 32-byte file MAC
└───────────────────────────┘
```

Readers and writers enforce the same **64 MiB total-file limit**, including the
header, index, all frames, and 40-byte trailer. Writers preflight the candidate
size before encryption and refuse oversize replacements; the previous vault
remains usable. This bound prevents corrupt or hostile files causing unbounded
allocation.

## 3. Magic and version

```
Offset  Length  Value
0       3       "LKv"                    (0x4C 0x4B 0x76)
3       1       version byte, 0x02
```

- A wrong magic is a clean "not a vault" error.
- Normal readers accept only version 2. Version 1 is never opened or upgraded
  implicitly; use `latchkey --vault OLD migrate --out NEW` (§9).
- Magic and version select the parser; unknown values are rejected.
- Magic, version, and `future_pad` are outside the wrapped-DEK AAD but are
  covered by the whole-file MAC (§7). `future_pad` must still be all zero.

## 4. Header

### 4.1 Layout

**Fixed-size header, 117 bytes total.** A length-prefixed (TLV) design was
considered and rejected: a fixed layout is simplest to authenticate as one
AAD range, and any field addition requires a version bump anyway
(§9.1).

```
Offset  Length  Field
0       4       magic + version (copied; §3)
4       1       kdf_id       (0x01 = Argon2id)
5       1       wrap_alg_id  (0x01 = AES-256-GCM, 0x02 = ChaCha20-Poly1305)
6       1       item_alg_id  (same encoding as wrap_alg_id)
7       3       reserved     (writers set [0xA5, 0, 0]; v2 always uses separate tags)
10      4       argon2_m     (MiB, u32; must be ≥ 8)
14      4       argon2_t     (iterations, u32; must be ≥ 1)
18      1       argon2_p     (lanes, u8; must be ≥ 1)
19      16      kdf_salt     (random per vault)
35      4       enc_counter  (u32 — encryptions under current DEK; §5)
39      12      wrap_nonce   (96-bit random nonce for KEK-wrapped DEK)
51      32      wrapped_dk   (DEK ciphertext — 32-byte DEK)
83      16      wrap_tag     (AEAD tag over the wrapped-DEK record)
99      18      future_pad   (zero; extensions require a version bump)
```

`wrapped_dk` holds the 32-byte DEK ciphertext; `wrap_tag` is the separate
16-byte AEAD tag over the wrapped-DEK record (the tag is not appended to
`wrapped_dk`). Total header size is **117 bytes**; §4.3 defines the
authenticated subset.

### 4.2 Field semantics

- `argon2_m/t/p` — the exact parameters used to derive the KEK from the
  master password. Stored plaintext deliberately: needed before any key
  exists. Read-time floors and resource ceilings are enforced before
  Argon2 runs (CRYPTO_SPEC §3).
- `kdf_salt` — 128-bit, CSPRNG, generated at `init`, never reused across
  vaults.
- `enc_counter` — counts **every index and item AEAD encryption under the DEK**.
  Creation starts at 1 (the initial empty index). Every save consumes 1 for the
  index, plus 1 for each rewritten live or tombstone frame; copied frames and
  KEK wraps do not consume DEK encryptions. A candidate reaching exactly 2^24
  is permitted; any candidate exceeding it is refused before encryption.
  Rotation resets the counter to the encryptions performed under the fresh DEK,
  not to zero after writing.
- `wrap_nonce` — fresh random 96-bit nonce on every wrapped-DEK encryption.
- `wrap_alg_id` / `item_alg_id` — wrap algorithm for the DEK record, and
  the algorithm all items are encrypted with. Independent choices,
  recorded separately (CRYPTO_SPEC §4).

### 4.3 Authentication

The wrapped-DEK AEAD record uses as **associated data** the full header
byte range from offset 4 through `wrap_nonce` inclusive (everything the
reader must consume *before* attempting the unwrap). Consequences, all
normative:

- Flipping any KDF parameter, algorithm ID, salt, counter, or wrap nonce
  causes wrapped-DEK authentication to fail.
- The wrapped DEK is authenticated as AEAD ciphertext. The whole-file HMAC
  additionally authenticates all 117 header bytes, including `future_pad`.

## 5. Index

The index is the item **directory**: an ordered list of entries, one per
slot, each mapping a stable public `item_id` to its slot number, plus the
item's title and username. Both live in the index — **not** the item
body — so `list` and TUI browsing decrypt only the index, never any
secret. Usernames are typically emails or account names with sensitivity
comparable to the title itself ("github.com" already reveals the
account); both are encrypted at rest (THREAT_MODEL §5.4).

```
Index (serialized, then encrypted as ONE AEAD ciphertext):
  u32                     entry_count
  repeated entry_count:
    u32    item_id        (monotonic, never reused, even after delete)
    u32    slot           (position in the items region)
    u8     state          (0x01 = live, 0x02 = tombstone)
    str    title          (length-prefixed UTF-8, max 256 bytes; not unique — duplicate titles are valid, identity is item_id)
    str    username       (length-prefixed UTF-8, max 512 bytes)
```

**No uniqueness invariant on `title`.** Duplicate titles are valid —
the same service ("github.com") can have multiple accounts, and
enforcing uniqueness would conflate the human handle with identity.
Stable identity is `item_id`, never reused. Title-collision handling is
a CLI concern: any command that addresses an item by title surfaces all
matches and requires interactive fuzzy selection when more than one
live entry bears that title (CLI_REFERENCE). Readers must not assume
uniqueness.

- **Encryption:** `item_alg_id`, DEK, fresh random 96-bit nonce. The nonce
  is stored in the clear immediately before the index ciphertext
  (standard AEAD framing; the nonce is not secret).
- **AAD:** vault version + a domain-separation byte `0x49` (`'I'`) so an
  index ciphertext can never be replayed as an item ciphertext or vice
  versa (see §6.2).
- Tombstones remain serialized as state `0x02`; they are never filtered or compacted,
  so `item_id` allocation stays monotonic across deletes. Rotation rewrites
  tombstone frames under the new DEK.

## 6. Items

### 6.1 Framing

The items region is a slot count followed by fixed-structure slots.
Slot addressing comes from the index (§5); the region itself is:
```

u32                        slot_count
repeated slot_count:
  12       nonce           (stored plaintext; nonces are not secret)
  u32      ct_len          (ciphertext bytes only)
  [ct_len] ciphertext
  16       tag             (separate AEAD tag)
```

All v2 item frames use separate tags, irrespective of reserved marker bytes.
Legacy combined-tag and separate-tag v1 frames are read only during explicit
migration (§9), never during normal open or save.

### 6.2 ItemRecord (plaintext schema)

opt-bytes password        (1-byte presence, then u32 length + raw bytes; max 1024)
str       url              (u16 length-prefixed UTF-8, max 2048 bytes, may be empty)
opt-bytes notes            (1-byte presence, then u32 length + raw bytes; max 8 KiB)
opt       totp              (1-byte presence; see below)
u64       created_unix
u64       modified_unix
u32       item_id         (mirrors the index entry — cross-checked on read)

Optional byte fields use `0x00` absent or `0x01` followed by a big-endian
`u32` byte length and raw bytes. URL and all index strings use a big-endian
`u16` byte length.

**TOTP field:** present only when the item has an authenticator secret:

```
u32       totp_secret_len (max 128)
[len]     raw decoded secret bytes
u32       totp_period    (seconds; must be > 0)
u32       totp_digits    (6 or 8)
u8        totp_alg       (0x01 SHA1, 0x02 SHA256, 0x03 SHA512)
```

The secret is decoded from base32 before serialization; base32 text never
appears in the item plaintext.


- **AAD for each item:** vault version + domain byte `0x53` (`'S'` for
  secret) + the item's `item_id` from the index. Domain separation means:
  - an item ciphertext can't be substituted for the index or another
    item (the `item_id` binds slot to identity),
  - moving an item between slots without the index agreeing fails
    authentication.
- **Serialization:** the explicit length-prefixed schema above — **not**
  `bincode`, whose output is Rust-implementation-defined. (Serde may be
  used internally, but the on-disk bytes are defined by this document.)

### 6.3 Slot stability

Deletes retain tombstone slots and encrypted placeholder frames. There is no
automatic compaction; rotation rewrites every slot atomically while preserving
states, metadata, and monotonic IDs. Explicit migration preserves the complete
legacy records, including any record retained in a tombstone frame.

## 7. Trailer and full-state authentication

The trailer is exactly **40 bytes**, in this order:

```
u32    slot_count      (redundant with §6)
u32    crc32c          (CRC32C of every byte BEFORE this 40-byte trailer)
32     file_mac       (HMAC-SHA256 of every preceding byte, including count and CRC)
```

For total file length `L`: trailer count is `[L-40, L-36)`, CRC is `[L-36, L-32)`,
and MAC is `[L-32, L)`. Derive the MAC key as:

```
HKDF-SHA256(
    IKM  = 32-byte DEK,
    salt = absent (RFC 5869: 32 zero bytes),
    info = ASCII "latchkey/v2/file-mac" (19 bytes, no terminator),
    L    = 32 bytes
)
```

HMAC input is exactly `file[0..L-32]`; no additional prefix or encoding.
Verification uses a constant-time tag comparison **before index decryption**.
The MAC authenticates the entire committed header, encrypted index, item
frames (including nonces/lengths/tags), counts, and CRC. AEAD remains an
independent per-record check; CRC is only a consistency check, not security.
After open, lazy reads (even cached-item requests), `check`, and saves
reauthenticate the disk snapshot and require the same full MAC commit identity
last read/written by that session. CRC alone is never a staleness identity.
Selective replay of an old valid frame or index into a newer commit therefore
fails, even if the attacker repairs the CRC.

Replacing the **entire** file with an old authenticated version cannot be
detected by a freshly opened session without externally trusted state.

## 8. Write protocol (normative)

1. Serialize the new file completely, to a temp file in the **same
   directory** as the vault (same filesystem → rename is atomic).
2. `fsync` the temp file.
3. Atomically rename over the old vault.
4. `fsync` the containing directory.

- On crash before step 3: old vault intact; the deterministic temp path is
  safely overwritten by the next write.
- A sibling `${vault}.lock` is opened and held with an exclusive OS file lock
  for the complete read/modify/write cycle, preventing same-tool concurrent
  writes. Cross-boundary writers (Windows-side processes editing via `\\wsl$`)
  can bypass the lock; this is accepted (THREAT_MODEL §5.5, last-write-wins).
- **Sync-safety:** because rename is atomic, a sync tool observes either
  the complete old file or the complete new file — never a hybrid.
- Creation and migration publish a complete synced temporary file via a
  same-filesystem hard link that atomically refuses an existing target,
  including a dangling symlink; no check-then-overwrite race is accepted.
- Before replacement, authenticate the current disk snapshot and require the
  session's complete MAC commit identity, not merely a valid CRC. Validate the
  total candidate size and DEK encryption cap before writing.

## 9. Explicit legacy migration

`Vault::migrate(source, target, password)` and
`latchkey --vault OLD migrate --out NEW` read only format 1, write format 2,
and leave all source bytes untouched. The master password is prompted without
echo, or read with `--from-stdin`; it is never a command-line argument.
The target must not exist. Its write lock is held throughout migration, and
the final publication atomically refuses replacement even if an external
process creates the target after the initial existence check.

Migration verifies the legacy wrapped DEK, index AEAD, CRC, framing, and
**every live and tombstone item AEAD/embedded ID**. It preserves item IDs,
states, metadata, and complete records; future allocation remains one above
the highest ID including tombstones. It generates a fresh salt, KEK, DEK,
wrap/index/item nonces, and uses the current default KDF policy. Both historical
v1 frame layouts (combined tag, or reserved marker 0xA5 with separate tag) are
supported only here.

Legacy v1 did not bind the whole committed state. Migration cannot
retroactively detect historical same-DEK index or item splicing whose individual
AEAD tags remain valid. Verify the trusted source before migration. Format 2
prevents subsequent selective substitution, but not full-file rollback (§7).
