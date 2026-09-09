# Vault File Format

**Status:** Draft v0.1 — pre-implementation
**Covers:** format version 1 (`RPV1`)
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
2. **Metadata is encrypted** — item count and titles live inside
   ciphertext (THREAT_MODEL §5.4). The header contains crypto parameters
   only.
3. **Safe as an opaque file under naive sync** — a partially-synced file
   must fail authentication cleanly, never yield garbage.
4. **Upgradable parameters** — KDF params and algorithm IDs live in the
   header, readable without a key, so upgrades don't require decryption.

## 2. File layout (overview)

```
┌───────────────────────────┐  offset 0
│  Magic + version ("RPv1") │  4 bytes — the ONLY unauthenticated data
├───────────────────────────┤
│  Header (length-prefixed) │  plaintext, self-authenticating via §4.3
├───────────────────────────┤
│  Index (encrypted)        │  one AEAD ciphertext; maps ids → slots
├───────────────────────────┤
│  Items (encrypted)        │  N independent AEAD ciphertexts, fixed
│                            │  ordering, tombstone-capable
├───────────────────────────┤
│  Trailer                  │  32-byte file hash + item count
└───────────────────────────┘
```

## 3. Magic and version

```
Offset  Length  Value
0       3       "RPv"                    (0x52 0x50 0x76)
3       1       version byte, 0x01
```

- A wrong magic is a clean "not a vault" error.
- The version byte selects the parser. Readers must reject versions they
  don't know with a specific, actionable error ("vault is version N, this
  build supports 1").
- The magic is the only field not covered by authentication. It is parsed
  defensively and used solely to select the parser — nothing derived from
  it is security-relevant.

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
7       3       reserved     (zero; readers must ignore, not reject)
10      4       argon2_m     (MiB, u32; must be ≥ 8)
14      4       argon2_t     (iterations, u32; must be ≥ 1)
18      1       argon2_p     (lanes, u8; must be ≥ 1)
19      16      kdf_salt     (random per vault)
35      4       enc_counter  (u32 — encryptions under current DEK; §5)
39      12      wrap_nonce   (96-bit; zero for KEK-wrapped DEK, see CRYPTO_SPEC §5)
51      32      wrapped_dk   (DEK ciphertext — 32-byte DEK)
83      16      wrap_tag     (AEAD tag over the wrapped-DEK record)
99      18      future_pad   (zero; reserved for v1.x fields without a bump)
```

`wrapped_dk` holds the 32-byte DEK ciphertext; `wrap_tag` is the separate
16-byte AEAD tag over the wrapped-DEK record (the tag is not appended to
`wrapped_dk`). Total header size: **117 bytes** — this is the exact range
§4.3 authenticates.

### 4.2 Field semantics

- `argon2_m/t/p` — the exact parameters used to derive the KEK from the
  master password. Stored plaintext deliberately: needed before any key
  exists. A floor is enforced on read (CRYPTO_SPEC §3).
- `kdf_salt` — 128-bit, CSPRNG, generated at `init`, never reused across
  vaults.
- `enc_counter` — incremented on every item encryption under the current
  DEK. When it reaches 2^24, writers must refuse and instruct the user to
  run `rotate` (CRYPTO_SPEC §5 backstop).
- `wrap_nonce` — reserved field. For v1 it is written as 32 zero bytes
  (a 96-bit zero nonce) because the KEK-wrapped-DEK operation is
  one-per-KEK. The field exists so a future version can move to
  randomized wrapping without a format break.
- `wrap_alg_id` / `item_alg_id` — wrap algorithm for the DEK record, and
  the algorithm all items are encrypted with. Independent choices,
  recorded separately (CRYPTO_SPEC §4).

### 4.3 Authentication

The wrapped-DEK AEAD record uses as **associated data** the full header
byte range from offset 4 through `wrap_nonce` inclusive (everything the
reader must consume *before* attempting the unwrap). Consequences, all
normative:

- Flipping any KDF parameter, algorithm ID, or the salt → unwrap fails.
- Truncating or extending the header → unwrap fails.
- The header needs no separate MAC — its integrity is transitive through
  the wrapped-DEK tag (this resolves CRYPTO_SPEC §12.2: **folded in**).

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
    str    title          (length-prefixed UTF-8, max 256 bytes; unique — §5a)
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
- Tombstones exist so `item_id`s remain unique across deletions without
  renumbering. The writer compacts tombstones away when they exceed half
  the live entries (a rewrite, atomic per §8).

## 6. Items

### 6.1 Framing

The items region is a slot count followed by fixed-structure slots.
Slot addressing comes from the index (§5); the region itself is:

```
u32                        slot_count
repeated slot_count:
  12       nonce           (stored plaintext; nonces are not secret)
  u32      ct_len
  [ct_len] ciphertext      (encrypted ItemRecord)
  16       tag
```

A rejected alternative — nonce-less slots with a shared nonce stored once
per region — was discarded because per-slot stored nonces make each slot
independently rewriteable (§6.3 compaction, single-item edits).

### 6.2 ItemRecord (plaintext schema)

```
str       password        (length-prefixed UTF-8, max 1024 bytes)
str       url             (length-prefixed UTF-8, max 2048 bytes, may be empty)
str       notes           (length-prefixed UTF-8, max 8 KiB)
opt       totp            (optional, length-prefixed; see below)
u64       created_unix
u64       modified_unix
u32       item_id         (mirrors the index entry — cross-checked on read)
```

**TOTP field:** present only when the item has an authenticator secret
(optional fields use a 1-byte presence tag — `0x00` absent, `0x01`
present followed by the length-prefixed payload). The payload is the
base32-encoded TOTP shared secret plus parameters, stored as its own
length-prefixed sub-record:

```
str       totp_secret     (base32, max 128 bytes plaintext-decoded)
u32       totp_period    (seconds; default 30)
u32       totp_digits     (6 or 8; default 6)
str       totp_alg        ("SHA1" | "SHA256" | "SHA512"; default SHA1)
```

- `totp_secret` is a secret at the same level as `password` — same
  ItemRecord encryption, same memory-hygiene rules.
- Non-default parameter values are always written explicitly; defaults
  are assumed on read so most records stay small.
- The base32 is decoded to raw bytes before the sub-record is
  serialized (the stored form is raw key bytes, not the base32
  string), so `str` here means raw bytes with a length prefix.

- **AAD for each item:** vault version + domain byte `0x53` (`'S'` for
  secret) + the item's `item_id` from the index. Domain separation means:
  - an item ciphertext can't be substituted for the index or another
    item (the `item_id` binds slot to identity),
  - moving an item between slots without the index agreeing fails
    authentication.
- **Serialization:** the explicit length-prefixed schema above — **not**
  `bincode`, whose output is Rust-implementation-defined. (Serde may be
  used internally, but the on-disk bytes are defined by this document.)

### 6.3 Compaction

Deletes tombstone slots and their ciphertexts during a full rewrite when
the tombstone ratio (§5) or `enc_counter` limits are hit. Compaction and
rotation renumber slots and rewrite the index atomically (§8).

## 7. Trailer

```
u32    slot_count      (redundant with §6 but a cheap consistency check)
u32    crc32c          (over the whole preceding file)
```

- The CRC is **not** a security mechanism — authentication comes from AEAD
  tags. It exists to distinguish "torn write / sync-in-progress" (CRC bad)
  from "deliberate tampering" (AEAD tag fails on a CRC-valid file) in
  error reporting *without* revealing which AEAD check failed
  (CRYPTO_SPEC §7: the user-facing error stays generic either way).
- A mismatched trailer is reported as "vault file appears incomplete or
  still syncing" — the realistic cause under the bring-your-own-sync
  policy (THREAT_MODEL §5.5).

## 8. Write protocol (normative)

1. Serialize the new file completely, to a temp file in the **same
   directory** as the vault (same filesystem → rename is atomic).
2. `fsync` the temp file.
3. Atomically rename over the old vault.
4. `fsync` the containing directory.

- On crash before step 3: old vault intact, temp orphaned — the next run
  deletes stale temp files matching the `rpass` prefix pattern in the
  vault directory.
- Advisory locking (Windows share modes; `fcntl` locks on Linux) prevents
  same-tool concurrent writes. Cross-boundary writers (Windows-side
  processes editing via `\\wsl$`) can bypass locks — accepted
  (THREAT_MODEL §5.5, last-write-wins).
- **Sync-safety:** because rename is atomic, a sync tool observes either
  the complete old file or the complete new file — never a hybrid.

## 9. Open items

1. ~~Header length-prefix encoding~~ — **resolved:** fixed-size 117-byte
   header (§4.1).
2. Confirm per-slot stored nonce framing (§6.1) once a reference
   implementation round-trips it.
3. Should the index be split per-page for large vaults? v1 says no —
   hundreds of items in one AEAD ciphertext is fine; revisit above ~10k.
4. Keyfile support (a second factor file)? Deferred post-v1; the header's
   `kdf_id` byte space has room for a KDF-with-keyfile variant.
5. ~~TOTP support~~ — **resolved:** in v1 (§6.2 ItemRecord `totp` field).
   The optional-presence-tag framing means pre-TOTP readers see the field
   as absent only if the byte is 0x00 — since v1 defines the field, all
   v1 writers understand it; older *pre-release* dev vaults from before
   the field existed are not a compatibility concern (no releases
   shipped).
