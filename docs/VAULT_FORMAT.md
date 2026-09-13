# Vault File Format

**Status:** Implemented; not yet publicly released
**Covers:** Format version 1 (`LKv1`)
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
│  Magic + version ("LKv1") │  4-byte parser selector
├───────────────────────────┤
│  Fixed header             │  crypto parameters + wrapped DEK, 117 total
├───────────────────────────┤
│  Index (encrypted)        │  one AEAD ciphertext; maps ids → slots
├───────────────────────────┤
│  Items (encrypted)        │  N independent AEAD ciphertexts
├───────────────────────────┤
│  Trailer                  │  u32 slot count + u32 CRC32C
└───────────────────────────┘
```

Readers refuse vault files larger than 64 MiB before parsing. v1 targets
hundreds of credentials; this bound prevents a corrupt or hostile file
from causing unbounded allocation.

## 3. Magic and version

```
Offset  Length  Value
0       3       "LKv"                    (0x52 0x50 0x76)
3       1       version byte, 0x01
```

- A wrong magic is a clean "not a vault" error.
- The version byte selects the parser. Readers must reject versions they
  don't know with a specific, actionable error ("vault is version N, this
  build supports 1").
- Magic, version, and `future_pad` are outside the wrapped-DEK AAD.
  Magic/version select the parser; unknown values are rejected.
  `future_pad` must be all zero, so unauthenticated extensions are never
  silently accepted.

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
7       3       reserved     (byte 0 = 0xA5 for v2 item framing; zero means legacy framing)
10      4       argon2_m     (MiB, u32; must be ≥ 8)
14      4       argon2_t     (iterations, u32; must be ≥ 1)
18      1       argon2_p     (lanes, u8; must be ≥ 1)
19      16      kdf_salt     (random per vault)
35      4       enc_counter  (u32 — encryptions under current DEK; §5)
39      12      wrap_nonce   (96-bit random nonce for KEK-wrapped DEK)
51      32      wrapped_dk   (DEK ciphertext — 32-byte DEK)
83      16      wrap_tag     (AEAD tag over the wrapped-DEK record)
99      18      future_pad   (zero; reserved for v1.x fields without a bump)
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
- `enc_counter` — incremented on every item encryption under the current
  DEK. When it reaches 2^24, writers must refuse and instruct the user to
  run `rotate` (CRYPTO_SPEC §5 backstop).
- `wrap_nonce` — 96-bit nonce for the KEK-wrapped DEK. Legacy v1 writers
  zeroed this field; v2 writers generate it randomly.
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
- The wrapped DEK is authenticated as AEAD ciphertext. The zero-only
  `future_pad` policy covers the remaining reserved bytes without
  claiming they are AEAD-authenticated.

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
- Tombstones remain serialized as state `0x02`; they are never filtered or compacted,
  so `item_id` allocation stays monotonic across deletes. Rotation rewrites
  tombstone frames under the new DEK.

## 6. Items

### 6.1 Framing

The items region is a slot count followed by fixed-structure slots.
Slot addressing comes from the index (§5); the region itself is:

u32                        slot_count
repeated slot_count:
  12       nonce           (stored plaintext; nonces are not secret)
  u32      ct_len          (ciphertext bytes only)
  [ct_len] ciphertext
  16       tag             (separate AEAD tag)
```

The v2 framing keeps the tag separate from the ciphertext length. Readers accept
legacy v1 frames whose `ct_len` included the tag, then migrate them on the next
write.

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
automatic compaction in v1; rotation rewrites every slot atomically while
preserving the tombstone records and monotonic item IDs.

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

- On crash before step 3: old vault intact; the deterministic temp path is
  safely overwritten by the next write.
- A sibling `${vault}.lock` is opened and held with an exclusive OS file lock
  for the complete read/modify/write cycle, preventing same-tool concurrent
  writes. Cross-boundary writers (Windows-side processes editing via `\\wsl$`)
  can bypass the lock; this is accepted (THREAT_MODEL §5.5, last-write-wins).
- **Sync-safety:** because rename is atomic, a sync tool observes either
  the complete old file or the complete new file — never a hybrid.

## 9. Open items

1. ~~Header length-prefix encoding~~ — **resolved:** fixed-size 117-byte
   header (§4.1).
2. ~~Per-slot stored nonce framing~~ — **resolved:** v2 separates the
   ciphertext length from the 16-byte AEAD tag; readers migrate legacy
   inline-tag frames (§6.1).
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
