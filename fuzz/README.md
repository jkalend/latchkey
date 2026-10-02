# Fuzz targets

cargo-fuzz targets for structural vault parsing and untrusted import files
(native JSON, Bitwarden, KeePassXC). Header/frame inputs are raw file bytes;
the plaintext index/item parsers are exercised directly with synthetic buffers.
Normal format-2 vault opens authenticate the complete file before decrypting
and parsing its index.

| Target | What it covers |
|---|---|
| `parse_header` | 117-byte format-2 header: magic, version, KDF/algorithm id decoders |
| `parse_index` | decrypted index payload: entry count + string length caps |
| `parse_item` | ItemRecord parser + serialize↔parse round-trip invariant |
| `split_item_frames` | format-2 on-disk frame walker (nonce ‖ ct_len ‖ ct ‖ tag), counts, and 40-byte trailer bounds |
| `otpauth_uri` | `otpauth://` parsing: query split, percent-decoding, then TOTP computation |
| `import_native_json` | hand-rolled JSON grammar + native schema-1 interpretation |
| `import_bitwarden` | Bitwarden JSON adapter: type dispatch, field extraction, TOTP URIs |
| `import_keepassxc` | KeePassXC CSV adapter: quoting, record/field caps |

## Running

Requires nightly (`rustup toolchain install nightly`) and the MSVC ASan
runtime on `PATH` (cargo-fuzz links `clang_rt.asan_dynamic-x86_64.dll`
dynamically on Windows — it lives in the MSVC BuildTools `bin/Hostx64/x64`):

```sh
cd fuzz
export PATH="/c/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/VC/Tools/MSVC/<ver>/bin/Hostx64/x64:$PATH"
cargo +nightly fuzz run <target> -- -max_total_time=60
```

Crash artifacts land in `fuzz/artifacts/<target>/`. `fuzz/corpus/` holds
seed inputs; it is committed so runs start warm.

## After the format-2 cutover

Previous format-1 campaigns do not establish coverage of the current code.
Run a fresh sanitizer-enabled campaign before publishing 0.3.0:

- Seed `parse_header` with the first 117 bytes of the current
  `test-vectors/vault-golden.bin`, and `split_item_frames` with the complete
  golden file. Legacy vault-only seeds now fail normal version selection early.
- Keep existing valid plaintext index/item, JSON/CSV, and otpauth seeds; refresh
  boundary cases for lengths/counts, truncation, malformed text, and nesting.
- Retain `test-vectors/vault-legacy-v1.bin` for migration verification rather
  than treating it as a normally openable vault.
- The eight targets do not exercise full-file MAC verification or legacy
  migration end-to-end. Historical index/frame substitution and migration
  preservation currently have deterministic regression coverage; a dedicated
  authenticated-vault/migration harness is additional work, not implied by
  parser fuzzing.
- Compilation of the targets is not a fuzz campaign or a coverage result.


## Found so far

- `split_item_frames` OOM: `Vec::with_capacity(slot_count)` trusted the
  untrusted slot count (fixed — grow-on-demand + explicit bounds checks).
- `parse_index` (same class, milder): eager 1M-entry pre-allocation on a
  4-byte count claim (fixed — bounded by input length / 9).
