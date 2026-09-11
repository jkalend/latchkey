# Fuzz targets

cargo-fuzz targets for the parsing surface — the code that touches
untrusted file bytes before any authentication happens (a corrupted
vault, a USB-stick swap, or a sync conflict is the realistic threat).

| Target | What it covers |
|---|---|
| `parse_header` | 117-byte header: magic, version, KDF/algorithm id decoders |
| `parse_index` | decrypted index payload: entry count + string length caps |
| `parse_item` | ItemRecord parser + serialize↔parse round-trip invariant |
| `split_item_frames` | on-disk frame walker (nonce ‖ ct_len ‖ ct+tag) |
| `otpauth_uri` | `otpauth://` parsing: query split, percent-decoding, then TOTP computation |

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

## Found so far

- `split_item_frames` OOM: `Vec::with_capacity(slot_count)` trusted the
  untrusted slot count (fixed — grow-on-demand + explicit bounds checks).
- `parse_index` (same class, milder): eager 1M-entry pre-allocation on a
  4-byte count claim (fixed — bounded by input length / 9).
