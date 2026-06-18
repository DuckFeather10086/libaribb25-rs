# libaribb25-rs

A Rust rewrite of **libaribb25** — the ARIB STD-B25 (and STD-B1)
descrambler used to decode ISDB MULTI2-scrambled transport streams via
a B-CAS smartcard.

This is a Cargo workspace with two crates:

| Crate     | Kind | What it is |
|-----------|------|-----------|
| `aribb25` | lib  | The descrambler core. Talks to the B-CAS card over PC/SC (`pcsc` crate), runs ECM/EMM key exchange, MULTI2-decrypts the TS payload. |
| `b25-rs` | bin  | Thin CLI front-end (`b25-rs`), API-compatible with the classic C `b25` tool. |

No CGO/FFI to the original C library — the descrambler is reimplemented
in Rust. The only external runtime dependency is **`pcscd`** plus a
B-CAS card reader.

## CLI usage

```text
b25-rs [options] src.m2t dst.m2t [more pairs ...]
b25-rs [options] -      -            # read TS from stdin, write to stdout
  -v <0|1>   0: silent, 1: verbose (default)
```

The stdin/stdout pipe form is how
[`ferrite`](https://github.com/DuckFeather10086/ferrite) chains it after the
tuner:

```
dvb-rs tune ... | b25-rs -v 0 - -   →   descrambled TS
```

## Build

```bash
cargo build --release          # produces target/release/b25-rs
```

## Runtime requirements

- `pcscd` running, with a polkit rule allowing the invoking user.
- A B-CAS card in a PC/SC-supported reader.

For free-to-air / cardless setups, ferrite can skip `b25-rs` entirely
(`DvbrCLI.B25Bin` empty). See the umbrella repo
[`ferrite`](https://github.com/DuckFeather10086/ferrite).
