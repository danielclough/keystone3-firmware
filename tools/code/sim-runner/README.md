# sim_runner

Coin-agnostic tooling for driving keystone3-firmware's real SDL simulator (`build/simulator`) via `Xvfb`/`xdotool`/`import` — so any coin's on-device confirm-screen flow can be automated and verified, not just one. Nothing in this crate knows about a specific coin's transaction or address semantics: every subcommand trades only in raw UR strings (write a request UR in, scan a response UR out) and screen coordinates. A new coin needs a new click-map config, not new Rust.

Two binaries:

- **`sim_map`** — persistent, interactive session driver for *building* a click-map by hand: boot the simulator once, then tap/pin/swipe/screenshot against it across many short-lived commands while a human (or an agent looking at the screenshots) figures out where things are.
- **`sim_device`** — self-contained, one-shot automated driver for *using* a finished click-map: boot, do one thing (provision a seed, export an account, sign a request), tear down. This is what an e2e test or a bug-reproduction script calls.

## Why this exists

Firmware bugs found through one coin's UI often generalize to every coin sharing the same widget code — but "found through Bitcoin" is a much weaker claim than "reproduces identically through an unrelated second coin." Mapping a new coin's screens with this tool is what turns a one-off bug report into evidence of a recurring class, cheaply, without hand-driving the simulator's GUI over and over for each coin under test.

## Layout

```
src/
  common.rs      # process/display orchestration shared by both binaries: spawn Xvfb + the
                 # simulator, tap/swipe/pin, screenshot/crop, locate the firmware checkout root.
  click_map.rs   # loader + validation for a click-map TOML (see configs/): Screen/Field types,
                 # point()/region() accessors, coordinate bounds checking against the declared
                 # resolution.
  bin/
    sim_map.rs     # boot/status/tap/pin/swipe/shot/teardown — session state kept in a temp file
                   # across invocations.
    sim_device.rs  # provision/export/sign/decode-frame — each a single, self-contained run.
configs/
  <coin>.toml      # one click-map per coin, selected with --map. Field names are shared where the
                   # same on-device concept applies across coins (home.menu_button,
                   # connect_wallet.qr_region, sign_confirm.swipe_from/to, ...) so a click-map is
                   # mostly filling in coordinates, not inventing a schema.
  reference/       # committed screenshots the click-map's `reference = "reference/<name>.png"`
                   # fields point at — visual proof of every mapped screen without booting a
                   # simulator.
```

## Building a click-map for a new coin

1. `cargo run --bin sim_device -- provision --coin <TICKER>` — writes a cached, seeded asset snapshot (fixed BIP-39 test vector) with `<TICKER>` selected as the home screen's coin.
2. `cargo run --bin sim_map -- boot` (run with the firmware repo root as `cwd`), then `pin 123456` to unlock.
3. Tap around, `sim_map shot <name>` after every navigation step to confirm arrival before recording a coordinate — don't guess-and-record. Screenshots land in `configs/reference/`.
4. Write the confirmed coordinates into `configs/<ticker>.toml`, reusing field names from an existing map where the same screen/concept applies.
5. `cargo run --bin sim_device -- export --map configs/<ticker>.toml` to validate the whole connect-wallet flow end to end, not just that individual taps land in the right place.
6. `sim_map teardown` to clean up.

## Debugging a stuck scan

If `sim_device export`/`sign` times out "reassembling a UR," pass `--debug-frames <dir>` to dump every frame the scanner captures (plus periodic full, uncropped screenshots), then inspect one directly with `sim_device decode-frame <path.png>` — it prints the raw QR payload and whether `ur::decode` accepts it. This is the fastest way to tell a mis-aimed crop region (no QR found) apart from a decodable-but-rejected payload (e.g. a case-sensitivity mismatch — Keystone renders export/signature QRs in uppercase, which the scanner normalises before parsing).

## What this crate is not

- Not a place for any coin's transaction-building or signing logic — that stays in whatever project actually needs to sign for that coin. This crate only automates the on-screen UI.
- Not tied to any other repository. It depends only on crates keystone3-firmware itself already depends on (`ur-parse-lib`, the same BC-UR decode stack) and has its own `[workspace]` table so it builds standalone even when checked out inside a larger workspace.
