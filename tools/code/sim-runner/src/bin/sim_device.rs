use anyhow::Context;
use clap::{Parser, Subcommand};
use sim_runner::click_map::ClickMap;
use sim_runner::common as sim_common;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};
use ur_parse_lib::keystone_ur_decoder::probe_decode;
use ur_parse_lib::keystone_ur_encoder::probe_encode;
use ur_registry::extend::crypto_multi_accounts::CryptoMultiAccounts;

const TEST_SEED: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MASTER_FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0a];
const PROVISION_PIN: &str = "123456";
const WALLET_NAME: &str = "sim-map-test";

const DEFAULT_COINS: &[&str] = &[
    "BTC", "ETH", "SOL", "NEAR", "BNB", "HNT", "XRP", "ADA", "TON", "ZEC", "DOT", "TRX", "LTC",
    "DOGE", "AVAX", "BCH", "APT", "SUI", "IOTA", "DASH", "AR", "XLM", "BABY", "NTMPI", "TIA",
    "NTRN", "DYM", "OSMO", "INJ", "ATOM", "CRO", "RUNE", "KAVA", "LUNC", "AXL", "LUNA", "AKT",
    "STRD", "SCRT", "BLD", "CTK", "EVMOS", "STARS", "XPRT", "SOMM", "JUNO", "IRIS", "DVPN",
    "ROWAN", "REGEN", "BOOT", "GRAV", "IXO", "NGM", "IOV", "UMEE", "QCK", "TGD",
];

#[derive(Parser)]
#[command(about = "Self-contained, automated driver for the keystone3-firmware simulator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Provision {
        #[arg(long, default_value = "NEAR")]
        coin: String,
    },
    Export {
        #[arg(long)]
        map: PathBuf,
        #[arg(long)]
        debug_frames: Option<PathBuf>,
    },
    /// Runs the same export flow as `Export`, then decodes the resulting `crypto-multi-accounts`
    /// UR in-process and prints the NEAR public key ("ed25519:...") whose origin path matches
    /// `path` exactly (e.g. "44'/397'/0'") — sim_device has no way to ask the on-device UI for a
    /// single derivation path directly, only a full export, so this mirrors fake_device's
    /// `pubkey <path>` interface on top of that.
    Pubkey {
        #[arg(long)]
        map: PathBuf,
        path: String,
        #[arg(long)]
        debug_frames: Option<PathBuf>,
    },
    DecodeFrame {
        path: PathBuf,
    },
    Sign {
        #[arg(long)]
        map: PathBuf,
        ur: String,
        #[arg(long)]
        debug_frames: Option<PathBuf>,
    },
}

fn cmd_provision(coin: &str) -> anyhow::Result<()> {
    let cache = sim_common::cache_dir();
    std::fs::create_dir_all(&cache).with_context(|| format!("creating {}", cache.display()))?;

    if !cache.join("user1_secret.json").exists() {
        let mnemonic = bip39::Mnemonic::parse(TEST_SEED).context("TEST_SEED is not a valid mnemonic")?;
        let seed = mnemonic.to_seed("");

        let mut param = vec![16u8, 0, 0, 0];
        param.extend_from_slice(&MASTER_FINGERPRINT);
        param.extend_from_slice(&[0u8; 7]);
        let mut name_bytes = WALLET_NAME.as_bytes().to_vec();
        anyhow::ensure!(name_bytes.len() <= 16, "wallet name too long for WALLET_NAME_MAX_LEN");
        name_bytes.resize(17, 0);
        param.extend_from_slice(&name_bytes);
        anyhow::ensure!(param.len() == 32, "param must be exactly 32 bytes, got {}", param.len());

        let zeros32 = vec![0u8; 32];
        let secret = serde_json::json!({
            "entropy": zeros32.clone(),
            "seed": seed.to_vec(),
            "slip39_ems": zeros32.clone(),
            "reserved_data": zeros32,
            "entropy_len": 16,
            "password": PROVISION_PIN,
            "param": param,
        });
        std::fs::write(cache.join("user1_secret.json"), secret.to_string())
            .context("writing user1_secret.json")?;

        std::fs::write(
            cache.join("user1_data.json"),
            serde_json::json!({"version": "1.0.1", "key": {}}).to_string(),
        )
        .context("writing user1_data.json")?;

        std::fs::write(
            cache.join("device_setting.json"),
            serde_json::json!({
                "version": "1.0.0", "setup_step": 5, "bright": 15, "auto_lock_screen": 60,
                "auto_power_off": 0, "vibration": 1, "random_pin_pad": 0, "permit_sign": 0,
                "dark_mode": 1, "usb_switch": 1, "last_version": 851970, "language": 0,
                "nftEnable": false, "nftValid": false, "enableBlindSigning": false,
            })
            .to_string(),
        )
        .context("writing device_setting.json")?;
    }

    let mut coins = serde_json::Map::new();
    let all_tickers = DEFAULT_COINS
        .iter()
        .map(|s| s.to_string())
        .chain(std::iter::once(coin.to_string()).filter(|c| !DEFAULT_COINS.contains(&c.as_str())));
    for c in all_tickers {
        let selected = c == coin;
        coins.insert(
            c,
            serde_json::json!({
                "recvIndex": 0, "recvPath": 0,
                "firstRecv": selected,
                "manage": selected,
            }),
        );
    }
    std::fs::write(cache.join("coin1.json"), serde_json::Value::Object(coins).to_string())
        .context("writing coin1.json")?;

    println!("provisioned ({coin}): {}", cache.display());
    Ok(())
}

struct SimHarness {
    xvfb: Child,
    simulator: Child,
    window_id: String,
}

impl SimHarness {
    fn boot() -> anyhow::Result<Self> {
        sim_common::restore_provisioned_assets()?;

        let xvfb = sim_common::spawn_detached(
            "Xvfb",
            &[sim_common::DISPLAY, "-screen", "0", sim_common::RESOLUTION],
            None,
            None,
        )
        .context("starting Xvfb — is it installed? (`sudo apt install xvfb`)")?;

        let dir = sim_common::firmware_dir();
        let placeholder =
            sim_common::spawn_detached("true", &[], None, None).context("spawning placeholder")?;
        let mut harness = SimHarness { xvfb, simulator: placeholder, window_id: String::new() };

        sim_common::wait_for(Duration::from_secs(5), || {
            sim_common::run("xdotool", &["getdisplaygeometry"]).is_ok()
        })
        .context("Xvfb never came up")?;

        let log = sim_common::simulator_log_path();
        let simulator = sim_common::spawn_detached("./build/simulator", &[], Some(&dir), Some(&log))
            .with_context(|| {
                format!(
                    "starting the simulator — build it first: `cd {} && python3 build.py -o simulator`",
                    dir.display()
                )
            })?;
        let _ = harness.simulator.kill();
        let _ = harness.simulator.wait();
        harness.simulator = simulator;

        harness.window_id = sim_common::wait_for_window().context(
            "simulator window never appeared — must run with the firmware repo root as cwd, or \
             LVGL's C: fs driver silently can't find ui_simulator/assets and black-screens",
        )?;

        sim_common::pin(&harness.window_id, PROVISION_PIN).context("unlocking with the provisioned PIN")?;
        std::thread::sleep(Duration::from_millis(300));
        Ok(harness)
    }

    /// Fails if the simulator has exited, quoting its log. Every UI step below funnels through
    /// this before it is allowed to blame its own tooling: once the firmware crashes, the window
    /// id every later `xdotool`/`import` call carries no longer resolves, and `import` in
    /// particular prints "no window with specified ID exists" and then *blocks* until run()'s
    /// timeout kills it — so the untreated failure reads as "import hung", which points at the
    /// harness instead of at the crash that actually happened several steps earlier.
    fn check_alive(&mut self) -> anyhow::Result<()> {
        let Some(status) = self.simulator.try_wait().context("polling the simulator process")? else {
            return Ok(());
        };
        let log = sim_common::simulator_log_path();
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        let mut tail: Vec<&str> = text.lines().rev().take(15).collect();
        tail.reverse();
        let tail = if tail.is_empty() { "(nothing captured)".to_string() } else { tail.join("\n") };
        anyhow::bail!(
            "the simulator exited ({status}) — the firmware crashed mid-flow; this is not a \
             harness timeout. Last output ({}):\n{tail}",
            log.display(),
        )
    }

    fn navigate_to_export(&mut self, map: &ClickMap) -> anyhow::Result<()> {
        let (x, y) = map.point("home", "menu_button")?;
        sim_common::tap(&self.window_id, x, y)?;
        std::thread::sleep(Duration::from_millis(300));
        let (x, y) = map.point("home_menu", "connect_software_wallet")?;
        sim_common::tap(&self.window_id, x, y)?;
        std::thread::sleep(Duration::from_millis(500));
        let (x, y) = map.point("choose_wallet", "chain_filter_more")?;
        sim_common::tap(&self.window_id, x, y)?;
        std::thread::sleep(Duration::from_millis(300));
        let (x, y) = map.point("choose_wallet_filtered", "coin_entry")?;
        sim_common::tap(&self.window_id, x, y)?;
        std::thread::sleep(Duration::from_millis(500));
        // Building the export UR is the heaviest thing this flow asks the firmware to do (every
        // NEAR xpub the device holds, CBOR-encoded and fountain-split), and it is where
        // GuiGetNearWalletData once overflowed its key array — so confirm the device survived
        // arriving here before the caller starts screenshotting a window that may be gone.
        self.check_alive()
    }
}

impl Drop for SimHarness {
    fn drop(&mut self) {
        let _ = self.simulator.kill();
        let _ = self.simulator.wait();
        let _ = self.xvfb.kill();
        let _ = self.xvfb.wait();
    }
}

fn decode_frame(path: &Path) -> anyhow::Result<String> {
    let img = image::open(path).with_context(|| format!("opening {}", path.display()))?.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(img);
    let grids = prepared.detect_grids();
    let grid = grids.first().context("no QR code found in frame")?;
    let (_, content) = grid.decode().map_err(|e| anyhow::anyhow!("decoding QR grid: {e}"))?;
    Ok(content)
}

fn normalise_ur(raw: &str) -> String {
    raw.to_lowercase()
}

fn ur_type_of(frame: &str) -> anyhow::Result<String> {
    frame
        .strip_prefix("ur:")
        .and_then(|rest| rest.split('/').next())
        .map(str::to_string)
        .with_context(|| format!("not a ur:<type>/... string: {frame:?}"))
}

fn scan_until_complete(
    harness: &mut SimHarness,
    region: (i32, i32, u32, u32),
    debug_frames: Option<&Path>,
) -> anyhow::Result<String> {
    let window_id = harness.window_id.clone();
    let window_id = window_id.as_str();
    let tmp = std::env::temp_dir().join("sim-device-scan.png");
    if let Some(dir) = debug_frames {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let mut decoder: Option<(ur::Decoder, String)> = None;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut seen = 0u32;
    let mut captured = 0u32;
    loop {
        // A capture failure here is far more often a dead simulator than a broken `import`, and
        // `import`'s own diagnostic for a vanished window is a 20s block — so ask the process
        // itself first and report the crash, falling back to the raw capture error only if the
        // firmware is genuinely still running.
        if let Err(capture_err) = sim_common::screenshot_crop(window_id, &tmp, region) {
            harness.check_alive()?;
            return Err(capture_err);
        }
        captured += 1;
        if let Some(dir) = debug_frames {
            let dest = dir.join(format!("frame_{captured:04}.png"));
            std::fs::copy(&tmp, &dest).with_context(|| format!("copying to {}", dest.display()))?;
            if captured <= 3 || captured % 20 == 0 {
                let full = dir.join(format!("full_{captured:04}.png"));
                sim_common::screenshot(window_id, &full)?;
            }
        }
        if let Ok(frame) = decode_frame(&tmp).map(|raw| normalise_ur(&raw)) {
            seen += 1;
            if let Some((dec, ur_type)) = &mut decoder {
                let _ = dec.receive(&frame);
                eprintln!("frame {seen}: progress {}%", dec.progress());
                if dec.complete() {
                    let cbor = dec
                        .message()
                        .map_err(|e| anyhow::anyhow!("{e}"))?
                        .context("decoder reported complete but no message")?;
                    let encoded = probe_encode(&cbor, 50_000, ur_type.clone())
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    return Ok(encoded.data);
                }
            } else if let Ok((kind, _payload)) = ur::decode(&frame) {
                match kind {
                    ur::ur::Kind::SinglePart => return Ok(frame),
                    ur::ur::Kind::MultiPart => {
                        let mut dec = ur::Decoder::default();
                        let _ = dec.receive(&frame);
                        decoder = Some((dec, ur_type_of(&frame)?));
                    }
                }
            }
        }
        if Instant::now() > deadline {
            anyhow::bail!("timed out reassembling a UR from {region:?}");
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn retry_once<T>(mut f: impl FnMut() -> anyhow::Result<T>) -> anyhow::Result<T> {
    match f() {
        Ok(v) => Ok(v),
        Err(first_err) => {
            eprintln!("sim_device: first attempt failed ({first_err:#}), retrying once on a fresh boot");
            f().map_err(|second_err| {
                second_err.context(format!("retry also failed; first attempt failed with: {first_err:#}"))
            })
        }
    }
}

fn cmd_decode_frame(path: &Path) -> anyhow::Result<()> {
    let raw = decode_frame(path)?;
    match ur::decode(&normalise_ur(&raw)) {
        Ok((kind, _)) => println!("ur kind: {kind:?}"),
        Err(e) => println!("not a decodable ur: {e}"),
    }
    println!("{raw}");
    Ok(())
}

fn cmd_export(map_path: &Path, debug_frames: Option<&Path>) -> anyhow::Result<()> {
    let map = ClickMap::load(map_path)?;
    let qr_region = map.region("connect_wallet", "qr_region")?;
    let ur = retry_once(|| {
        let mut h = SimHarness::boot()?;
        h.navigate_to_export(&map)?;
        scan_until_complete(&mut h, qr_region, debug_frames)
    })?;
    println!("{ur}");
    Ok(())
}

fn cmd_pubkey(map_path: &Path, path: &str, debug_frames: Option<&Path>) -> anyhow::Result<()> {
    let map = ClickMap::load(map_path)?;
    let qr_region = map.region("connect_wallet", "qr_region")?;
    let ur = retry_once(|| {
        let mut h = SimHarness::boot()?;
        h.navigate_to_export(&map)?;
        scan_until_complete(&mut h, qr_region, debug_frames)
    })?;

    let decoded = probe_decode::<CryptoMultiAccounts>(ur).map_err(|e| anyhow::anyhow!("{e}"))?;
    let accounts = decoded.data.context("no data in crypto-multi-accounts UR")?;
    let key = accounts
        .get_keys()
        .into_iter()
        .find(|k| {
            k.get_origin()
                .and_then(|p| p.get_path())
                .is_some_and(|p| p == path)
        })
        .with_context(|| format!("no key at path {path} in this export"))?;
    let raw: [u8; 32] = key
        .get_key()
        .try_into()
        .map_err(|b: Vec<u8>| anyhow::anyhow!("NEAR public key is {} bytes, expected 32", b.len()))?;
    println!("ed25519:{}", bs58::encode(raw).into_string());
    Ok(())
}

fn cmd_sign(map_path: &Path, ur: &str, debug_frames: Option<&Path>) -> anyhow::Result<()> {
    std::fs::write(sim_common::assets_dir().join("qrcode_data.txt"), format!("{ur}\n"))
        .context("writing qrcode_data.txt")?;

    let map = ClickMap::load(map_path)?;
    let (scan_x, scan_y) = map.point("home", "scan_button")?;
    let swipe_from = map.point("sign_confirm", "swipe_from")?;
    let swipe_to = map.point("sign_confirm", "swipe_to")?;
    let qr_region = map.region("sign_response", "qr_region")?;

    let signature_ur = retry_once(|| {
        let mut h = SimHarness::boot()?;
        sim_common::tap(&h.window_id, scan_x, scan_y)?;
        std::thread::sleep(Duration::from_millis(1000));
        sim_common::swipe(&h.window_id, swipe_from, swipe_to, 12)?;
        std::thread::sleep(Duration::from_millis(500));
        sim_common::reauth_pin(&h.window_id, PROVISION_PIN)?;
        std::thread::sleep(Duration::from_millis(500));
        // Parsing and rendering the sign request, then signing it, is the other place the firmware
        // does real work under this harness — same reasoning as navigate_to_export's check.
        h.check_alive()?;

        scan_until_complete(&mut h, qr_region, debug_frames)
    })?;
    println!("{signature_ur}");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Provision { coin } => cmd_provision(&coin),
        Command::DecodeFrame { path } => cmd_decode_frame(&path),
        Command::Export { map, debug_frames } => cmd_export(&map, debug_frames.as_deref()),
        Command::Pubkey { map, path, debug_frames } => cmd_pubkey(&map, &path, debug_frames.as_deref()),
        Command::Sign { map, ur, debug_frames } => cmd_sign(&map, &ur, debug_frames.as_deref()),
    }
}
