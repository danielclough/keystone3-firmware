use anyhow::Context;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sim_runner::common as sim_common;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(about = "Interactive session driver for hand-mapping the keystone3-firmware simulator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Boot,
    Status,
    Tap { x: i32, y: i32 },
    Pin { digits: String },
    Swipe { x1: i32, y1: i32, x2: i32, y2: i32 },
    Shot { name: String },
    Teardown,
}

#[derive(Serialize, Deserialize)]
struct Session {
    xvfb_pid: u32,
    sim_pid: u32,
    window_id: String,
}

fn state_path() -> PathBuf {
    std::env::temp_dir().join("sim-map-session.toml")
}

fn shots_dir() -> anyhow::Result<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("configs/reference");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

fn load_session() -> anyhow::Result<Session> {
    let text = std::fs::read_to_string(state_path())
        .context("no active mapping session — run `sim_map boot` first")?;
    toml::from_str(&text).context("corrupt session state file")
}

fn save_session(s: &Session) -> anyhow::Result<()> {
    std::fs::write(
        state_path(),
        toml::to_string_pretty(s).context("serialising session state")?,
    )
    .context("writing session state")
}

fn cmd_boot() -> anyhow::Result<()> {
    if let Ok(s) = load_session() {
        if sim_common::pid_alive(s.xvfb_pid) && sim_common::pid_alive(s.sim_pid) {
            anyhow::bail!(
                "a mapping session is already running (window {}) — `sim_map teardown` first",
                s.window_id
            );
        }
    }
    let _ = std::fs::remove_file(state_path());

    sim_common::restore_provisioned_assets()
        .context("run `sim_device provision --coin <TICKER>` before `sim_map boot`")?;

    let xvfb = sim_common::spawn_detached(
        "Xvfb",
        &[sim_common::DISPLAY, "-screen", "0", sim_common::RESOLUTION],
        None,
        None,
    )
    .context("starting Xvfb — is it installed? (`sudo apt install xvfb`)")?;
    sim_common::wait_for(Duration::from_secs(5), || {
        sim_common::run("xdotool", &["getdisplaygeometry"]).is_ok()
    })
    .context("Xvfb never came up")?;

    let dir = sim_common::firmware_dir();
    let log = sim_common::simulator_log_path();
    let sim = sim_common::spawn_detached("./build/simulator", &[], Some(&dir), Some(&log))
        .with_context(|| {
            format!(
                "starting the simulator — build it first: `cd {} && python3 build.py -o simulator`",
                dir.display()
            )
        })?;

    let window_id = sim_common::wait_for_window().context(
        "simulator window never appeared — must run with the firmware repo root as cwd, or \
         LVGL's C: fs driver silently can't find ui_simulator/assets and black-screens",
    )?;

    save_session(&Session {
        xvfb_pid: xvfb.id(),
        sim_pid: sim.id(),
        window_id: window_id.clone(),
    })?;
    println!("booted: display {}, window {window_id}", sim_common::DISPLAY);
    Ok(())
}

fn cmd_status() -> anyhow::Result<()> {
    let s = match load_session() {
        Ok(s) => s,
        Err(_) => {
            println!("no active session");
            return Ok(());
        }
    };
    let xvfb_ok = sim_common::pid_alive(s.xvfb_pid);
    let sim_ok = sim_common::pid_alive(s.sim_pid);
    println!(
        "window {} — Xvfb pid {} ({}), simulator pid {} ({})",
        s.window_id,
        s.xvfb_pid,
        if xvfb_ok { "alive" } else { "dead" },
        s.sim_pid,
        if sim_ok { "alive" } else { "dead" },
    );
    if !sim_ok {
        // A dead simulator here almost always means the firmware crashed under the last tap, so
        // point at the log rather than leaving the next `tap`/`shot` to fail against a window id
        // that no longer resolves.
        println!("simulator output: {}", sim_common::simulator_log_path().display());
    }
    if !xvfb_ok || !sim_ok {
        anyhow::bail!("session is stale — `sim_map teardown` then `sim_map boot` again");
    }
    Ok(())
}

fn cmd_shot(name: &str) -> anyhow::Result<()> {
    let s = load_session()?;
    let path = shots_dir()?.join(format!("{name}.png"));
    sim_common::screenshot(&s.window_id, &path)?;
    println!("{}", path.display());
    Ok(())
}

fn cmd_teardown() -> anyhow::Result<()> {
    if let Ok(s) = load_session() {
        let _ = sim_common::run("kill", &["-9", &s.sim_pid.to_string()]);
        let _ = sim_common::run("kill", &["-9", &s.xvfb_pid.to_string()]);
    }
    let _ = std::fs::remove_file(state_path());
    println!("torn down");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Boot => cmd_boot(),
        Command::Status => cmd_status(),
        Command::Tap { x, y } => {
            let s = load_session()?;
            sim_common::tap(&s.window_id, x, y)
        }
        Command::Pin { digits } => {
            let s = load_session()?;
            sim_common::pin(&s.window_id, &digits)
        }
        Command::Swipe { x1, y1, x2, y2 } => {
            let s = load_session()?;
            sim_common::swipe(&s.window_id, (x1, y1), (x2, y2), 12)
        }
        Command::Shot { name } => cmd_shot(&name),
        Command::Teardown => cmd_teardown(),
    }
}
