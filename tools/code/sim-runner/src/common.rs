use anyhow::Context;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const DISPLAY: &str = ":99";
pub const WINDOW_NAME: &str = "TFT Simulator";
pub const RESOLUTION: &str = "480x800x24";

pub fn firmware_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("sim_map is tools/code/sim_map, three levels under the firmware root")
        .to_path_buf()
}

pub fn cache_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(".cache/assets-baseline")
}

pub fn assets_dir() -> PathBuf {
    firmware_dir().join("ui_simulator/assets")
}

pub fn restore_provisioned_assets() -> anyhow::Result<()> {
    let cache = cache_dir();
    if !cache.join("user1_secret.json").exists() {
        anyhow::bail!("no provisioned snapshot — run `sim_device provision --coin <TICKER>` first");
    }
    let assets = assets_dir();
    for name in ["user1_secret.json", "user1_data.json", "device_setting.json", "coin1.json"] {
        std::fs::copy(cache.join(name), assets.join(name))
            .with_context(|| format!("restoring {name}"))?;
    }
    Ok(())
}

const RUN_TIMEOUT: Duration = Duration::from_secs(20);

pub fn run(bin: &str, args: &[&str]) -> anyhow::Result<String> {
    use std::io::Read;

    let mut child = Command::new(bin)
        .args(args)
        .env("DISPLAY", DISPLAY)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {bin} {args:?} (is it installed?)"))?;

    let mut stdout_pipe = child.stdout.take().expect("piped");
    let mut stderr_pipe = child.stderr.take().expect("piped");
    let stdout_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now() + RUN_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().with_context(|| format!("polling {bin} {args:?}"))? {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("{bin} {args:?} did not finish within {RUN_TIMEOUT:?} — killed");
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let stdout = stdout_thread.join().map_err(|_| anyhow::anyhow!("stdout reader thread panicked"))?;
    let stderr = stderr_thread.join().map_err(|_| anyhow::anyhow!("stderr reader thread panicked"))?;
    if !status.success() {
        anyhow::bail!("{bin} {args:?} failed ({status})\n{}", String::from_utf8_lossy(&stderr).trim());
    }
    Ok(String::from_utf8_lossy(&stdout).trim().to_string())
}

pub fn spawn_detached(bin: &str, args: &[&str], cwd: Option<&Path>) -> anyhow::Result<Child> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .env("DISPLAY", DISPLAY)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.spawn()
        .with_context(|| format!("spawning {bin} {args:?}"))
}

pub fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

pub fn wait_for(timeout: Duration, mut ok: impl FnMut() -> bool) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if ok() {
            return Ok(());
        }
        if Instant::now() > deadline {
            anyhow::bail!("timed out");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn wait_for_window() -> anyhow::Result<String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(found) = run("xdotool", &["search", "--name", WINDOW_NAME]) {
            if let Some(first) = found.lines().next().filter(|l| !l.is_empty()) {
                return Ok(first.to_string());
            }
        }
        if Instant::now() > deadline {
            anyhow::bail!("timed out waiting for the \"{WINDOW_NAME}\" window");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn tap(window_id: &str, x: i32, y: i32) -> anyhow::Result<()> {
    run("xdotool", &["mousemove", "--window", window_id, &x.to_string(), &y.to_string()])?;
    std::thread::sleep(Duration::from_millis(150));
    run("xdotool", &["mousedown", "1"])?;
    std::thread::sleep(Duration::from_millis(200));
    run("xdotool", &["mouseup", "1"])?;
    Ok(())
}

pub fn swipe(window_id: &str, from: (i32, i32), to: (i32, i32), steps: u32) -> anyhow::Result<()> {
    run("xdotool", &["mousemove", "--window", window_id, &from.0.to_string(), &from.1.to_string()])?;
    std::thread::sleep(Duration::from_millis(150));
    run("xdotool", &["mousedown", "1"])?;
    std::thread::sleep(Duration::from_millis(100));
    for i in 1..=steps {
        let x = from.0 + (to.0 - from.0) * i as i32 / steps as i32;
        let y = from.1 + (to.1 - from.1) * i as i32 / steps as i32;
        run("xdotool", &["mousemove", "--window", window_id, &x.to_string(), &y.to_string()])?;
        std::thread::sleep(Duration::from_millis(80));
    }
    std::thread::sleep(Duration::from_millis(100));
    run("xdotool", &["mouseup", "1"])?;
    Ok(())
}

pub fn pin_digit_xy(c: char) -> anyhow::Result<(i32, i32)> {
    Ok(match c {
        '1' => (84, 448),
        '2' => (240, 448),
        '3' => (395, 448),
        '4' => (84, 521),
        '5' => (240, 521),
        '6' => (395, 521),
        '7' => (84, 596),
        '8' => (240, 596),
        '9' => (395, 596),
        '0' => (240, 670),
        'b' => (395, 670),
        other => anyhow::bail!("no known PIN-pad coordinate for {other:?}"),
    })
}

pub fn reauth_pin_digit_xy(c: char) -> anyhow::Result<(i32, i32)> {
    Ok(match c {
        '1' => (84, 533),
        '2' => (240, 533),
        '3' => (395, 533),
        '4' => (84, 607),
        '5' => (240, 607),
        '6' => (395, 607),
        '7' => (84, 681),
        '8' => (240, 681),
        '9' => (395, 681),
        '0' => (240, 755),
        'b' => (395, 755),
        other => anyhow::bail!("no known reauth-PIN-pad coordinate for {other:?}"),
    })
}

pub fn pin(window_id: &str, digits: &str) -> anyhow::Result<()> {
    for c in digits.chars() {
        let (x, y) = pin_digit_xy(c)?;
        tap(window_id, x, y)?;
    }
    Ok(())
}

pub fn reauth_pin(window_id: &str, digits: &str) -> anyhow::Result<()> {
    for c in digits.chars() {
        let (x, y) = reauth_pin_digit_xy(c)?;
        tap(window_id, x, y)?;
    }
    Ok(())
}

pub fn screenshot(window_id: &str, out_path: &Path) -> anyhow::Result<()> {
    let path_str = out_path.to_str().context("non-utf8 screenshot path")?;
    run("import", &["-window", window_id, path_str])?;
    Ok(())
}

pub fn screenshot_crop(
    window_id: &str,
    out_path: &Path,
    region: (i32, i32, u32, u32),
) -> anyhow::Result<()> {
    let path_str = out_path.to_str().context("non-utf8 screenshot path")?;
    let (x, y, w, h) = region;
    run("import", &["-window", window_id, "-crop", &format!("{w}x{h}+{x}+{y}"), path_str])?;
    Ok(())
}
