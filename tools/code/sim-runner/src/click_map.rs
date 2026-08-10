use crate::common as sim_common;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Mean per-channel absolute difference, over a whole crop, below which two renders of the same
/// screen count as the same screen. Not byte equality: the simulator renders text through SDL with
/// subpixel variation that differs between runs and between host GPUs, so an exact comparison
/// would fail constantly and the only surviving response would be to delete the assertion. A mean
/// of 8/255 is far below the delta of *any* two different screens in this map (the smallest such
/// pair, `pin_pad` vs `reauth_pin_pad`, differs by an order of magnitude more) while absorbing
/// every anti-aliasing wobble observed across capture runs.
const MAX_MEAN_CHANNEL_DELTA: f64 = 8.0;

#[derive(Debug, Deserialize)]
pub struct ClickMap {
    pub resolution: Resolution,
    pub screens: BTreeMap<String, Screen>,
    /// Directory the map was loaded from, so `reference = "reference/near/home.png"` resolves
    /// against the map rather than against the caller's cwd -- `sim_device` runs with its own cwd
    /// and the e2e fixtures shell into it from three different directory depths.
    #[serde(skip)]
    base_dir: PathBuf,
}

#[derive(Debug, Deserialize, Clone, Copy)]
pub struct Resolution {
    pub w: i32,
    pub h: i32,
}

/// The field naming the window rectangle a screen's `reference` crop covers. Deliberately not the
/// whole window: `connect_wallet` and `sign_response` are dominated by an *animated* QR whose
/// frames differ every run, so a full-window comparison there would be noise. Each screen points
/// this at its own stable chrome (title, header) instead.
const REFERENCE_REGION: &str = "reference_region";

#[derive(Debug, Deserialize)]
pub struct Screen {
    #[serde(flatten)]
    pub fields: BTreeMap<String, Field>,
}

impl Screen {
    fn reference_path(&self) -> Option<&str> {
        match self.fields.get("reference") {
            Some(Field::Reference(rel)) => Some(rel),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Field {
    Region { x: i32, y: i32, w: u32, h: u32 },
    Point { x: i32, y: i32 },
    Reference(String),
}

impl ClickMap {
    pub fn load(path: &Path) -> Result<Self> {
        let map = Self::load_without_references(path)?;
        map.validate()?;
        Ok(map)
    }

    /// `load` minus the "every reference crop exists" check -- the only legitimate caller is
    /// `sim_device verify-screens --capture`, which exists precisely to create the files whose
    /// absence `validate` refuses. Every other path must go through `load`, so that a map whose
    /// crops were never captured cannot masquerade as a verified one.
    pub fn load_without_references(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut map: ClickMap = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        map.base_dir = path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
        map.check_bounds_or_err()?;
        Ok(map)
    }

    /// Fatal, not a warning. This check *is* F8: a screen with a named-but-absent reference crop
    /// is a screen nothing verifies, and the suite that swipes through it would still pass. When
    /// this fails the remedy is `make shop-sim-capture`, not deleting the `reference` line.
    fn validate(&self) -> Result<()> {
        for (screen_name, screen) in &self.screens {
            let Some(rel) = screen.reference_path() else {
                continue;
            };
            let full = self.base_dir.join(rel);
            anyhow::ensure!(
                full.exists(),
                "click_map: [screens.{screen_name}] references {}, which does not exist -- \
                 capture it with `sim_device verify-screens --map <map> --capture`",
                full.display()
            );
            anyhow::ensure!(
                screen.fields.contains_key(REFERENCE_REGION),
                "click_map: [screens.{screen_name}] has a `reference` but no `{REFERENCE_REGION}` \
                 saying which part of the window to compare"
            );
        }
        Ok(())
    }

    fn check_bounds_or_err(&self) -> Result<()> {
        for (screen_name, screen) in &self.screens {
            for (field_name, field) in &screen.fields {
                let corner = match *field {
                    Field::Point { x, y } => Some(((x, y), (x, y))),
                    Field::Region { x, y, w, h } => Some(((x, y), (x + w as i32, y + h as i32))),
                    Field::Reference(_) => None,
                };
                if let Some(((x0, y0), (x1, y1))) = corner {
                    let in_bounds = |x: i32, y: i32| {
                        x >= 0 && x <= self.resolution.w && y >= 0 && y <= self.resolution.h
                    };
                    anyhow::ensure!(
                        in_bounds(x0, y0) && in_bounds(x1, y1),
                        "{screen_name}.{field_name} extends outside the {}x{} simulator window",
                        self.resolution.w,
                        self.resolution.h
                    );
                }
            }
        }
        Ok(())
    }

    fn field(&self, screen: &str, field: &str) -> Result<&Field> {
        self.screens
            .get(screen)
            .with_context(|| format!("click_map has no [screens.{screen}]"))?
            .fields
            .get(field)
            .with_context(|| format!("click_map's [screens.{screen}] has no {field:?} field"))
    }

    pub fn point(&self, screen: &str, field: &str) -> Result<(i32, i32)> {
        match self.field(screen, field)? {
            Field::Point { x, y } => Ok((*x, *y)),
            Field::Region { x, y, .. } => Ok((*x, *y)),
            other => anyhow::bail!("[screens.{screen}].{field} is not a point: {other:?}"),
        }
    }

    pub fn region(&self, screen: &str, field: &str) -> Result<(i32, i32, u32, u32)> {
        match self.field(screen, field)? {
            Field::Region { x, y, w, h } => Ok((*x, *y, *w, *h)),
            other => anyhow::bail!("[screens.{screen}].{field} is not a region: {other:?}"),
        }
    }

    /// Screens carrying a `reference`, in map order -- what `verify-screens` walks.
    pub fn referenced_screens(&self) -> Vec<&str> {
        self.screens
            .iter()
            .filter(|(_, s)| s.reference_path().is_some())
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Assert the simulator is showing `screen` right now, by comparing its `reference_region`
    /// against the committed crop. This is the difference between "a swipe happened at (88,743)"
    /// and "the confirm screen was on display when it happened" -- the latter is the only claim
    /// this project's premise actually rests on (CLAUDE.md's I3).
    pub fn verify_screen(&self, window_id: &str, screen: &str) -> Result<()> {
        let expected = self.reference_file(screen)?;
        let region = self.region(screen, REFERENCE_REGION)?;
        let shot = tempfile::Builder::new()
            .prefix("sim-verify-")
            .suffix(".png")
            .tempfile()
            .context("creating a temp file for the screen crop")?;
        sim_common::screenshot_crop(window_id, shot.path(), region)?;

        let delta = mean_channel_delta(shot.path(), &expected)
            .with_context(|| format!("comparing {screen} against {}", expected.display()))?;
        anyhow::ensure!(
            delta <= MAX_MEAN_CHANNEL_DELTA,
            "expected the simulator to be showing `{screen}`, but its {REFERENCE_REGION} differs \
             from {} by a mean of {delta:.2}/255 per channel (limit {MAX_MEAN_CHANNEL_DELTA}). \
             Either the flow took a wrong turn, or the firmware UI moved and the crop needs \
             recapturing with `sim_device verify-screens --capture`.",
            expected.display()
        );
        Ok(())
    }

    /// Write (or overwrite) `screen`'s reference crop from whatever is on screen now. Capture is
    /// always an explicit, separate act -- never a fallback inside `verify_screen` -- because a
    /// verifier that captures on miss can never fail.
    pub fn capture_screen(&self, window_id: &str, screen: &str) -> Result<PathBuf> {
        let out = self.reference_file(screen)?;
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let region = self.region(screen, REFERENCE_REGION)?;
        sim_common::screenshot_crop(window_id, &out, region)?;
        Ok(out)
    }

    /// Where `screen`'s committed crop lives. Public so a caller that stages crops before
    /// deciding to commit them (`verify-screens --capture`) can resolve the destination without
    /// duplicating the base-dir join.
    pub fn reference_file_for(&self, screen: &str) -> Result<PathBuf> {
        self.reference_file(screen)
    }

    /// The window rectangle `screen`'s reference crop covers.
    pub fn reference_region(&self, screen: &str) -> Result<(i32, i32, u32, u32)> {
        self.region(screen, REFERENCE_REGION)
    }

    fn reference_file(&self, screen: &str) -> Result<PathBuf> {
        let rel = self
            .screens
            .get(screen)
            .with_context(|| format!("click_map has no [screens.{screen}]"))?
            .reference_path()
            .with_context(|| format!("[screens.{screen}] has no `reference` crop to compare"))?;
        Ok(self.base_dir.join(rel))
    }
}

/// Mean absolute difference per colour channel between two PNGs. Differing dimensions are an
/// error rather than a large delta: that means the map's region changed without the crop being
/// recaptured, which is a stale-fixture bug, not a screen mismatch, and saying so saves the reader
/// a wrong diagnosis.
fn mean_channel_delta(actual: &Path, expected: &Path) -> Result<f64> {
    let a = image::open(actual)
        .with_context(|| format!("reading {}", actual.display()))?
        .to_rgb8();
    let b = image::open(expected)
        .with_context(|| format!("reading {}", expected.display()))?
        .to_rgb8();
    anyhow::ensure!(
        a.dimensions() == b.dimensions(),
        "crop is {:?} but {} is {:?} -- recapture the reference",
        a.dimensions(),
        expected.display(),
        b.dimensions()
    );
    let total: u64 = a
        .as_raw()
        .iter()
        .zip(b.as_raw().iter())
        .map(|(x, y)| x.abs_diff(*y) as u64)
        .sum();
    Ok(total as f64 / a.as_raw().len() as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"
resolution = { w = 480, h = 800 }

[screens.home]
menu_button = { x = 437, y = 95 }
scan_button = { x = 388, y = 710 }

[screens.choose_wallet_filtered]
coin_entry = { x = 130, y = 681 }

[screens.connect_wallet]
qr_region = { x = 72, y = 222, w = 336, h = 336 }

[screens.sign_confirm]
swipe_from = { x = 88, y = 743 }
swipe_to = { x = 440, y = 743 }
reference = "reference/not_captured_yet.png"
"#;

    fn fixture() -> ClickMap {
        toml::from_str(FIXTURE).expect("fixture TOML must parse")
    }

    #[test]
    fn a_well_formed_map_loads_and_every_coordinate_is_in_bounds() {
        let map = fixture();
        assert_eq!(map.resolution.w, 480);
        assert_eq!(map.resolution.h, 800);
        map.check_bounds_or_err().expect("fixture coordinates are all in bounds");
        assert!(map.screens.contains_key("home"));
    }

    #[test]
    fn points_and_regions_resolve_by_screen_and_field() {
        let map = fixture();
        assert_eq!(map.point("home", "menu_button").unwrap(), (437, 95));
        assert_eq!(map.point("home", "scan_button").unwrap(), (388, 710));
        assert_eq!(map.point("choose_wallet_filtered", "coin_entry").unwrap(), (130, 681));
        assert_eq!(map.region("connect_wallet", "qr_region").unwrap(), (72, 222, 336, 336));
        assert_eq!(map.point("sign_confirm", "swipe_from").unwrap(), (88, 743));
        assert_eq!(map.point("sign_confirm", "swipe_to").unwrap(), (440, 743));
    }

    /// The F8 guarantee, stated as a test: a map naming a crop that was never captured must not
    /// load. Before this, `validate` only warned, so every suite "ran under the simulator with
    /// reference-image verification" while verifying nothing.
    #[test]
    fn a_missing_reference_crop_fails_the_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("click_map_fixture.toml");
        std::fs::write(&path, FIXTURE).unwrap();
        let err = ClickMap::load(&path).expect_err("a missing reference/ PNG must fail loading");
        assert!(err.to_string().contains("not_captured_yet.png"), "{err}");
    }

    #[test]
    fn capture_mode_can_still_load_a_map_whose_crops_do_not_exist_yet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("click_map_fixture.toml");
        std::fs::write(&path, FIXTURE).unwrap();
        let map = ClickMap::load_without_references(&path)
            .expect("capture mode exists precisely to create the missing crops");
        assert_eq!(map.referenced_screens(), vec!["sign_confirm"]);
    }

    /// A `reference` with no `reference_region` names a file but no rectangle to compare it
    /// against -- silently unverifiable, which is the exact failure F8 is meant to end.
    #[test]
    fn a_reference_without_a_region_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let png = dir.path().join("captured.png");
        image::RgbImage::new(4, 4).save(&png).unwrap();
        let path = dir.path().join("click_map_fixture.toml");
        std::fs::write(
            &path,
            "resolution = { w = 480, h = 800 }\n\
             [screens.sign_confirm]\n\
             swipe_from = { x = 88, y = 743 }\n\
             reference = \"captured.png\"\n",
        )
        .unwrap();
        let err = ClickMap::load(&path).expect_err("a reference with no region must fail loading");
        assert!(err.to_string().contains("reference_region"), "{err}");
    }

    #[test]
    fn two_renders_of_the_same_screen_compare_equal_and_different_ones_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let flat = dir.path().join("flat.png");
        let jittered = dir.path().join("jittered.png");
        let other = dir.path().join("other.png");

        let mut base = image::RgbImage::from_pixel(16, 16, image::Rgb([120, 120, 120]));
        base.save(&flat).unwrap();
        // Anti-aliasing wobble: a few pixels off by a little. Must still count as the same screen.
        for p in base.pixels_mut().take(20) {
            *p = image::Rgb([124, 116, 121]);
        }
        base.save(&jittered).unwrap();
        image::RgbImage::from_pixel(16, 16, image::Rgb([20, 200, 90])).save(&other).unwrap();

        assert!(mean_channel_delta(&jittered, &flat).unwrap() <= MAX_MEAN_CHANNEL_DELTA);
        assert!(mean_channel_delta(&other, &flat).unwrap() > MAX_MEAN_CHANNEL_DELTA);
    }

    #[test]
    fn a_crop_whose_size_no_longer_matches_the_reference_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let small = dir.path().join("small.png");
        let big = dir.path().join("big.png");
        image::RgbImage::new(8, 8).save(&small).unwrap();
        image::RgbImage::new(16, 16).save(&big).unwrap();
        let err = mean_channel_delta(&small, &big).expect_err("size mismatch is its own diagnosis");
        assert!(err.to_string().contains("recapture"), "{err}");
    }

    #[test]
    fn an_out_of_bounds_coordinate_is_rejected() {
        let text = r#"
resolution = { w = 480, h = 800 }
[screens.bad]
somewhere = { x = 9999, y = 1 }
"#;
        let map: ClickMap = toml::from_str(text).unwrap();
        assert!(map.check_bounds_or_err().is_err());
    }

    #[test]
    fn a_missing_screen_or_field_is_a_clear_error_not_a_panic() {
        let map = fixture();
        assert!(map.point("no_such_screen", "x").is_err());
        assert!(map.point("home", "no_such_field").is_err());
    }
}
