use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct ClickMap {
    pub resolution: Resolution,
    pub screens: BTreeMap<String, Screen>,
}

#[derive(Debug, Deserialize, Clone, Copy)]
pub struct Resolution {
    pub w: i32,
    pub h: i32,
}

#[derive(Debug, Deserialize)]
pub struct Screen {
    #[serde(flatten)]
    pub fields: BTreeMap<String, Field>,
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
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let map: ClickMap = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        map.validate(path.parent().unwrap_or_else(|| Path::new(".")));
        map.check_bounds_or_err()?;
        Ok(map)
    }

    fn validate(&self, base_dir: &Path) {
        for (screen_name, screen) in &self.screens {
            for (field_name, field) in &screen.fields {
                if let Field::Reference(rel) = field {
                    let full = base_dir.join(rel);
                    if !full.exists() {
                        eprintln!(
                            "click_map: {screen_name}.{field_name} references {} — not yet captured",
                            full.display()
                        );
                    }
                }
            }
        }
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

    #[test]
    fn a_missing_reference_crop_warns_but_does_not_fail_load() {
        let dir = std::env::temp_dir();
        let path = dir.join("sim_map_click_map_fixture_test.toml");
        std::fs::write(&path, FIXTURE).unwrap();
        let map = ClickMap::load(&path).expect("a missing reference/ PNG must not fail loading");
        let _ = std::fs::remove_file(&path);
        assert!(map.screens.contains_key("sign_confirm"));
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
