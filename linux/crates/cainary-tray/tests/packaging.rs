//! The deb and rpm manifests install exactly what packaging/linux-assets.txt lists.

use std::fs;
use std::path::PathBuf;

use toml::Value;

fn tray_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn manifest() -> Value {
    let text = fs::read_to_string(tray_dir().join("Cargo.toml")).unwrap();
    text.parse().unwrap()
}

/// (source, dest, mode) of every asset in `metadata.<tool>.assets`, `dest` without a leading `/`.
fn asset_triples(tool: &str) -> Vec<(String, String, String)> {
    let manifest = manifest();
    manifest["package"]["metadata"][tool]["assets"]
        .as_array()
        .unwrap_or_else(|| panic!("{tool} has no assets"))
        .iter()
        .map(|asset| {
            let (src, dest, mode) = match asset {
                Value::Array(p) => (&p[0], &p[1], &p[2]),
                Value::Table(t) => (&t["source"], &t["dest"], &t["mode"]),
                other => panic!("{tool}: unexpected asset {other}"),
            };
            let dest = dest.as_str().unwrap();
            (
                src.as_str().unwrap().to_owned(),
                dest.strip_prefix('/').unwrap_or(dest).to_owned(),
                mode.as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn the_deb_and_rpm_assets_equal_linux_assets_txt() {
    let list = fs::read_to_string(tray_dir().join("../../../packaging/linux-assets.txt")).unwrap();
    let expected: Vec<(String, String, String)> = list
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut fields = line.split_whitespace();
            let (mode, staged, dest) = (fields.next(), fields.next(), fields.next());
            assert!(fields.next().is_none(), "bad line: {line}");
            (
                format!("target/release/{}", staged.unwrap()),
                dest.unwrap().to_owned(),
                mode.unwrap().to_owned(),
            )
        })
        .collect();
    assert!(expected.len() > 10, "only {} entries", expected.len());
    for tool in ["deb", "generate-rpm"] {
        assert_eq!(
            asset_triples(tool),
            expected,
            "{tool} assets differ from linux-assets.txt"
        );
    }
}
