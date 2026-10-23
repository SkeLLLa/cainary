//! The shared scenarios stay decodable and renderable.

use cainary_tray_model::fixtures::scenarios;
use cainary_tray_model::view;

#[test]
fn every_scenario_builds_a_view() {
    let all = scenarios();
    let mut names: Vec<_> = all.iter().map(|s| s.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), all.len(), "scenario names are unique");
    for s in all {
        let json = view::build(
            &s.state,
            &s.settings,
            false,
            |_| "14:05".into(),
            |_, _| String::new(),
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).expect(s.name);
        assert!(parsed.is_object(), "{}", s.name);
        assert!(
            ["popup", "details", "settings", "about"].contains(&s.window),
            "{}",
            s.name
        );
    }
}
