//! The tray icon, drawn like the macOS menu bar icon: the app's robo-canary, colored or as its
//! symbolic silhouette, with a badge holding the count of entries to review (1–9) or `?` when the
//! result can't be trusted.
//!
//! Icons are SVG text, written where the tray host can load them by name (see `IconDir` in the
//! app). The badge sits in the logo's empty top-left corner, so no clip or mask is needed: hosts
//! recolor symbolic icons by restyling every shape, which breaks both. Digits are holes in the
//! badge (even-odd fill), so they stay readable on any panel.

use serde::{Deserialize, Serialize};

/// How the tray icon is colored.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IconStyle {
    /// The panel-colored silhouette with a badge tinted by the level.
    #[default]
    Monochrome,
    /// Silhouette and badge both panel-colored, like the panel's other icons.
    FullMonochrome,
    /// The colored logo once there is a level, with a tinted badge, as macOS's "Color".
    Color,
}

impl IconStyle {
    pub const ALL: [Self; 3] = [Self::Monochrome, Self::FullMonochrome, Self::Color];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Monochrome => "monochrome",
            Self::FullMonochrome => "full-monochrome",
            Self::Color => "color",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|style| style.as_str() == key)
    }
}

/// The level shown (macOS `MenuState.Look`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Look {
    /// Panel-colored: first scan, or couldn't scan.
    Template,
    /// Panel-colored and faded: nothing installed.
    TemplateDimmed,
    Green,
    Blue,
    Yellow,
    Orange,
    Red,
}

/// The badge (macOS `MenuState.Badge`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Badge {
    None,
    /// `?`: the result can't be trusted.
    Unknown,
    /// Entries at `low` or above, 1–9.
    Count(u8),
}

/// What the tray icon shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TrayIcon {
    pub look: Look,
    pub badge: Badge,
}

/// The panel color an icon file falls back to when the host doesn't recolor it (Breeze text).
const DEFAULT_TEXT: &str = "#232629";
/// The app icon and its symbolic variant, as installed.
const LOGO: &str = include_str!("../../../data/icons/hicolor/scalable/apps/ua.SkeLLLa.cAInary.svg");
const LOGO_SYMBOLIC: &str =
    include_str!("../../../data/icons/hicolor/scalable/apps/ua.SkeLLLa.cAInary-symbolic.svg");
/// The logos' `8 6 112 112` view box onto the 22×22 icon.
const LOGO_TRANSFORM: &str = "matrix(0.196429 0 0 0.196429 -1.571429 -1.178571)";
/// The badge circle: radius 4.3 around (4.4, 4.5), where the logo is empty.
const BADGE: &str = "M4.4 0.2a4.3 4.3 0 1 0 0.001 0Z";
/// Opacity of the dimmed silhouette (macOS `dimmedAlpha`).
const DIMMED: &str = "0.45";

impl TrayIcon {
    /// A distinct name per distinct picture, so a host's icon cache never shows a stale one.
    /// Panel-colored icons end in `-symbolic`, which is what lets GTK-based hosts recolor them.
    /// The app id is joined with a `.`, not a `-`: KIconLoader searches the system theme before
    /// the icon theme path, dropping `-` parts until a name matches, so `<app id>-tray-…` would
    /// resolve to the installed app icon.
    pub fn name(self, style: IconStyle) -> String {
        let tint = if self.colored(style) {
            "color"
        } else if self.look == Look::TemplateDimmed {
            "dimmed"
        } else {
            "plain"
        };
        let badge = match self.badge {
            Badge::None => String::new(),
            Badge::Unknown => "-unknown".into(),
            Badge::Count(n) => match self.badge_tint(style) {
                Some(_) => format!("-{}{}", look_key(self.look), n.clamp(1, 9)),
                None => format!("-{}", n.clamp(1, 9)),
            },
        };
        let symbolic = if !self.colored(style) {
            "-symbolic"
        } else {
            ""
        };
        format!("{}.tray-{tint}{badge}{symbolic}", crate::APP_ID)
    }

    pub fn svg(self, style: IconStyle) -> String {
        self.svg_with_text(style, DEFAULT_TEXT)
    }

    /// [`Self::svg`] with `text` (a CSS color) for the panel-colored parts, for drawing it
    /// ourselves.
    pub fn svg_with_text(self, style: IconStyle, text: &str) -> String {
        let mut svg = String::from(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"22\" height=\"22\" viewBox=\"0 0 22 22\">",
        );
        svg.push_str(&format!(
            "<style id=\"current-color-scheme\">.ColorScheme-Text{{color:{text}}}</style>"
        ));
        let (logo, opacity) = if self.colored(style) {
            (LOGO, "1")
        } else if self.look == Look::TemplateDimmed {
            (LOGO_SYMBOLIC, DIMMED)
        } else {
            (LOGO_SYMBOLIC, "1")
        };
        svg.push_str(&format!(
            "<g transform=\"{LOGO_TRANSFORM}\" opacity=\"{opacity}\">{}</g>",
            shapes(logo)
        ));
        let glyph = match self.badge {
            Badge::None => None,
            Badge::Unknown => Some(QUESTION),
            Badge::Count(n) => Some(DIGITS[usize::from(n.clamp(1, 9)) - 1]),
        };
        if let Some(glyph) = glyph {
            let d = format!("{BADGE}{}", glyph_holes(glyph));
            let shape = match self.badge_tint(style) {
                // GTK recolors every shape of a symbolic icon but `.warning`/`.error`.
                Some((color, class)) => format!("<path class=\"{class}\" fill=\"{color}\""),
                None => "<path class=\"ColorScheme-Text\" fill=\"currentColor\"".into(),
            };
            svg.push_str(&format!("{shape} fill-rule=\"evenodd\" d=\"{d}\"/>"));
        }
        svg.push_str("</svg>\n");
        svg
    }

    /// Whether the logo is drawn in its own colors; otherwise it is the panel-colored
    /// silhouette, as are the template looks (no level yet) in every style.
    fn colored(self, style: IconStyle) -> bool {
        style == IconStyle::Color && !matches!(self.look, Look::Template | Look::TemplateDimmed)
    }

    /// The count badge's fixed color and GTK class; `None` for panel-colored. `?` always
    /// follows the panel, as on macOS.
    fn badge_tint(self, style: IconStyle) -> Option<(&'static str, &'static str)> {
        if style == IconStyle::FullMonochrome || !matches!(self.badge, Badge::Count(_)) {
            return None;
        }
        match self.look {
            Look::Yellow => Some((YELLOW, "warning")),
            Look::Orange => Some((ORANGE, "warning")),
            Look::Red => Some((RED, "error")),
            _ => None,
        }
    }
}

fn look_key(look: Look) -> &'static str {
    match look {
        Look::Template => "plain",
        Look::TemplateDimmed => "dimmed",
        Look::Green => "green",
        Look::Blue => "blue",
        Look::Yellow => "yellow",
        Look::Orange => "orange",
        Look::Red => "red",
    }
}

const YELLOW: &str = "#f5c211";
const ORANGE: &str = "#f67400";
const RED: &str = "#da4453";

/// A logo file's shapes: what follows its title and color-scheme style, up to `</svg>`.
fn shapes(svg: &'static str) -> &'static str {
    let start = ["</style>", "</title>"]
        .into_iter()
        .find_map(|tag| svg.find(tag).map(|at| at + tag.len()))
        .expect("the logo has a title");
    let end = svg.rfind("</svg>").expect("the logo is an SVG");
    svg[start..end].trim()
}

/// 3×5 pixel glyphs, top row first; `#` is a hole in the badge.
const DIGITS: [[&str; 5]; 9] = [
    [".#.", "##.", ".#.", ".#.", "###"],
    ["###", "..#", "###", "#..", "###"],
    ["###", "..#", "###", "..#", "###"],
    ["#.#", "#.#", "###", "..#", "..#"],
    ["###", "#..", "###", "..#", "###"],
    ["###", "#..", "###", "#.#", "###"],
    ["###", "..#", "..#", "..#", "..#"],
    ["###", "#.#", "###", "#.#", "###"],
    ["###", "#.#", "###", "..#", "###"],
];
const QUESTION: [&str; 5] = ["###", "..#", ".##", "...", ".#."];

/// The glyph's runs as rectangles centered in the badge. Runs never overlap, so each is a hole
/// under the even-odd rule.
fn glyph_holes(glyph: [&str; 5]) -> String {
    let (left, top) = (2.9_f32, 2.0_f32);
    let mut d = String::new();
    for (row, cells) in glyph.iter().enumerate() {
        let mut column = 0;
        let cells = cells.as_bytes();
        while column < cells.len() {
            if cells[column] != b'#' {
                column += 1;
                continue;
            }
            let start = column;
            while column < cells.len() && cells[column] == b'#' {
                column += 1;
            }
            let (x, y, width) = (left + start as f32, top + row as f32, column - start);
            d.push_str(&format!(" M{x} {y}h{width}v1h-{width}Z"));
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_LOOKS: [Look; 7] = [
        Look::Template,
        Look::TemplateDimmed,
        Look::Green,
        Look::Blue,
        Look::Yellow,
        Look::Orange,
        Look::Red,
    ];

    fn badges() -> Vec<Badge> {
        let mut badges = vec![Badge::None, Badge::Unknown];
        badges.extend((1..=9).map(Badge::Count));
        badges
    }

    #[test]
    fn equal_names_mean_equal_pictures() {
        for style in IconStyle::ALL {
            let mut seen = std::collections::HashMap::new();
            for look in ALL_LOOKS {
                for badge in badges() {
                    let icon = TrayIcon { look, badge };
                    let svg = icon.svg(style);
                    if let Some(other) = seen.insert(icon.name(style), svg.clone()) {
                        assert_eq!(other, svg, "{} names two pictures", icon.name(style));
                    }
                }
            }
        }
    }

    #[test]
    fn full_monochrome_has_no_fixed_colors() {
        let icon = TrayIcon {
            look: Look::Red,
            badge: Badge::Count(3),
        };
        let svg = icon.svg(IconStyle::FullMonochrome);
        assert!(!svg.contains(RED));
        assert!(
            icon.name(IconStyle::FullMonochrome)
                .ends_with(".tray-plain-3-symbolic")
        );
        // The default keeps the logo panel-colored and tints only the badge.
        let svg = icon.svg(IconStyle::Monochrome);
        assert!(svg.contains(&format!("class=\"error\" fill=\"{RED}\"")));
        assert!(svg.contains("class=\"ColorScheme-Text\""));
        assert!(
            icon.name(IconStyle::Monochrome)
                .ends_with(".tray-plain-red3-symbolic")
        );
        // Color draws the colored logo; nothing is left for the host to recolor.
        assert!(icon.name(IconStyle::Color).ends_with(".tray-color-red3"));
        assert!(icon.svg(IconStyle::Color).contains("url(#plate)"));
        assert!(
            !icon
                .svg(IconStyle::Color)
                .contains("ColorScheme-Text\" fill=\"currentColor\">")
        );
    }

    #[test]
    fn draws_the_app_icon_or_its_symbolic_variant() {
        for style in IconStyle::ALL {
            for look in ALL_LOOKS {
                let icon = TrayIcon {
                    look,
                    badge: Badge::None,
                };
                let (want, other) = if icon.colored(style) {
                    (LOGO, LOGO_SYMBOLIC)
                } else {
                    (LOGO_SYMBOLIC, LOGO)
                };
                let svg = icon.svg(style);
                assert!(svg.contains(shapes(want)), "{}", icon.name(style));
                assert!(!svg.contains(shapes(other)), "{}", icon.name(style));
            }
        }
    }

    #[test]
    fn names_never_fall_back_to_the_app_icon() {
        for style in IconStyle::ALL {
            for look in ALL_LOOKS {
                for badge in badges() {
                    let name = TrayIcon { look, badge }.name(style);
                    // What a `-`-stripping lookup reaches last.
                    let stem = name.split('-').next().unwrap();
                    assert_eq!(stem, format!("{}.tray", crate::APP_ID), "{name}");
                }
            }
        }
    }

    #[test]
    fn unknown_badge_follows_the_panel() {
        let icon = TrayIcon {
            look: Look::Template,
            badge: Badge::Unknown,
        };
        for style in IconStyle::ALL {
            assert!(icon.name(style).ends_with(".tray-plain-unknown-symbolic"));
        }
    }

    #[test]
    fn digit_holes_sit_inside_the_badge() {
        for glyph in DIGITS.iter().chain([&QUESTION]) {
            let d = glyph_holes(*glyph);
            for part in d.split(" M").skip(1) {
                let mut numbers = part.split(['h', 'v', ' ']);
                let mut next = || numbers.next().unwrap().parse::<f32>().unwrap();
                let (x, y, width) = (next(), next(), next());
                // Every corner of the run within the radius-4.3 circle at (4.4, 4.5).
                for (cx, cy) in [(x, y), (x + width, y), (x, y + 1.0), (x + width, y + 1.0)] {
                    assert!(((cx - 4.4).powi(2) + (cy - 4.5).powi(2)).sqrt() < 4.3);
                }
            }
        }
    }

    #[test]
    fn style_keys_round_trip() {
        for style in IconStyle::ALL {
            assert_eq!(IconStyle::from_key(style.as_str()), Some(style));
        }
    }
}
