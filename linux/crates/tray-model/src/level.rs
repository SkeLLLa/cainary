//! Levels: the core's open `level` slug, and the eight looks the tray icon can take.

use std::cmp::Ordering;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// How worrying an entry or finding is, as the core reports it. Ascending, so `max()` is the
/// worst. A slug this build doesn't know is kept as `Unknown`, sorts below everything and is
/// drawn as a grey `?`, so a newer core can add a level without breaking the tray.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Level {
    NotInstalled,
    Ok,
    OptedOut,
    Low,
    Medium,
    High,
    Unknown(String),
}

impl Level {
    pub fn from_slug(slug: &str) -> Self {
        match slug {
            "not-installed" => Self::NotInstalled,
            "ok" => Self::Ok,
            "opted-out" => Self::OptedOut,
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            other => Self::Unknown(other.to_owned()),
        }
    }

    pub fn slug(&self) -> &str {
        match self {
            Self::NotInstalled => "not-installed",
            Self::Ok => "ok",
            Self::OptedOut => "opted-out",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Unknown(s) => s,
        }
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown(_))
    }

    fn rank(&self) -> i8 {
        match self {
            Self::Unknown(_) => -1,
            Self::NotInstalled => 0,
            Self::Ok => 1,
            Self::OptedOut => 2,
            Self::Low => 3,
            Self::Medium => 4,
            Self::High => 5,
        }
    }
}

// Ordered by rank only: two different unknown slugs compare equal, as on macOS.
impl PartialOrd for Level {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.rank().cmp(&other.rank()))
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl<'de> Deserialize<'de> for Level {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from_slug(&String::deserialize(d)?))
    }
}

impl Serialize for Level {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.slug())
    }
}
