use serde::{Deserialize, Serialize};

/// Curated IPv6-only endpoint regions. Arbitrary hostnames are not accepted.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum EndpointPresetRegion {
    Us,
    De,
    Fi,
}

/// Resolve the domain using the authenticated account's current entitlement.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EndpointPresetTier {
    Free,
    Plus,
    ZeroTrust,
}

impl EndpointPresetTier {
    pub const ALL: [Self; 3] = [Self::Free, Self::Plus, Self::ZeroTrust];
}

impl EndpointPresetRegion {
    pub const ALL: [Self; 3] = [Self::Us, Self::De, Self::Fi];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Us => "us",
            Self::De => "de",
            Self::Fi => "fi",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "us" => Some(Self::Us),
            "de" => Some(Self::De),
            "fi" => Some(Self::Fi),
            _ => None,
        }
    }

    pub const fn hostname(self, tier: EndpointPresetTier) -> &'static str {
        match (self, tier) {
            (Self::Us, EndpointPresetTier::Free) => "us.v6.free.orangesky.dev",
            (Self::Us, EndpointPresetTier::Plus) => "us.v6.plus.orangesky.dev",
            (Self::Us, EndpointPresetTier::ZeroTrust) => "us.v6.zt.orangesky.dev",
            (Self::De, EndpointPresetTier::Free) => "de.v6.free.orangesky.dev",
            (Self::De, EndpointPresetTier::Plus) => "de.v6.plus.orangesky.dev",
            (Self::De, EndpointPresetTier::ZeroTrust) => "de.v6.zt.orangesky.dev",
            (Self::Fi, EndpointPresetTier::Free) => "fi.v6.free.orangesky.dev",
            (Self::Fi, EndpointPresetTier::Plus) => "fi.v6.plus.orangesky.dev",
            (Self::Fi, EndpointPresetTier::ZeroTrust) => "fi.v6.zt.orangesky.dev",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_exactly_the_nine_curated_hosts() {
        for region in EndpointPresetRegion::ALL {
            for (tier, label) in [
                (EndpointPresetTier::Free, "free"),
                (EndpointPresetTier::Plus, "plus"),
                (EndpointPresetTier::ZeroTrust, "zt"),
            ] {
                assert_eq!(
                    region.hostname(tier),
                    format!("{}.v6.{label}.orangesky.dev", region.as_str())
                );
            }
            assert_eq!(EndpointPresetRegion::parse(region.as_str()), Some(region));
            assert_eq!(
                serde_json::to_string(&region).unwrap(),
                format!("\"{}\"", region.as_str())
            );
        }
        assert_eq!(EndpointPresetRegion::parse("US"), None);
        assert_eq!(EndpointPresetRegion::parse("example.com"), None);
        assert!(serde_json::from_str::<EndpointPresetRegion>("\"other\"").is_err());
    }
}
