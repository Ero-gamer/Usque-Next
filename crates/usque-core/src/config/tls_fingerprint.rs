use serde::{Deserialize, Serialize};

/// TLS ClientHello preset for authenticated WARP MASQUE, adapted to H2 or QUIC.
/// This does not emulate Chrome's HTTP or QUIC packet behavior.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TlsFingerprint {
    #[default]
    Default,
    Chrome131,
}

impl TlsFingerprint {
    pub const ALL: [Self; 2] = [Self::Default, Self::Chrome131];
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Account, Profile, SharedNetworkSettings};

    #[test]
    fn legacy_profiles_and_shared_settings_keep_default_handshake() {
        let mut profile = serde_json::to_value(Profile::default()).unwrap();
        profile.as_object_mut().unwrap().remove("tls_fingerprint");
        assert_eq!(
            serde_json::from_value::<Profile>(profile)
                .unwrap()
                .tls_fingerprint,
            TlsFingerprint::Default
        );
        let mut shared = serde_json::to_value(SharedNetworkSettings::default()).unwrap();
        shared.as_object_mut().unwrap().remove("tls_fingerprint");
        assert_eq!(
            serde_json::from_value::<SharedNetworkSettings>(shared)
                .unwrap()
                .tls_fingerprint,
            TlsFingerprint::Default
        );
    }

    #[test]
    fn preset_survives_shared_persistence_and_account_hydration() {
        for (preset, name) in [
            (TlsFingerprint::Default, "default"),
            (TlsFingerprint::Chrome131, "chrome131"),
        ] {
            assert_eq!(serde_json::to_value(preset).unwrap(), name);
            let profile = Profile {
                tls_fingerprint: preset,
                ..Default::default()
            };
            let shared = SharedNetworkSettings::from_profile(&profile);
            let shared: SharedNetworkSettings =
                serde_json::from_slice(&serde_json::to_vec(&shared).unwrap()).unwrap();
            assert_eq!(
                shared.hydrate(&Account::default_account()).tls_fingerprint,
                preset
            );
        }
        for value in ["chrome", "Chrome131", "unknown"] {
            assert!(serde_json::from_value::<TlsFingerprint>(serde_json::json!(value)).is_err());
        }
    }
}
