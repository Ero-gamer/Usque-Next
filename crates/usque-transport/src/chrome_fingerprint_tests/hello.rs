//! Keeps only public algorithm identifiers, never randoms, SNI or key shares.
use std::collections::BTreeMap;

use super::Carrier;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Hello {
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub groups: Vec<u16>,
    pub signatures: Vec<u16>,
    pub versions: Vec<u16>,
    pub key_share_groups: Vec<u16>,
    pub key_share_lengths: Vec<usize>,
    pub alpn: Vec<String>,
    pub compression: Vec<u16>,
    pub session_id_length: usize,
    pub trust_anchor_ids: Vec<Vec<u8>>,
    pub ech_shape: Option<(usize, u16, u16, usize, usize)>,
    pub extension_bodies_valid: bool,
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let (value, rest) = self.0.split_at_checked(length)?;
        self.0 = rest;
        Some(value)
    }
    fn u8(&mut self) -> Option<usize> {
        Some(usize::from(self.take(1)?[0]))
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }
    fn vector8(&mut self) -> Option<&'a [u8]> {
        let length = self.u8()?;
        self.take(length)
    }
    fn vector16(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }
}

fn words(bytes: &[u8]) -> Option<Vec<u16>> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    Some(
        bytes
            .chunks_exact(2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .collect(),
    )
}

fn grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

fn normalized(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|value| !grease(*value))
        .collect()
}

impl Hello {
    pub fn parse(message: &[u8]) -> Option<Self> {
        let mut reader = Reader(message);
        if reader.u8()? != 1 {
            return None;
        }
        let size = reader.take(3)?;
        let size =
            (usize::from(size[0]) << 16) | (usize::from(size[1]) << 8) | usize::from(size[2]);
        if reader.0.len() != size || reader.u16()? != 0x0303 {
            return None;
        }
        reader.take(32)?;
        let session_id_length = reader.vector8()?.len();
        let ciphers = words(reader.vector16()?)?;
        if reader.vector8()? != [0] {
            return None;
        }
        let mut extensions_reader = Reader(reader.vector16()?);
        if !reader.0.is_empty() {
            return None;
        }
        let mut extensions = Vec::new();
        let mut data = BTreeMap::new();
        while !extensions_reader.0.is_empty() {
            let id = extensions_reader.u16()?;
            let bytes = extensions_reader.vector16()?;
            if data.insert(id, bytes).is_some() {
                return None;
            }
            extensions.push(id);
        }
        let vector16 = |id| -> Option<Vec<u16>> {
            words(Reader(data.get(&id).copied().unwrap_or(&[0, 0])).vector16()?)
        };
        let vector8 = |id| -> Option<Vec<u16>> {
            words(Reader(data.get(&id).copied().unwrap_or(&[0])).vector8()?)
        };
        let mut alpn_reader = Reader(Reader(data.get(&16)?).vector16()?);
        let mut alpn = Vec::new();
        while !alpn_reader.0.is_empty() {
            alpn.push(std::str::from_utf8(alpn_reader.vector8()?).ok()?.to_owned());
        }
        let mut shares = Reader(Reader(data.get(&51)?).vector16()?);
        let mut key_share_groups = Vec::new();
        let mut key_share_lengths = Vec::new();
        while !shares.0.is_empty() {
            key_share_groups.push(shares.u16()?);
            key_share_lengths.push(shares.vector16()?.len());
        }
        let mut trust_anchor_ids = Vec::new();
        if let Some(bytes) = data.get(&0xca34) {
            let mut reader = Reader(bytes);
            let mut ids = Reader(reader.vector16()?);
            if !reader.0.is_empty() {
                return None;
            }
            while !ids.0.is_empty() {
                let id = ids.vector8()?;
                if id.is_empty() {
                    return None;
                }
                trust_anchor_ids.push(id.to_vec());
            }
        }
        let ech_shape = if let Some(bytes) = data.get(&65037) {
            let mut reader = Reader(bytes);
            let outer = reader.u8()?;
            let kdf = reader.u16()?;
            let aead = reader.u16()?;
            reader.u8()?; // ephemeral config ID is never retained
            let enc = reader.vector16()?.len();
            let payload = reader.vector16()?.len();
            if !reader.0.is_empty() {
                return None;
            }
            Some((outer, kdf, aead, enc, payload))
        } else {
            None
        };
        let extension_bodies_valid = [
            (5, &[1, 0, 0, 0, 0][..]),
            (11, &[1, 0][..]),
            (18, &[][..]),
            (23, &[][..]),
            (35, &[][..]),
            (45, &[1, 1][..]),
            (65281, &[0][..]),
            (17513, &[0, 3, 2, b'h', b'2'][..]),
            (17613, &[0, 3, 2, b'h', b'2'][..]),
        ]
        .iter()
        .all(|(id, expected)| data.get(id).is_none_or(|actual| actual == expected));
        Some(Self {
            ciphers,
            extensions,
            groups: vector16(10)?,
            signatures: vector16(13)?,
            versions: vector8(43)?,
            key_share_groups,
            key_share_lengths,
            alpn,
            compression: vector8(27)?,
            session_id_length,
            trust_anchor_ids,
            ech_shape,
            extension_bodies_valid,
        })
    }

    pub fn verify_chrome(&self, carrier: Carrier) -> Result<(), String> {
        self.verify_variant(carrier, false)
    }

    pub fn verify_chrome155(&self, carrier: Carrier) -> Result<(), String> {
        self.verify_variant(carrier, true)
    }

    fn verify_variant(&self, carrier: Carrier, chrome155: bool) -> Result<(), String> {
        let mut expected_ciphers = vec![0x1301, 0x1302, 0x1303];
        if carrier == Carrier::H2 {
            expected_ciphers.extend([
                0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
                0x002f, 0x0035,
            ]);
        }
        let expected_alpn = match carrier {
            Carrier::H2 => vec!["h2", "http/1.1"],
            Carrier::H3 => vec!["h3"],
        };
        let expected_versions = match carrier {
            Carrier::H2 => vec![0x0304, 0x0303],
            Carrier::H3 => vec![0x0304],
        };
        let mut expected_extensions = match carrier {
            Carrier::H2 => vec![
                0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17513, 65037, 65281,
            ],
            Carrier::H3 => vec![0, 5, 10, 13, 16, 18, 27, 43, 45, 51, 57, 65037],
        };
        if chrome155 {
            for id in &mut expected_extensions {
                if *id == 17513 {
                    *id = 17613;
                }
            }
            expected_extensions.push(0xca34);
            expected_extensions.sort_unstable();
        }
        let classical = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let expected_signatures = if chrome155 {
            [&[0x0904, 0x0905, 0x0906][..], &classical].concat()
        } else {
            classical.to_vec()
        };
        let mut actual_extensions = normalized(&self.extensions);
        actual_extensions.sort_unstable();
        let checks = [
            ("extension_set", actual_extensions == expected_extensions),
            ("ciphers", normalized(&self.ciphers) == expected_ciphers),
            ("groups", normalized(&self.groups) == [4588, 29, 23, 24]),
            (
                "signatures",
                normalized(&self.signatures) == expected_signatures
                    && self.signatures.len() == expected_signatures.len() + usize::from(chrome155)
                    && (!chrome155 || self.signatures.first().is_some_and(|v| grease(*v))),
            ),
            (
                "key_shares",
                normalized(&self.key_share_groups) == [4588, 29],
            ),
            ("versions", normalized(&self.versions) == expected_versions),
            ("alpn", self.alpn == expected_alpn),
            ("brotli", self.compression == [2]),
            ("extension_bodies", self.extension_bodies_valid),
            (
                "key_share_lengths",
                self.key_share_groups
                    .iter()
                    .zip(&self.key_share_lengths)
                    .filter(|(group, _)| !grease(**group))
                    .map(|(_, length)| *length)
                    .collect::<Vec<_>>()
                    == [1216, 32],
            ),
            (
                "trust_anchors",
                self.trust_anchor_ids
                    == if chrome155 {
                        chrome155_trust_anchors()
                    } else {
                        Vec::new()
                    },
            ),
            (
                "grease",
                self.ciphers.iter().any(|value| grease(*value))
                    && self
                        .extensions
                        .iter()
                        .filter(|value| grease(**value))
                        .count()
                        == 2,
            ),
            (
                "ech_grease",
                self.extensions.contains(&65037)
                    && self
                        .ech_shape
                        .is_some_and(|(outer, kdf, aead, enc, payload)| {
                            outer == 0
                                && kdf == 1
                                && aead == 1
                                && enc == 32
                                && [144, 176, 208, 240].contains(&payload)
                        }),
            ),
            (
                "ocsp_sct",
                self.extensions.contains(&5) && self.extensions.contains(&18),
            ),
            (
                "carrier",
                match carrier {
                    Carrier::H2 => {
                        self.extensions
                            .contains(&if chrome155 { 17613 } else { 17513 })
                            && !self.extensions.contains(&57)
                            && self.session_id_length == 32
                    }
                    Carrier::H3 => self.extensions.contains(&57) && self.session_id_length == 0,
                },
            ),
        ];
        let failed: Vec<_> = checks
            .iter()
            .filter(|(_, ok)| !ok)
            .map(|(name, _)| *name)
            .collect();
        if failed.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "ClientHello mismatch: {}; observed {self:?}",
                failed.join(",")
            ))
        }
    }

    #[cfg(windows)]
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "cipher_suites": normalized(&self.ciphers),
            "extension_ids": normalized(&self.extensions),
            "groups": normalized(&self.groups),
            "signature_algorithms": self.signatures,
            "key_share_groups": normalized(&self.key_share_groups),
            "key_share_lengths": self.key_share_lengths,
            "supported_versions": normalized(&self.versions),
            "alpn": self.alpn,
            "certificate_compression": self.compression,
            "session_id_length": self.session_id_length,
            "trust_anchor_count": self.trust_anchor_ids.len(),
            "ech_shape": self.ech_shape
        })
    }
}

fn chrome155_trust_anchors() -> Vec<Vec<u8>> {
    // Independent public fixture from uTLS ff1b50fbbe9a u_chrome155.go.
    [
        "82df130201",
        "82df130206",
        "82df13020d",
        "82df13020e",
        "82df13020f",
        "82df130212",
        "82df130213",
        "82df130214",
        "839a648c9b2d0107",
        "839a648c9b2d0108",
        "839a648c9b2d0109",
        "839a648c9b2d010a",
        "839a648c9b2d010b",
        "839a648c9b2d010c",
        "839a648c9b2d010d",
        "839a648c9b2d0112",
        "839a648c9b2d0113",
        "d6790901",
        "d6790904",
        "d6790905",
        "d6790906",
        "d6790907",
        "d6790908",
        "d679090a",
        "d679090b",
        "d679090c",
        "d679090d",
        "d679090f",
    ]
    .iter()
    .map(|hex| {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    })
    .collect()
}
