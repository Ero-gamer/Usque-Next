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
    pub alpn: Vec<String>,
    pub compression: Vec<u16>,
    pub session_id_length: usize,
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
        while !shares.0.is_empty() {
            key_share_groups.push(shares.u16()?);
            shares.vector16()?;
        }
        Some(Self {
            ciphers,
            extensions,
            groups: vector16(10)?,
            signatures: vector16(13)?,
            versions: vector8(43)?,
            key_share_groups,
            alpn,
            compression: vector8(27)?,
            session_id_length,
        })
    }

    pub fn verify_chrome(&self, carrier: Carrier) -> Result<(), String> {
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
        let expected_extensions = match carrier {
            Carrier::H2 => vec![
                0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17513, 65037, 65281,
            ],
            Carrier::H3 => vec![0, 5, 10, 13, 16, 18, 27, 43, 45, 51, 57, 65037],
        };
        let mut actual_extensions = normalized(&self.extensions);
        actual_extensions.sort_unstable();
        let checks = [
            ("extension_set", actual_extensions == expected_extensions),
            ("ciphers", normalized(&self.ciphers) == expected_ciphers),
            ("groups", normalized(&self.groups) == [4588, 29, 23, 24]),
            (
                "signatures",
                self.signatures
                    == [
                        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
                    ],
            ),
            (
                "key_shares",
                normalized(&self.key_share_groups) == [4588, 29],
            ),
            ("versions", normalized(&self.versions) == expected_versions),
            ("alpn", self.alpn == expected_alpn),
            ("brotli", self.compression == [2]),
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
            ("ech_grease", self.extensions.contains(&65037)),
            (
                "ocsp_sct",
                self.extensions.contains(&5) && self.extensions.contains(&18),
            ),
            (
                "carrier",
                match carrier {
                    Carrier::H2 => {
                        self.extensions.contains(&17513)
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
            "supported_versions": normalized(&self.versions),
            "alpn": self.alpn,
            "certificate_compression": self.compression,
            "session_id_length": self.session_id_length
        })
    }
}
