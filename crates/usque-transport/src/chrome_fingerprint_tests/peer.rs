//! Observational metadata only. Never authenticates a certificate or retains it.
#[derive(Clone, Debug)]
pub(super) struct CertificateAlgorithms {
    pub public_key: &'static str,
    pub issuer_signature: &'static str,
}

impl CertificateAlgorithms {
    #[cfg(windows)]
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({"public_key": self.public_key, "issuer_signature": self.issuer_signature})
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (value, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(value)
    }
    fn number(&mut self, n: usize) -> Option<usize> {
        self.take(n)?.iter().try_fold(0usize, |v, b| {
            v.checked_mul(256)?.checked_add(usize::from(*b))
        })
    }
    fn vector(&mut self, n: usize) -> Option<&'a [u8]> {
        let len = self.number(n)?;
        self.take(len)
    }
    fn der(&mut self, tag: u8) -> Option<&'a [u8]> {
        if self.take(1)? != [tag] {
            return None;
        }
        let mut len = self.number(1)?;
        if len & 128 != 0 {
            let count = len & 127;
            if count == 0 || count > 3 || self.0.first() == Some(&0) {
                return None;
            }
            len = self.number(count)?;
            if len < 128 {
                return None;
            }
        }
        self.take(len)
    }
}

fn algorithm(oid: &[u8]) -> &'static str {
    match oid {
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1] => "ec",
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1] => "rsa",
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 10] => "rsa_pss",
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2] => "ecdsa_sha256",
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 3] => "ecdsa_sha384",
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 11] => "rsa_sha256",
        [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 17] => "mldsa44",
        [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 18] => "mldsa65",
        [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 19] => "mldsa87",
        _ => "unknown",
    }
}

pub(super) fn signature_name(value: u16) -> &'static str {
    match value {
        0x0403 | 0x0503 | 0x0603 => "ecdsa",
        0x0804..=0x0806 | 0x0809..=0x080b => "rsa_pss",
        0x0401 | 0x0501 | 0x0601 => "rsa_pkcs1",
        0x0904 => "mldsa44",
        0x0905 => "mldsa65",
        0x0906 => "mldsa87",
        _ => "unknown",
    }
}

fn certificate_der(input: &[u8]) -> Option<CertificateAlgorithms> {
    let mut outer = Reader(input);
    let mut cert = Reader(outer.der(0x30)?);
    if !outer.0.is_empty() {
        return None;
    }
    let mut tbs = Reader(cert.der(0x30)?);
    let issuer_signature = algorithm(Reader(cert.der(0x30)?).der(6)?);
    cert.der(3)?;
    if !cert.0.is_empty() {
        return None;
    }
    if tbs.0.first() == Some(&0xa0) {
        tbs.der(0xa0)?;
    }
    tbs.der(2)?; // serial
    for _ in 0..4 {
        tbs.der(0x30)?;
    } // signing algorithm, issuer, validity, subject
    let mut spki = Reader(tbs.der(0x30)?);
    let public_key = algorithm(Reader(spki.der(0x30)?).der(6)?);
    spki.der(3)?;
    if !spki.0.is_empty() {
        return None;
    }
    Some(CertificateAlgorithms {
        public_key,
        issuer_signature,
    })
}

fn handshake(message: &[u8], expected: u8) -> Option<&[u8]> {
    let mut reader = Reader(message);
    if reader.take(1)? != [expected] {
        return None;
    }
    let body = reader.vector(3)?;
    reader.0.is_empty().then_some(body)
}

pub(super) fn certificate_verify(message: &[u8]) -> Option<u16> {
    let mut reader = Reader(handshake(message, 15)?);
    let signature = u16::try_from(reader.number(2)?).ok()?;
    if reader.vector(2)?.is_empty() || !reader.0.is_empty() {
        return None;
    }
    Some(signature)
}

pub(super) fn certificate_message(message: &[u8]) -> Option<CertificateAlgorithms> {
    let decoded;
    let body = if message.first() == Some(&25) {
        let mut compressed = Reader(handshake(message, 25)?);
        if compressed.number(2)? != 2 {
            return None;
        }
        let expected = compressed.number(3)?;
        if expected > 1024 * 1024 {
            return None;
        }
        let input = compressed.vector(3)?;
        if !compressed.0.is_empty() {
            return None;
        }
        decoded = crate::tls_fingerprint::decompress_probe_certificate(input)?;
        if decoded.len() != expected {
            return None;
        }
        decoded.as_slice()
    } else {
        handshake(message, 11)?
    };
    let mut reader = Reader(body);
    if !reader.vector(1)?.is_empty() {
        return None;
    }
    let mut chain = Reader(reader.vector(3)?);
    if !reader.0.is_empty() {
        return None;
    }
    let leaf = chain.vector(3)?;
    chain.vector(2)?;
    while !chain.0.is_empty() {
        chain.vector(3)?;
        chain.vector(2)?;
    }
    certificate_der(leaf)
}

#[test]
fn signature_algorithms_and_malformed_messages_are_distinguished() {
    for (id, name) in [
        (0x0403, "ecdsa"),
        (0x0804, "rsa_pss"),
        (0x0904, "mldsa44"),
        (0x0905, "mldsa65"),
        (0x0906, "mldsa87"),
    ] {
        let id: u16 = id;
        let [hi, lo] = id.to_be_bytes();
        let message = [15, 0, 0, 5, hi, lo, 0, 1, 0];
        assert_eq!(certificate_verify(&message), Some(id));
        assert_eq!(signature_name(id), name);
        for n in 0..message.len() {
            assert!(certificate_verify(&message[..n]).is_none());
        }
    }
}

#[test]
fn certificate_metadata_does_not_confuse_public_key_and_issuer_signature() {
    fn der(tag: u8, data: &[u8]) -> Vec<u8> {
        assert!(data.len() < 128);
        [vec![tag, data.len() as u8], data.to_vec()].concat()
    }
    let signature = der(0x30, &der(6, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2]));
    for (oid, name) in [
        (vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1], "ec"),
        (vec![0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1], "rsa"),
        (vec![0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 17], "mldsa44"),
        (vec![0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 18], "mldsa65"),
        (vec![0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 19], "mldsa87"),
    ] {
        // Synthetic DER: metadata extraction must work even when EVP cannot
        // instantiate the public key. This is not a valid/authenticated cert.
        let spki = der(0x30, &[der(0x30, &der(6, &oid)), der(3, &[0])].concat());
        let tbs = der(
            0x30,
            &[
                der(2, &[1]),
                signature.clone(),
                vec![0x30, 0, 0x30, 0, 0x30, 0],
                spki,
            ]
            .concat(),
        );
        let cert = der(0x30, &[tbs, signature.clone(), der(3, &[0])].concat());
        let meta = certificate_der(&cert).unwrap();
        assert_eq!(meta.public_key, name);
        assert_eq!(meta.issuer_signature, "ecdsa_sha256");
        for n in 0..cert.len() {
            assert!(certificate_der(&cert[..n]).is_none());
        }
    }
}
